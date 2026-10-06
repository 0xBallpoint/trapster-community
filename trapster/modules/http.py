import asyncio
import hashlib
import ipaddress
import logging
import secrets

from starlette.requests import ClientDisconnect
from fastapi import FastAPI, Request, Response

from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2 import FileSystemLoader, Undefined
import yaml
import random, string, base64, mimetypes, re, uuid
from urllib.parse import parse_qsl, quote
from datetime import datetime, timezone
from pathlib import Path

mimetypes.add_type('image/x-icon', '.ico')

from trapster.modules.base import BaseHoneypot

# Carries a custom HTTP/1.1 reason phrase from the handler to the hypercorn
# reason patch below, via the ASGI `state` extension (request.state / scope
# ["state"]). Not a contextvar: FastAPI's @app.middleware("http") decorator
# (see custom_method_middleware) runs the actual endpoint in a child task
# spawned by Starlette's BaseHTTPMiddleware, and a contextvar set there is
# invisible to the outer task that hands the response to hypercorn. The ASGI
# scope dict, in contrast, is the same object shared across that task split,
# so mutating scope["state"] is visible wherever the scope is threaded next.
_REASON_STATE_KEY = "custom_http_reason"

# HTTP methods FastAPI routes natively; anything else is a "custom" method.
STANDARD_METHODS = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE", "QUERY"}


def _patch_hypercorn_reason():
    """Let config.yaml override the HTTP/1.1 reason phrase.

    Hypercorn builds an h11.Response without a reason, so h11 derives the
    standard phrase from the status code. We wrap _send_h11_event so that, when
    the current stream's ASGI scope carries a reason (see _REASON_STATE_KEY),
    the h11.Response is rebuilt with that reason. HTTP/2 has no reason phrase,
    so this only affects h11 connections; if this patch fails to apply (e.g. a
    future hypercorn version reshapes H11Protocol), requests simply get the
    standard reason phrase instead of the configured one.
    """
    try:
        from hypercorn.protocol import h11 as hyper_h11
        import h11 as h11lib
    except Exception:
        return

    original = hyper_h11.H11Protocol._send_h11_event

    async def _send_h11_event(self, event):
        if isinstance(event, h11lib.Response):
            scope = getattr(self.stream, "scope", None) if self.stream is not None else None
            reason = scope.get("state", {}).get(_REASON_STATE_KEY) if scope is not None else None
            if reason is not None:
                event = h11lib.Response(
                    status_code=event.status_code,
                    headers=event.headers,
                    http_version=event.http_version,
                    reason=reason.encode("latin1"),
                )
        return await original(self, event)

    hyper_h11.H11Protocol._send_h11_event = _send_h11_event


def _patch_hypercorn_ssl_shutdown():
    """Swallow TimeoutError from TLS wait_closed 

    Clients that drop TLS without a clean close_notify raise TimeoutError: "SSL shutdown timed out".
    Hypercorn leaves it uncaught in TCPServer._close, so this function catches it and aborts the connection.

    REMOVE when fixed upstream:
      https://github.com/pgjones/hypercorn/pull/342  (TimeoutError + abort)
      https://github.com/pgjones/hypercorn/issues/202
    After a hypercorn release that catches TimeoutError, delete this function and its call.
    """
    try:
        from hypercorn.asyncio.tcp_server import TCPServer
    except Exception:
        return

    original = TCPServer._close

    async def _close(self):
        try:
            await original(self)
        except TimeoutError:
            try:
                transport = self.writer.transport
                if transport is not None:
                    transport.abort()
            except Exception:
                pass

    TCPServer._close = _close


_patch_hypercorn_reason()
_patch_hypercorn_ssl_shutdown()

# Optional AI import - gracefully handle when AI dependencies aren't installed
try:
    from trapster.ai import HTTPAgent
    AI_AVAILABLE = True
except ImportError:
    HTTPAgent = None
    AI_AVAILABLE = False


class HttpHandler:
    def __init__(self, config, logger):
        self.protocol_name = "http"
        self.config = config or {}
        self.config.setdefault('skin', 'default_apache')
        self.config.setdefault('basic_auth', False)
        self.config.setdefault('username', None)
        self.config.setdefault('password', None)

        self.logger = logger
        self.logger.debug = False

        self.NAME = self.config.get('skin')
        self.BASIC_AUTH = self.config.get('basic_auth')
        self.USERNAME = self.config.get('username')
        self.PASSWORD = self.config.get('password')
        self.data_folder = Path(__file__).parent.parent / "data" / "http"

    def setup(self):
        try:
            resolved_path = (self.data_folder / self.NAME).resolve()
            if not resolved_path.is_relative_to(self.data_folder):
                raise ValueError(f"Invalid skin name: {self.NAME}")
        except (ValueError, RuntimeError):
            self.NAME = "default_apache"  # Fallback to a default skin

        self.static_folder = self.data_folder / self.NAME / "files"
        self.template_folder = self.data_folder / self.NAME / "templates"
        self.config_file = self.data_folder / self.NAME / "config.yaml"

        with self.config_file.open('r') as file:
            self.http_config = yaml.safe_load(file)

        self._resolve_deploy_config()
        self.env = self.create_jinja_env()
        # http_version: "2" offers HTTP/2 via ALPN (https only); clients that
        # negotiate h2 get lowercase headers, h1.1 clients get Title-Case. The
        # casing is decided per-request by the protocol, not by this flag.
        version = str(self.http_config.get('http_version', '') or '').strip()
        self.http2 = version in ('2', '2.0', 'h2')
        self.http_agent = HTTPAgent() if AI_AVAILABLE else None

    # --- request / config helpers ------------------------------------------

    @staticmethod
    def parse_query_string(query_string):
        """Parse 'a=1&b=2&c' into {'a': '1', 'b': '2', 'c': ''}."""
        params = {}
        for param in query_string.split('&') if query_string else []:
            key, sep, value = param.partition('=')
            params[key] = value
        return params

    async def sanitize_request(self, request):
        if not request:
            return None

        body = None
        form = {}
        if request.method in ["POST", "PUT", "PATCH"]:
            raw = await request.body()
            body = raw.decode() if raw else None
            # Parse form-urlencoded bodies so templates can reflect fields back
            # (e.g. the submitted username). Last value wins for repeated keys.
            ctype = request.headers.get("content-type", "")
            if body and "application/x-www-form-urlencoded" in ctype:
                form = dict(parse_qsl(body, keep_blank_values=True))

        return {
            "url": request.url,
            "path": request.url.path,
            "method": request.method,
            "headers": dict(request.headers),
            "body": body,
            "form": form,
            "remote": request.client.host if request.client else None,
            "cookies": request.cookies,
            "query_string": dict(request.query_params),
            "content_type": request.headers.get("content-type"),
            "host": request.headers.get("host"),
            "secure": request.url.scheme == "https",
            "scheme": request.url.scheme,
            "path_qs": str(request.url).split(request.base_url.netloc, 1)[1],
        }

    @staticmethod
    def make_etag_fn(deploy_seed, route_ref=None):
        """Build an etag() Jinja helper bound to a deploy seed.

        Parameters (all optional):
          weak, style ('iis'|'hash'), key, length, changenumber, fmt
        """
        if route_ref is None:
            route_ref = ['']

        def etag(weak=False, style='iis', key=None, length=None, changenumber=0, fmt=None):
            material = f"{deploy_seed}:{key if key is not None else route_ref[0]}"
            digest = hashlib.sha1(material.encode()).hexdigest()
            default_len = 32 if style == 'hash' else 13
            n = default_len if length is None else int(length)
            n = max(1, min(n, len(digest)))
            hexpart = digest[:n]

            if fmt is not None:
                token = str(fmt).format(hex=hexpart, n=changenumber, changenumber=changenumber)
                value = token if '"' in token else f'"{token}"'
            elif style == 'hash':
                value = f'"{hexpart}"'
            else:
                value = f'"{hexpart}:{changenumber}"'

            if weak:
                value = f'W/{value}'
            return value

        return etag

    def _resolve_deploy_config(self):
        """Evaluate Jinja expressions in config.yaml once at startup.

        A random deploy_seed is generated per process (stable for the honeypot's
        lifetime, unique across deployments) and exposed as {{ deploy_seed }}, so
        vars produce values that differ per deployment but stay identical across
        every request of a given deployment. Resolved vars become {{ vars.X }} in
        every template. Global/per-endpoint headers and inline content are also
        evaluated, letting fingerprint-prone values (etags, tokens, RSA keys)
        live as Jinja expressions instead of hardcoded strings.
        """
        deploy_seed = self.config.get('deploy_seed') or secrets.token_hex(8)
        route_ref = ['']

        eval_env = ImmutableSandboxedEnvironment(autoescape=False)
        eval_env.globals['random'] = self.random_filter
        eval_env.globals['deploy_seed'] = deploy_seed
        eval_env.globals['md5'] = lambda s: hashlib.md5(str(s).encode()).hexdigest()
        eval_env.globals['etag'] = self.make_etag_fn(deploy_seed, route_ref)
        eval_env.globals['route'] = ''

        def evaluate(value):
            if isinstance(value, str) and ('{{' in value or '{%' in value):
                # Values referencing `request` are per-request (e.g. a redirect
                # Location); leave them intact for render-time, not deploy-time.
                if 'request' in value:
                    return value
                try:
                    return eval_env.from_string(value).render()
                except Exception:
                    return value
            if isinstance(value, dict):
                return {k: evaluate(v) for k, v in value.items()}
            if isinstance(value, list):
                return [evaluate(v) for v in value]
            return value

        # Resolve vars sequentially so each entry can reference earlier ones via
        # {{ vars.X }} (enables derived values like md5(vars.server_id)).
        resolved_vars = {}
        for key, value in self.http_config.get('vars', {}).items():
            eval_env.globals['vars'] = resolved_vars
            resolved_vars[key] = evaluate(value)
        self.http_config['vars'] = resolved_vars
        eval_env.globals['vars'] = resolved_vars

        if 'headers' in self.http_config:
            self.http_config['headers'] = evaluate(self.http_config['headers'])

        for endpoint in self.http_config.get('endpoints', []):
            for route, details in endpoint.items():
                route_ref[0] = route
                eval_env.globals['route'] = route
                if not isinstance(details, list):
                    details = [details]
                for detail in details:
                    if 'headers' in detail:
                        detail['headers'] = evaluate(detail['headers'])
                    if 'content' in detail:
                        detail['content'] = evaluate(detail['content'])

        # Reused by create_jinja_env() so per-request templates get the same
        # deploy_seed / etag() as the deploy-time headers/content evaluated above.
        self._deploy_seed = deploy_seed
        self._etag_fn = self.make_etag_fn(deploy_seed)

    @staticmethod
    def random_filter(seed=None, alphabet=string.hexdigits[:-6], length=36):
        """Jinja helper generating a (optionally seeded) random string."""
        if seed is not None:
            random.seed(seed)
        return ''.join(random.choice(alphabet) for _ in range(length))

    def create_jinja_env(self):
        env = ImmutableSandboxedEnvironment(
            loader=FileSystemLoader(self.template_folder),
            autoescape=True,
            # Keep the original document's trailing newline so a rendered page
            # is byte-for-byte identical to the source (Content-Length tell).
            keep_trailing_newline=True,
        )
        env.globals.update({
            'random': self.random_filter,
            'get_current_time': lambda: datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT'),
            'uuid': lambda: str(uuid.uuid4()),
            'vars': self.http_config.get('vars', {}),
            'etag': getattr(self, '_etag_fn', self.make_etag_fn(getattr(self, '_deploy_seed', ''))),
            'deploy_seed': getattr(self, '_deploy_seed', ''),
        })
        env.filters['quote'] = lambda s: quote(str(s), safe='')
        env.undefined = Undefined
        return env

    @staticmethod
    def _query_matches(rules, params):
        """True if every query rule (regex per param) matches the request."""
        return all(name in params and re.fullmatch(pattern, params[name])
                   for name, pattern in rules.items())

    def get_endpoint_config(self, full_url, method):
        """Find the config entry matching this URL + method (+ query rules)."""
        base_url, _, query_string = full_url.partition('?')
        query_params = self.parse_query_string(query_string)

        for endpoint in self.http_config.get('endpoints', []):
            for route, details in endpoint.items():
                if not re.fullmatch(route, base_url):
                    continue
                if not isinstance(details, list):
                    details = [details]
                candidates = [d for d in details if d['method'] == method]

                # Prefer a config whose query rules all match the request,
                # otherwise fall back to one with no query rules.
                for config in candidates:
                    if config.get('query') and self._query_matches(config['query'], query_params):
                        return config
                fallback = next((d for d in candidates if not d.get('query')), None)
                if fallback:
                    return fallback
        return None

    def parse_front_matter(self, content):
        """Extract optional YAML-ish front matter, allowing a template to set
        its own status code:

            ---
            status_code: 500
            ---

        Returns (metadata_dict, body).
        """
        if content.startswith('---'):
            parts = content.split('---', 2)
            if len(parts) >= 3:
                header, body = parts[1].strip(), parts[2].strip()
                metadata = {}
                for line in header.splitlines():
                    if ':' in line:
                        key, value = line.split(':', 1)
                        metadata[key.strip()] = value.strip()
                return metadata, body
        return {}, content

    # --- content / response building ---------------------------------------

    # Suffixes served as Jinja text templates from templates/.
    _JINJA_FILE_SUFFIXES = frozenset({
        '.html', '.htm', '.css', '.js', '.json', '.xml', '.txt', '.svg',
        '.csv', '.md', '.map', '.j2',
    })

    async def get_content(self, endpoint_config, request=None):
        if not endpoint_config:
            return "", 200

        if 'content' in endpoint_config:
            return endpoint_config['content'], endpoint_config.get('status_code', 200)

        if 'file' in endpoint_config:
            file_path = (self.template_folder / endpoint_config['file']).resolve()
            try:
                # Guard against path traversal outside the template folder.
                file_path.relative_to(self.template_folder.resolve())
                if not file_path.is_file():
                    raise FileNotFoundError(file_path)
                status = int(endpoint_config.get('status_code', 200))
                # Binary assets (fonts, icons, …) — raw bytes, no Jinja.
                if file_path.suffix.lower() not in self._JINJA_FILE_SUFFIXES:
                    return file_path.read_bytes(), status
                raw_content = file_path.read_text()
                template = self.env.from_string(raw_content)
                template.globals['request'] = await self.sanitize_request(request)
                metadata, body = self.parse_front_matter(template.render())
                return body, int(metadata.get('status_code', status))
            except (ValueError, FileNotFoundError, UnicodeDecodeError) as e:
                print(f"Error: {e}")

        elif 'ai' in endpoint_config:
            # experimental AI response: prompt = configured text + requested path
            session_id = request.client.host
            prompt = endpoint_config['ai'] + "\n" + request.url.path
            result = await self.http_agent.make_query("http:" + session_id, prompt) if self.http_agent else None
            if result is None:
                return '', 404
            # the AI response is sometimes wrapped in a ```json block
            result = result.replace('```json\n', '').replace('\n```', '')
            return result, 200

        return "", 404

    @staticmethod
    def _strip_ctl(value):
        """Drop CR/LF and other control chars. Rendered header and reason values
        can contain attacker data (request.path, request.method); stripping
        control chars prevents HTTP response / status-line injection."""
        return ''.join(c for c in value
                       if c == '\t' or (' ' <= c < '\x7f') or c > '\xa0')

    @staticmethod
    def _is_not_modified(request, headers: dict) -> bool:
        """True if the request's conditional headers indicate the resource is unchanged."""
        etag = next((v for k, v in headers.items() if k.lower() == "etag"), None)
        if etag:
            inm = request.headers.get("if-none-match", "")
            if inm and (inm.strip('"') == etag.strip('"') or inm == "*"):
                return True
        last_modified = next((v for k, v in headers.items() if k.lower() == "last-modified"), None)
        if last_modified:
            ims = request.headers.get("if-modified-since", "")
            if ims:
                try:
                    from email.utils import parsedate_to_datetime
                    if parsedate_to_datetime(ims) >= parsedate_to_datetime(last_modified):
                        return True
                except Exception:
                    if ims == last_modified:
                        return True
        return False

    def _render_reason(self, config, request_info):
        """Render a config entry's optional 'reason' Jinja template to a string."""
        raw = config.get("reason") if config else None
        if not raw:
            return None
        try:
            template = self.env.from_string(raw)
            template.globals["request"] = request_info
            return self._strip_ctl(template.render().strip()) or None
        except Exception:
            return None

    async def _set_reason(self, config, request):
        """Stash the custom reason phrase (if any) for the hypercorn patch to pick up."""
        reason = self._render_reason(config, await self.sanitize_request(request))
        if reason:
            request.scope.setdefault("state", {})[_REASON_STATE_KEY] = reason

    # --- delay -------------------------------------------------------------

    # Gaussian response delay: mu/sigma tuned to mimic a modest embedded web
    # server (mean ~300 ms, most responses between 80 ms and 520 ms).
    _DELAY_MU    = 0.30
    _DELAY_SIGMA = 0.11
    _DELAY_MIN   = 0.05
    _DELAY_MAX   = 0.80

    _DELAY_MU_POST    = 0.80
    _DELAY_SIGMA_POST = 0.20
    _DELAY_MIN_POST   = 0.30
    _DELAY_MAX_POST   = 2.50

    async def _apply_delay(self, method: str = "GET"):
        if method == "POST":
            mu, sigma = self._DELAY_MU_POST, self._DELAY_SIGMA_POST
            min_d, max_d = self._DELAY_MIN_POST, self._DELAY_MAX_POST
        else:
            mu, sigma = self._DELAY_MU, self._DELAY_SIGMA
            min_d, max_d = self._DELAY_MIN, self._DELAY_MAX
        delay = random.gauss(mu, sigma)
        await asyncio.sleep(max(min_d, min(max_d, delay)))

    # --- request handlers --------------------------------------------------

    def _log_type(self, request):
        """POST/PUT/PATCH or any request with an Authorization header -> login."""
        if request.method in ("POST", "PUT", "PATCH"):
            return self.logger.LOGIN
        if request.headers.get("Authorization"):
            return self.logger.LOGIN
        return self.logger.QUERY

    async def handle_request(self, request):
        if not await self.check_auth(request):
            return await self.handle_error(request, 401)

        target = str(request.url).split(request.base_url.netloc, 1)[1]
        endpoint_config = self.get_endpoint_config(target, request.method)

        if endpoint_config:
            await self._apply_delay(request.method)
            combined_headers = {**self.http_config.get('headers', {}),
                                 **endpoint_config.get('headers', {})}
            if self._is_not_modified(request, combined_headers):
                await self.log(request, self._log_type(request), 304)
                return Response(content=b"", status_code=304,
                                headers={k: v for k, v in combined_headers.items()
                                         if k.lower() in ("etag", "cache-control", "last-modified")})
            content, status_code = await self.get_content(endpoint_config, request)
            status_code = endpoint_config.get('status_code', status_code)
            headers = dict(endpoint_config.get('headers', {}))
            await self._set_reason(endpoint_config, request)
            await self.log(request, self._log_type(request), status_code)
        else:
            # only the default response is logged (inside handle_default)
            content, status_code, headers = await self.handle_static_file(request)

        response_headers = self.http_config.get('headers', {}).copy()
        response_headers.update(headers)
        return await self._make_response(content, status_code, response_headers, request)

    async def _render_request_headers(self, headers, request):
        """Render per-request Jinja in header VALUES (e.g. a redirect
        'Location: https://{{ request.host }}{{ request.path }}'). Deploy-time
        vars are already resolved; only values still containing '{{' are
        rendered, and request_info is built lazily at most once."""
        info = None
        rendered = {}
        for key, value in headers.items():
            if isinstance(value, str) and '{{' in value:
                if info is None:
                    info = await self.sanitize_request(request)
                try:
                    tmpl = self.env.from_string(value)
                    tmpl.globals['request'] = info
                    value = self._strip_ctl(tmpl.render())
                except Exception:
                    pass
            rendered[key] = value
        return rendered

    @staticmethod
    def _cookie_name_from_set_cookie(value: str):
        """Return the cookie name from a Set-Cookie header value, or None."""
        first = value.split(';', 1)[0].strip()
        if '=' in first:
            return first.split('=', 1)[0].strip()
        return None

    async def _make_response(self, content, status_code, headers, request):
        """Build a Response serving exactly the configured headers.

        Content-Type is NOT inferred: some origins send no Content-Type, and a
        faithful copy must reproduce that. We pass headers as-is and never pass
        media_type, so Starlette adds a Content-Type only when the config
        provides one. Static files set their own Content-Type (mimetypes) before
        reaching here. The header name's case is restored by the middleware.

        Set-Cookie headers are suppressed when the client already carries that
        cookie, so repeated requests don't keep re-setting the same cookie.
        """
        headers = await self._render_request_headers(headers, request)
        if request is not None:
            client_cookies = request.cookies
            headers = {
                k: v for k, v in headers.items()
                if not (
                    k.lower() == 'set-cookie'
                    and (name := self._cookie_name_from_set_cookie(v)) is not None
                    and name in client_cookies
                )
            }
        return Response(content=content, status_code=status_code, headers=headers)

    async def handle_static_file(self, request):
        if request.url.path.endswith('/'):
            rel = request.url.path.lstrip('/') + 'index.html'
        elif request.method == 'GET':
            rel = request.url.path.lstrip('/')
        else:
            return await self.handle_default(request)

        # Resolve BOTH sides and require strict containment so attacker-supplied
        # paths (../, symlinks, encoded traversal, NUL bytes) cannot escape the
        # skin's files/ directory (LFI). Anything outside falls through to the
        # normal default response, so a probe looks like an ordinary 404.
        try:
            static_root = self.static_folder.resolve()
            base = self.static_folder.resolve()
            file_path = (self.static_folder / rel).resolve()
            file_path.relative_to(base)
            if file_path.is_file():
                content = file_path.read_bytes()
                content_type = (mimetypes.guess_type(str(file_path))[0]
                                or 'application/octet-stream')
                return content, 200, {'Content-Type': content_type}
        except (ValueError, OSError):
            pass

        return await self.handle_default(request)

    async def handle_default(self, request):
        await self._apply_delay(request.method)
        config = self.http_config.get('default')
        content, _ = await self.get_content(config, request)
        status_code = config.get('status_code', 404)
        headers = dict(config.get('headers', {}))
        await self._set_reason(config, request)
        await self.log(request, self._log_type(request), status_code)
        return content, status_code, headers

    async def handle_error(self, request, error_code):
        # Use the configured error response, else an {error_code}.html template.
        errors = self.http_config.get('errors', {})
        error_config = errors.get(str(error_code))
        content, _ = await self.get_content(error_config or {"file": f"{error_code}.html"}, request)

        headers = self.http_config.get('headers', {}).copy()
        headers.update((error_config or {}).get('headers', {}))
        if error_code == 401:
            headers['WWW-Authenticate'] = 'Basic realm="Restricted Area"'
        await self._set_reason(error_config, request)

        await self.log(request, self._log_type(request), error_code)
        return await self._make_response(content, error_code, headers, request)

    async def handle_unknown_method(self, request):
        """Respond to non-standard HTTP methods (custom verbs like 'DEADZA')."""
        config = self.http_config.get('unknown_method')
        if not config:
            return await self.handle_error(request, 405)

        content, _ = await self.get_content(config, request)
        status_code = config.get('status_code', 405)
        headers = self.http_config.get('headers', {}).copy()
        headers.update(config.get('headers', {}))
        await self._set_reason(config, request)

        await self.log(request, self._log_type(request), status_code)
        return await self._make_response(content, status_code, headers, request)

    # --- auth / logging ----------------------------------------------------

    async def check_auth(self, request):
        if not self.BASIC_AUTH:
            return True

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return False
        try:
            encoded_credentials = auth_header.split(' ', 1)[1]
            username, password = base64.b64decode(encoded_credentials).decode('utf-8').split(':')
            return username == self.USERNAME and password == self.PASSWORD
        except Exception as e:
            print(f"Error: {e}")
            return False

    async def log(self, request, log_type, status_code, extra=None):
        """Log a request. For POST/PUT/PATCH, the body is stored and scanned for
        common credential fields (form-encoded or XML/SOAP)."""
        src_ip, src_port = request.client.host, request.client.port
        dst_ip, dst_port = request.scope.get("server", ("unknown", "unknown"))

        all_extra = {
            "skin": self.NAME,
            "method": request.method,
            "target": str(request.url).split(request.base_url.netloc, 1)[1],
            "version": request.scope.get("http_version"),
            "headers": dict(request.headers),
            "status_code": status_code,
            # Manually added because transport doesn't exist
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
        }
        all_extra.update(extra or {})

        auth_header = request.headers.get("Authorization")
        if auth_header:
            scheme, _, token = auth_header.partition(" ")
            all_extra["auth_scheme"] = scheme
            if scheme.lower() == "basic" and token:
                try:
                    username, _, password = base64.b64decode(token).decode("utf-8").partition(":")
                    all_extra["username"] = username
                    all_extra["password"] = password
                except Exception:
                    all_extra["auth_token"] = token
            elif token:
                all_extra["auth_token"] = token

        data = ''
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                if body:
                    data = body
                    all_extra.update(self._extract_credentials(body.decode('utf-8', errors='replace')))
            except ClientDisconnect:
                pass

        self.logger.log(f"{self.protocol_name}.{log_type}", request.client, data=data, extra=all_extra)

    # Form fields commonly carrying credentials, by role.
    _USERNAME_FIELDS = {'login', 'username', 'account', 'user%5Blogin%5D', 'j_username', 'ba_username'}
    _PASSWORD_FIELDS = {'password', 'credential', 'passwd', 'user%5Bpassword%5D', 'j_password', 'secretkey', 'ba_password'}

    def _extract_credentials(self, form_data):
        """Pull username/password out of a POST body (form-encoded or XML/SOAP)."""
        extra = {'form': form_data}

        for key, value in self.parse_query_string(form_data).items():
            if key in self._USERNAME_FIELDS:
                extra['username'] = value
            elif key in self._PASSWORD_FIELDS:
                extra['password'] = value

        if '<Envelope' in form_data and '</Envelope>' in form_data:
            for tag, field in (('userName', 'username'), ('password', 'password')):
                open_tag, close_tag = f'<{tag}>', f'</{tag}>'
                if open_tag in form_data and close_tag in form_data:
                    start = form_data.find(open_tag) + len(open_tag)
                    extra[field] = form_data[start:form_data.find(close_tag)]

        return extra


class HeaderCapitalizationMiddleware:
    """Set response header-name casing from the negotiated protocol and inject
    the Date header (Hypercorn's own date/server headers are disabled).

    Starlette lowercases all outgoing header names. Casing is then decided
    purely by scope['http_version']:

    - HTTP/2: names stay lowercase (required by the protocol); 'date' is injected.
    - HTTP/1.1: names are Title-Cased (the convention); 'Date' is injected.
    """

    # Standard headers whose canonical case isn't simple Title-Case.
    _TITLE_EXCEPTIONS = {'etag': 'ETag', 'www-authenticate': 'WWW-Authenticate'}

    def __init__(self, app):
        self.app = app

    def _title(self, lower):
        return self._TITLE_EXCEPTIONS.get(lower, lower.title())

    async def _handle_lifespan(self, receive, send):
        # The honeypot app has no startup/shutdown logic. Handling the lifespan
        # protocol here (instead of letting Starlette do it) avoids Hypercorn's
        # noisy LifespanFailureError when the server task is cancelled on Ctrl+C.
        while True:
            try:
                message = await receive()
            except asyncio.CancelledError:
                return
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self._handle_lifespan(receive, send)
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        is_h2 = scope.get("http_version") == "2"

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                has_date = False
                names = []  # lowercase name, value
                for raw_name, raw_value in message.get("headers", []):
                    lower = raw_name.decode("latin1").lower()
                    if lower == "date":
                        has_date = True
                    names.append((lower, raw_value))

                if is_h2:
                    headers = [[lower.encode("latin1"), value] for lower, value in names]
                    date_name = b"date"
                else:
                    headers = [[self._title(lower).encode("latin1"), value]
                               for lower, value in names]
                    date_name = b"Date"

                if not has_date:
                    date_val = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
                    headers.append([date_name, date_val.encode("latin1")])

                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, send_wrapper)


class TrustedProxyMiddleware:
    """Resolve the real client address when a trusted reverse proxy fronts
    the service. For connections from a trusted peer the client IP is taken
    from the X-Forwarded-For chain (rightmost non-trusted address) or from
    X-Real-IP. Entries are IP addresses or CIDR networks.
    Without trusted_proxies configured nothing changes."""

    def __init__(self, app, trusted_proxies=None):
        self.app = app
        self.networks = []
        if isinstance(trusted_proxies, str):
            trusted_proxies = [trusted_proxies]
        log = logging.getLogger(__name__)
        for entry in trusted_proxies or []:
            net = self._network(entry) if isinstance(entry, str) else None
            if net is not None:
                self.networks.append(net)
                if net.prefixlen == 0:
                    log.warning(
                        "trusted_proxies entry %r trusts every peer; "
                        "client-supplied headers become unreliable", entry)
            else:
                log.warning(
                    "trusted_proxies entry %r ignored: expected an IP "
                    "address or CIDR network", entry)

    MAX_CHAIN_ENTRIES = 32

    @staticmethod
    def _addr(value):
        value = value.strip()
        if value.startswith("["):
            end = value.find("]")
            if end == -1:
                return None
            tail = value[end + 1:]
            if tail and not (tail.startswith(":")
                             and tail[1:].isascii() and tail[1:].isdigit()):
                return None
            value = value[1:end]
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return None
        mapped = getattr(addr, "ipv4_mapped", None)
        return mapped or addr

    @staticmethod
    def _network(value):
        log = logging.getLogger(__name__)
        try:
            ipaddress.ip_network(value)
        except ValueError:
            strict_ok = False
        else:
            strict_ok = True
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        if not strict_ok:
            log.warning(
                "trusted_proxies entry %r has host bits set; "
                "using %s", value, net)
        if (net.version == 6 and net.prefixlen >= 96 and
                net.subnet_of(ipaddress.ip_network("::ffff:0:0/96"))):
            log.warning(
                "trusted_proxies entry %r is IPv4-mapped and can never "
                "match; use the IPv4 form instead", value)
        return net

    def _is_trusted(self, value):
        addr = self._addr(value)
        if addr is None:
            return False
        return any(net.version == addr.version and addr in net
                   for net in self.networks)

    def _resolve(self, scope):
        client = scope.get("client")
        if not (client and self.networks and self._is_trusted(client[0])):
            return
        xff_parts = []
        real_ips = []
        for name, value in scope.get("headers", []):
            name = name.decode("latin1").lower()
            if name == "x-forwarded-for":
                xff_parts.append(value.decode("latin1"))
            elif name == "x-real-ip":
                real_ips.append(value.decode("latin1"))
        ip = None
        chain = ",".join(xff_parts).split(",")
        for part in reversed(chain[-self.MAX_CHAIN_ENTRIES:]):
            addr = self._addr(part.strip())
            if addr is None:
                break
            if not self._is_trusted(part.strip()):
                ip = str(addr)
                break
        if ip is None and not xff_parts and len(real_ips) == 1:
            addr = self._addr(real_ips[0].strip())
            if addr is not None:
                ip = str(addr)
        if ip is not None:
            scope["client"] = (ip, client[1])

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            self._resolve(scope)
        await self.app(scope, receive, send)


class HttpHoneypot(BaseHoneypot):
    service_name = "http"

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.port = config['port']
        self.trusted_proxies = config.get('trusted_proxies') or []
        self.handler = HttpHandler(config=config, logger=logger)
        self.fastapi_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        self.app = None  # set after route setup in start()
        self.server = None

        # FastAPI only routes standard methods; custom verbs are handled here.
        @self.fastapi_app.middleware("http")
        async def custom_method_middleware(request: Request, call_next):
            if request.method not in STANDARD_METHODS:
                return await self.handler.handle_unknown_method(request)
            return await call_next(request)

    def _hypercorn_config(self):
        """Base Hypercorn config shared by HTTP and HTTPS. Date and Server are
        disabled here; the middleware injects Date (with protocol-correct case)
        and Server comes from the skin's config headers."""
        from hypercorn.config import Config as HyperConfig
        config = HyperConfig()
        config.bind = [f"{self.bindaddr}:{self.port}"]
        config.include_server_header = False
        config.include_date_header = False
        config.accesslog = None
        config.errorlog = None
        return config

    async def _serve_hypercorn(self, config):
        from hypercorn.asyncio import serve as hyper_serve
        try:
            await hyper_serve(self.app, config,
                              shutdown_trigger=self._shutdown_event.wait)
        except (OSError, SystemExit) as e:
            self._log_bind_error(e)
            return False
        except asyncio.CancelledError:
            self._shutdown_event.set()
            raise

    async def start(self):
        self.handler.setup()

        @self.fastapi_app.api_route("/{path:path}", methods=list(STANDARD_METHODS))
        async def catch_all(request: Request, path: str):
            return await self.handler.handle_request(request)

        self.app = HeaderCapitalizationMiddleware(
            TrustedProxyMiddleware(self.fastapi_app, self.trusted_proxies))
        self._shutdown_event = asyncio.Event()
        return await super().start()

    async def _start_server(self):
        # Plaintext HTTP/1.1 (no ALPN). Hypercorn is used for both HTTP and
        # HTTPS so there is a single server backend.
        return await self._serve_hypercorn(self._hypercorn_config())

    async def stop(self):
        if getattr(self, '_shutdown_event', None) is not None:
            self._shutdown_event.set()
        return await super().stop()
