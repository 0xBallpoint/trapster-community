from aiohttp import web
from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2 import FileSystemLoader, Undefined
import yaml
import random, string, base64, mimetypes, re
from datetime import datetime, timezone
from pathlib import Path

from .base import BaseHoneypot

class HttpHandler:
    def __init__(self, config, logger):
        self.protocol_name = "http"

        self.config = config
        self.logger = logger

        self.NAME = config.get('skin', 'default_apache')
        self.BASIC_AUTH = config.get('basic_auth', False)
        self.USERNAME = config.get('username', None)
        self.PASSWORD = config.get('password', None)

        self.data_folder = Path(__file__).parent.parent / "data" / "http" / self.NAME
        self.static_folder = self.data_folder / "files"
        self.template_folder = self.data_folder / "templates"
        self.config_file = self.data_folder / "config.yaml"

        self.http_config = self.load_config()
        self.env = self.create_jinja_env()

    def load_config(self):
        with self.config_file.open('r') as file:
            return yaml.safe_load(file)

    @staticmethod
    def sanitize_request(request):
        if request:
            return { 
                "url": request.url,
                "path": request.path,
                "method": request.method,
                "headers": dict(request.headers),
                "body": request.body if request.body_exists else "",
                "remote": request.remote, 
                "cookies": request.cookies,
                "query_string": request.query_string,
                "content_type": request.content_type,
                "host": request.host,
                "secure": request.secure,
                "scheme": request.scheme,
                "path_qs": request.path_qs
            }
        
    @staticmethod
    def random_filter(seed=None, alphabet=string.hexdigits[:-6], length=36):
        # Jinja filter to generate a random string
        if seed is not None:
            random.seed(seed)
        return ''.join(random.choice(alphabet) for _ in range(length))

    def create_jinja_env(self):
        env = ImmutableSandboxedEnvironment(
            loader=FileSystemLoader(self.template_folder),
            autoescape=True
        )
        env.globals.update({
            'random': self.random_filter,
            'get_current_time': lambda: datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT'),
        })
        env.undefined = Undefined
        return env

    def get_endpoint_config(self, full_url, method):
        for endpoint in self.http_config.get('endpoints', []):
            for route, details in endpoint.items():
                if re.fullmatch(route, full_url):
                    if isinstance(details, list):
                        return next((d for d in details if d['method'] == method), None)
                    elif details['method'] == method:
                        return details
        return None

    def get_content(self, endpoint_config, request=None):
        if not endpoint_config:
            return "", 200
        
        if 'content' in endpoint_config:
            return endpoint_config['content'], endpoint_config.get('status_code', 200)
        elif 'file' in endpoint_config:
            file_path = self.template_folder / endpoint_config['file']
            try:
                if file_path.resolve().relative_to(self.template_folder.resolve()):
                    file_path = file_path.resolve()
                    with file_path.open('r') as file:
                         # add request object to the template
                        template = self.env.from_string(file.read())
                        template.globals['request'] = self.sanitize_request(request)

                    return template.render(), 200
            except (ValueError, FileNotFoundError):
                pass
        return "File not found", 404

    async def handle_error(self, request, error_code):
        # Check if errors is defined in config.yaml, otherwise use a error template (like 401.html), otherwise send nothing
        error_config = self.http_config.get('errors', {}).get(str(error_code))
        if error_config:
            content, _ = self.get_content(error_config)
        else:
            content, _ = self.get_content({"file": f"{error_code}.html"})

        headers = self.http_config.get('headers', {}).copy()
        headers.update(self.http_config.get('errors', {}).get(str(error_code), {}).get('headers', {}))
        
        if error_code == 401:
            headers['WWW-Authenticate'] = 'Basic realm="Restricted Area"'
        
        await self.log(request, self.logger.QUERY, error_code)
        return web.Response(body=content, content_type='text/html', status=error_code, headers=headers)

    async def create_response(self, request, content, status_code, headers, endpoint_config=None):
        # Use configured headers if available, otherwise use default headers
        response_headers = self.http_config.get('headers', {}).copy()
        if endpoint_config:
            response_headers.update(endpoint_config.get('headers', {}))
        response_headers.update(headers)

        # Determine content type
        content_type = response_headers.pop('Content-Type', 'text/html')

        await self.log(request, self.logger.QUERY, status_code)
        return web.Response(body=content, content_type=content_type, charset='utf-8', 
                            status=status_code, headers=response_headers)

    async def handle_request(self, request):
        if self.BASIC_AUTH and not self.check_auth(request):
            return await self.handle_error(request, 401)

        full_url = request.url.path_qs
        method = request.method
        endpoint_config = self.get_endpoint_config(full_url, method)
        headers = {}

        if endpoint_config:
            # Use configured response    
            content, status_code = self.get_content(endpoint_config, request)
            status_code = endpoint_config.get('status_code', status_code)
        else:
            content, status_code, headers = self.handle_static_file(request)

        return await self.create_response(request, content, status_code, headers, endpoint_config)

    def check_auth(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return False
        encoded_credentials = auth_header.split(' ', 1)[1]
        username, password = base64.b64decode(encoded_credentials).decode('utf-8').split(':')
        self.logger.log(f"{self.protocol_name}.{self.logger.LOGIN}", request.transport, 
                        extra={"username": username, "password": password})
        return username == self.USERNAME and password == self.PASSWORD

    def handle_static_file(self, request):
        if request.path.endswith('/'):
            file_path = self.static_folder / request.path.lstrip('/') / 'index.html'
        elif request.method == 'GET':
            file_path = self.static_folder / request.path.lstrip('/')
        else:
            return self.get_default_response()

        try:
            if file_path.resolve().relative_to(self.static_folder) and file_path.is_file():
                content = file_path.read_bytes()
                content_type = mimetypes.guess_type(str(file_path))[0] or 'application/octet-stream'
                return content, 200, {'Content-Type': content_type}
        except ValueError:
            pass
        return self.get_default_response()

    def get_default_response(self):
        default_response = self.http_config.get('default')
        content, _ = self.get_content(default_response)
        status_code = default_response.get('status_code', 404)
        return content, status_code, {}
    
    async def log(self, request, log_type, status_code, extra=None):
        all_extra = {
            "method": request.method,
            "target": request.path,
            "version": f"HTTP/{request.version.major}.{request.version.minor}",
            "headers": dict(request.headers),
            "status_code": status_code,
        }

        if request.body_exists:
            all_extra["data"] = (await request.read()).decode(errors='backslashreplace')
        all_extra.update(extra or {})
        self.logger.log(f"{self.protocol_name}.{log_type}", request.transport, extra=all_extra)


class HttpHoneypot(BaseHoneypot):
    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.port = config['port']
        self.handler = HttpHandler(config=config, logger=logger)

    async def start(self):
        app = web.Application()
        app.add_routes([web.route('*', '/{path:.*}', self.handler.handle_request)])
        runner = web.AppRunner(app, access_log=None, handle_signals=True)
        await runner.setup()
        self.site = web.TCPSite(runner, self.bindaddr, self.port)
        await self.site.start()

    async def stop(self):
        if hasattr(self, 'site'):
            await self.site.stop()
