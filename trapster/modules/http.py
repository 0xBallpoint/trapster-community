import uvicorn
import asyncio
from starlette.requests import ClientDisconnect
from fastapi import FastAPI, Request, Response

from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2 import FileSystemLoader, Undefined
import yaml
import random, string, base64, mimetypes, re
from datetime import datetime, timezone
from pathlib import Path

from trapster.modules.base import BaseHoneypot
from trapster.libs.ai.http import HttpAI

class HttpHandler:
    def __init__(self, config, logger):
        self.protocol_name = "http"

        self.logger = logger

        self.NAME = config.get('skin', 'default_apache')
        self.BASIC_AUTH = config.get('basic_auth', False)
        self.USERNAME = config.get('username', None)
        self.PASSWORD = config.get('password', None)

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
        
        self.env = self.create_jinja_env()

    @staticmethod
    def parse_query_string(query_string):
        # Parse query string into a dictionary
        query_dict = {}
        if query_string:
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    query_dict[key] = value
                else:
                    query_dict[param] = ''
        return query_dict

    async def sanitize_request(self, request):
        if request:
            body = None
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
                body = body.decode() if body else None
                
            return { 
                "url": request.url,
                "path": request.url.path,
                "method": request.method,
                "headers": dict(request.headers),
                "body": body,
                "remote": request.client.host if request.client else None, 
                "cookies": request.cookies,
                "query_string": dict(request.query_params),
                "content_type": request.headers.get("content-type"),
                "host": request.headers.get("host"),
                "secure": request.url.scheme == "https",
                "scheme": request.url.scheme,
                "path_qs": str(request.url).split(request.base_url.netloc, 1)[1]
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
        # Parse URL and query parameters
        base_url = full_url.split('?')[0]
        query_string = full_url.split('?')[1] if '?' in full_url else ''
        query_params = {}
        if query_string:
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    query_params[key] = value
                else:
                    query_params[param] = ''

        for endpoint in self.http_config.get('endpoints', []):
            for route, details in endpoint.items():
                # 1. Check base URL match first
                if not re.fullmatch(route, base_url):
                    continue

                # 2. Check method match
                if not isinstance(details, list):
                    details = [details]  # Convert single config to list format

                # Find all configs that match the method
                matching_configs = [d for d in details if d['method'] == method]
                if not matching_configs:
                    continue
                
                # 3. Handle query parameters
                if not query_params:
                    # URL has no query params - look for config without query rules
                    no_query_config = next((d for d in matching_configs if not d.get('query')), None)
                    if no_query_config:
                        return no_query_config
                else:
                    # URL has query params - try to find matching query rules
                    for config in matching_configs:
                        if not config.get('query'):
                            continue
                        
                        # Check each query parameter rule
                        matches_all = True
                        query_rules = config['query']
                        for param_name, pattern in query_rules.items():
                            if param_name not in query_params or not re.fullmatch(pattern, query_params[param_name]):
                                matches_all = False
                                break
                        if not matches_all:
                            continue
                        
                        if matches_all:
                            return config

                    # If no query rules matched but we have a base URL match,
                    # return the first config without query rules
                    no_query_config = next((d for d in matching_configs if not d.get('query')), None)
                    if no_query_config:
                        return no_query_config
        
        return None

    def parse_front_matter(self, content):
        """
        This allows the rendered template to overwrite the status code of the request using:
            ---
            status_code: 500
            ---

        Returns:
            tuple: A dictionary of metadata (e.g., status_code) and the template content.
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
        return {}, content  # No front matter found, return empty metadata

    async def get_content(self, endpoint_config, request=None):
        if not endpoint_config:
            return "", 200
        
        if 'content' in endpoint_config:
            return endpoint_config['content'], endpoint_config.get('status_code', 200)
        
        elif 'file' in endpoint_config:
            file_path = self.template_folder / endpoint_config['file']
            try:
                if file_path.resolve().relative_to(self.template_folder.resolve()):
                    file_path = file_path.resolve()
                    # Read the template file
                    with file_path.open('r') as file:
                        raw_content = file.read()

                    # Add the request object to the template and render it
                    template = self.env.from_string(raw_content)
                    template.globals['request'] = await self.sanitize_request(request)
                    rendered_output = template.render()

                    # Parse the front matter and template content
                    metadata, template_content = self.parse_front_matter(rendered_output)

                    # Extract the status_code from metadata or default to 200
                    status_code = int(metadata.get('status_code', 200))

                    return template_content, status_code
            except (ValueError, FileNotFoundError) as e:
                print(f"Error: {e}")
                pass

        elif 'ai' in endpoint_config:
            # experimental ai response
            ai_agent = HttpAI()
            peer_addr = request.client.host
            session_id = peer_addr
            query_string = str(request.url).split('?', 1)[1] if '?' in str(request.url) else ''
            result = await ai_agent.make_query("http:"+session_id, query_string)
            result = result.replace('```json\n', '').replace('\n```', '') # sometime the AI response is wrapped in ```json
            return result, 200
        
        return "", 404

    async def handle_error(self, request, error_code):
        # Check if errors is defined in config.yaml
        # otherwise use a error template (like 401.html)
        # otherwise send nothing
        error_config = self.http_config.get('errors', {}).get(str(error_code))
        if error_config:
            content, _ = await self.get_content(error_config)
        else:
            content, _ = await self.get_content({"file": f"{error_code}.html"})

        headers = self.http_config.get('headers', {}).copy()
        headers.update(self.http_config.get('errors', {}).get(str(error_code), {}).get('headers', {}))
        
        if error_code == 401:
            headers['WWW-Authenticate'] = 'Basic realm="Restricted Area"'

        await self.log(request, self.logger.QUERY, error_code)
        return Response(content=content, media_type='text/html', status_code=error_code, headers=headers)

    async def check_auth(self, request):
        if not self.BASIC_AUTH:
            return True
            
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return False
        encoded_credentials = auth_header.split(' ', 1)[1]
        username, password = base64.b64decode(encoded_credentials).decode('utf-8').split(':')
        await self.log(request, self.logger.LOGIN, 401, extra={"username": username, "password": password})
        return username == self.USERNAME and password == self.PASSWORD

    async def handle_request(self, request):
        if not await self.check_auth(request):
            return await self.handle_error(request, 401)

        full_url = str(request.url).split(request.base_url.netloc, 1)[1]
        
        method = request.method
        endpoint_config = self.get_endpoint_config(full_url, method)
        headers = {}

        if endpoint_config:
            # Use configured response    
            content, status_code = await self.get_content(endpoint_config, request)
            status_code = endpoint_config.get('status_code', status_code)
            headers = endpoint_config.get('headers', {})
            if method == "POST":
                await self.log(request, self.logger.LOGIN, status_code)
            else:
                await self.log(request, self.logger.QUERY, status_code)

        else:
            content, status_code, headers = await self.handle_static_file(request)
            # only default response is logged

        # Prepare response headers
        response_headers = self.http_config.get('headers', {}).copy()
        response_headers.update(headers)

        # Determine content type, we cannot use both content_type variable and Content-Type in headers
        content_type = response_headers.pop('Content-Type', 'text/html')

        return Response(content=content, media_type=content_type, status_code=status_code, headers=response_headers)

    async def handle_static_file(self, request):
        if request.url.path.endswith('/'):
            file_path = self.static_folder / request.url.path.lstrip('/') / 'index.html'
        elif request.method == 'GET':
            file_path = self.static_folder / request.url.path.lstrip('/')
        else:
            return await self.handle_default(request)

        try:
            if file_path.resolve().relative_to(self.static_folder) and file_path.is_file():
                content = file_path.read_bytes()
                content_type = mimetypes.guess_type(str(file_path))[0] or 'application/octet-stream'
                return content, 200, {'Content-Type': content_type}
        except ValueError:
            return "", 500, {}

        return await self.handle_default(request)

    async def handle_default(self, request):
        default_response = self.http_config.get('default')
        content, _ = await self.get_content(default_response)
        status_code = default_response.get('status_code', 404)
        headers = default_response.get('headers', {})
        await self.log(request, self.logger.QUERY, status_code)
        return content, status_code, headers
    
    async def log(self, request, log_type, status_code, extra=None):
        '''
        Log the request to the logger and extract login and password from the request body, if any
        The POST data is logged as hex string in the data field
        The rest is processed and logged in the extra field
        '''
        src_ip, src_port = request.client.host, request.client.port
        dst_ip, dst_port = request.scope.get("server", ("unknown", "unknown"))

        all_extra = {
            "method": request.method,
            "target": str(request.url).split(request.base_url.netloc, 1)[1],
            "headers": dict(request.headers),
            "status_code": status_code,

            # Manually added because transport doesn't exist
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
        }

        all_extra.update(extra or {})

        data = ''
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                
                if body:
                    data = body
                    form_data = body.decode('utf-8', errors='replace')
                    
                    query_direct = self.parse_query_string(form_data)
                    for key, value in query_direct.items():
                        if key in ['login', 'username','account', 'user%5Blogin%5D', 'j_username']:
                            all_extra['username'] = value
                        elif key in ['password', 'credential', 'passwd', 'user%5Bpassword%5D', 'j_password', 'secretkey']:
                            all_extra['password'] = value
                    
                    # Handle XML/SOAP data
                    if '<Envelope' in form_data and '</Envelope>' in form_data:
                        if '<userName>' in form_data and '</userName>' in form_data:
                            username_start = form_data.find('<userName>') + len('<userName>')
                            username_end = form_data.find('</userName>')
                            all_extra['login'] = form_data[username_start:username_end]
                            
                        if '<password>' in form_data and '</password>' in form_data:
                            password_start = form_data.find('<password>') + len('<password>')
                            password_end = form_data.find('</password>')
                            all_extra['password'] = form_data[password_start:password_end]
            
            except ClientDisconnect:
                pass
        
        self.logger.log(f"{self.protocol_name}.{log_type}", request.client, data=data, extra=all_extra)


class HttpHoneypot(BaseHoneypot):
    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.port = config['port']
        self.handler = HttpHandler(config=config, logger=logger)
        self.app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        self.server = None
        
        # Add middleware to remove unwanted headers
        @self.app.middleware("http")
        async def customize_headers(request: Request, call_next):
            response = await call_next(request)
            
            # Store original headers
            original_headers = dict(response.headers.items())
            
            # Clear all headers
            headers_to_delete = list(response.headers.keys())
            for key in headers_to_delete:
                del response.headers[key]
            
            # Add back headers with proper capitalization, excluding unwanted ones
            for key, value in original_headers.items():
                if key.lower() != 'server':
                    response.headers[key] = value

            return response

             
        # Add a middleware to handle custom methods
        @self.app.middleware("http")
        async def custom_method_middleware(request: Request, call_next):
            # Standard HTTP methods that FastAPI handles by default
            standard_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"]
            
            if request.method not in standard_methods:
                # For custom methods, directly call the handler instead of going through FastAPI routing
                return await self.handler.handle_error(request, 405)
            
            # For standard methods, continue with normal FastAPI processing
            return await call_next(request)


    async def start(self):
        self.handler.setup()
        
        @self.app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"])
        async def catch_all(request: Request, path: str):
            return await self.handler.handle_request(request)
        
        return await super().start()
    
    async def _start_server(self):
        config = uvicorn.Config(
            app=self.app,
            host=self.bindaddr,
            port=self.port,
            log_level="error",
            access_log=False,
            server_header=False
        )

        self.server = uvicorn.Server(config)
        try:
            await self.server.serve()
        except asyncio.CancelledError:
            self.server.should_exit = True
            await self.server.shutdown()
            raise

    async def stop(self):
        if self.server:
            # Signal the server to shut down
            self.server.should_exit = True
            # Wait for the server to shut down
            await self.server.shutdown()
        
        return await super().stop()