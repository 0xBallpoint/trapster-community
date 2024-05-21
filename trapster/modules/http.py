# -*- coding: utf-8 -*-

from .base import BaseProtocol, BaseHoneypot
import logging

# Based on https://github.com/thomwiggers/httpserver
# __author__ = 'Thom Wiggers, Luuk Scholten'
# __email__ = 'thom@thomwiggers.nl, info@luukscholten.com'
# __version__ = '1.1.0'

import asyncio
import hashlib
import logging
import mimetypes
import os
import re
from datetime import datetime
from http.client import responses
from urllib.parse import unquote


class InvalidRequestError(Exception):
    """Raised for invalid requests. Contains the error code.

    This exception can be transformed to a http response.
    """

    def __init__(self, code, *args, **kwargs):
        """Configures a new InvalidRequestError

        Arguments:
            code -- the HTTP error code
        """
        super(InvalidRequestError, self).__init__(*args, **kwargs)
        self.code = code


    def get_http_response(self):
        """Get this exception as an HTTP response suitable for output"""
        return HttpProtocol()._get_response(
            code=self.code,
            body=str(self),
            headers={
                'Content-Type': 'text/plain'
            }
        )

class HttpProtocol(BaseProtocol):
    """HTTP/1.1 Protocol implementation

    Per connection made, one of these gets instantiated
    """
    config = {
        "basic_auth": False,
        "skin": "defaultApache"
    }

    def __init__(self, config=None, event_loop=None, timeout=10):
        if config:
            self.config = config

        self.protocol_name = "http"
        self.headers = {}

        self._loop = event_loop or asyncio.get_event_loop()
        self._timeout = timeout
        self._timeout_handle = None

    def connection_made(self, transport):

        """Called when the connection is made"""
        self.transport = transport
        # too verbose self.logger.log(self.logger.LOG_HTTP_CONNECTION_MADE, self.transport)

        self.transport = transport
        self.keepalive = True

        if self._timeout:
            self._timout_handle = self._loop.call_later(
                self._timeout, self._handle_timeout)

    def data_received(self, data):
        """Process received data from the socket

        Called when we receive data
        """
        try:
            request = self._parse_headers(data)
            self._handle_request(request)
        except InvalidRequestError as e:
            self._write_response(e.get_http_response())

        if not self.keepalive:
            if self._timeout_handle:
                self._timeout_handle.cancel()
            self.transport.close()

        if self._timeout and self._timeout_handle:
            self._timeout_handle.cancel()
            self._timout_handle = self._loop.call_later(
                self._timeout, self._handle_timeout)

    def _get_response(self, **kwargs):
        """Get a template response

        Use kwargs to add things to the dictionary
        """
        if 'code' not in kwargs:
            kwargs['code'] = 200
        if 'headers' not in kwargs:
            kwargs['headers'] = dict()
        if 'version' not in kwargs:
            kwargs['version'] = 'HTTP/1.1'

        return dict(**kwargs)

    def _write_transport(self, string):
        """Convenience function to write to the transport"""
        if isinstance(string, str):  # we need to convert to bytes
            self.transport.write(string.encode('utf-8'))
        else:
            self.transport.write(string)

    def _write_response(self, response):
        """Write the response back to the client

        Arguments:
        response -- the dictionary containing the response.
        """
        # add custom headers
        if self.config['skin'] == "nasLogin":
            response['headers'].update({
                'Vary': 'Accept-Encoding',
                'Cache-control': 'no-store',
                'X-Content-Type-Options': 'nosniff',
                'X-XSS-Protection': '1; mode=block',
                'X-Frame-Options': 'SAMEORIGIN',
                'P3P': 'CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"',
                'Content-Security-Policy': "base-uri 'self';  connect-src ws: wss: *; default-src 'self' 'unsafe-eval' data: blob: https://*.synology.com https://www.synology.cn/; font-src 'self' data: https://*.googleapis.com https://*.gstatic.com; form-action 'self'; frame-ancestors 'self' https://gofile.me http://gofile.me; frame-src 'self' data: blob: https://*.synology.com https://www.synology.cn/; img-src 'self' data: blob: https://*.google.com https://*.googleapis.com http://*.googlecode.com https://*.gstatic.com; media-src 'self' data: about:;  script-src 'self' 'unsafe-eval' data: blob: https://*.synology.com https://www.synology.cn/ https://*.google.com https://*.googleapis.com; style-src 'self' 'unsafe-inline' https://*.googleapis.com;",
                'Set-Cookie': 'id=;expires=Thu, 01-Jan-1970 00:00:01 GMT;path=/'
            })
        elif self.config['skin'] == "defaultIIS":
            response['headers'].update({
                'Server' : 'Microsoft-IIS/8.5',
                'X-Powered-By': 'ASP.NET',
                'X-AspNet-Version': '4.0.30319',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains;',
                'X-XSS-Protection': '1; mode=block',
            })
                

        # write response
        status = '{} {} {}\r\n'.format(response['version'],
                                       response['code'],
                                       responses[response['code']])
        self._write_transport(status)

        if 'body' in response and 'Content-Length' not in response['headers']:
            response['headers']['Content-Length'] = len(response['body'])

        response['headers']['Date'] = datetime.utcnow().strftime(
            "%a, %d %b %Y %H:%M:%S +0000")

        for (header, content) in response['headers'].items():
            self._write_transport('{}: {}\r\n'.format(header, content))

        self._write_transport('\r\n')
        if 'body' in response:
            self._write_transport(response['body'])


    def _parse_headers(self, data):
        request = dict()

        try:
            request_strings = list(map(lambda x: x.decode(),
                                   data.split(b'\r\n')))
        except UnicodeDecodeError:
            return request

        # Parse request method and HTTP version
        method_line = request_strings[0].split()

        # The first line has either 3 or 2 arguments
        if not (2 <= len(method_line) <= 3):
            # Got an invalid http header
            self.keepalive = False  # We don't trust you
            raise InvalidRequestError(400, 'Bad request')
        # HTTP 0.9 isn't supported.
        if len(method_line) == 2:
            # Got a HTTP/0.9 request
            self.keepalive = False  # HTTP/0.9 won't support persistence
            raise InvalidRequestError(505, "This server only supports HTTP/1.0"
                                           "and HTTP/1.1")
        else:
            request['version'] = method_line[2]

        # method
        request['method'] = method_line[0]
        # request URI
        request['target'] = method_line[1]

        # Parse the headers
        request["headers"] = {}
        for line in request_strings[1:]:
            if line == '':  # an empty line signals the end of the headers
                break
            header, value = line.split(': ', 1)
            request["headers"][header] = value
        
        # Retrieve POST data
        try:
            post_data = data.split(b'\r\n\r\n')[1]
        except:
            post_data = b'error'

        extra = {"method":request.get('method'), "basic": False, "version" : request.get('version'), "target":request.get('target'), "headers": request.get('headers')}
        if post_data != b'':
            extra["data"] = post_data

        # If Authorization Header : basic auth is True
        if request["headers"].get("Authorization"):
            extra['basic'] = True

        # Log request
        self.logger.log(self.protocol_name + "." + self.logger.EXTRA, self.transport, extra=extra)

        return request

    def _get_request_uri(self, request):
        """Parse the request URI into something useful

        Server MUST accept full URIs (5.1.2)"""
        request_uri = request.get('target')
        if request_uri.startswith('/'):  # eg. GET /index.html
            return (request.get('Host', 'localhost').split(':')[0],
                    request_uri[1:])
        elif '://' in request_uri:  # eg. GET http://rded.nl
            locator = request_uri.split('://', 1)[1]
            try:
                host, path = locator.split('/', 1)
            except ValueError:
                host = locator
                path = '/'
            return (host.split(':')[0], path)

    def _handle_request(self, request):
        """Process the headers and get the file"""

        # Check if this is a persistent connection.
        if request.get('version') == 'HTTP/1.1':
            self.keepalive = not request.get('Connection') == 'close'
        elif request.get('version') == 'HTTP/1.0':
            self.keepalive = request.get('Connection') == 'Keep-Alive'

        # Check if we're getting a sane request
        if request.get('method') not in ('GET', 'POST', 'HEAD'):
            raise InvalidRequestError(501, 'Method not implemented')
        if request.get('version') not in ('HTTP/1.0', 'HTTP/1.1'):
            raise InvalidRequestError(
                505, 'Version not supported. Supported versions are: {}, {}'
                .format('HTTP/1.0', 'HTTP/1.1'))

        host, location = self._get_request_uri(request)

        # We must ignore the Host header if a host is specified in GET
        if host is None:
            host = request.get('Host')

        # Send 401 Unauthorized if basic_auth configuration
        if self.config['basic_auth'] == True:
            response = self._get_response(version=request['version'], code=401)
            response["headers"] = {
                'WWW-Authenticate': 'Basic realm="Unauthorized"',
                "Content-Type": "text/html; charset=utf-8"
                }
            response["body"] = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Authorization Required</title>
</head><body>
<center><h1>401 Authorization Required</h1></center>
<hr><center>Apache 2.4.6</center>
</body></html>
"""
            return self._write_response(response)

        # Check requested filename
        script_dir = os.path.dirname(os.path.abspath(__file__))

        folder = script_dir + "/resources/httpskins/" + self.config['skin']
        
        filename = os.path.join(folder, unquote(location))

        if os.path.isdir(filename):
            filename = os.path.join(filename, 'index.html')

        if not os.path.isfile(filename):
            response = self._get_response(version=request['version'], code=404)
            response["headers"] = {
                "Content-Type": "text/html; charset=utf-8"
                }
            response["body"] = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.6</address>
</body></html>
"""
            return self._write_response(response)

        # Start response with version
        response = self._get_response(version=request['version'])

        # timeout negotiation
        match = re.match(r'timeout=(\d+)', request.get('Keep-Alive', ''))
        if match is not None:
            requested_timeout = int(match.group(1))
            if requested_timeout < self._timeout:
                self._timeout = requested_timeout

        # tell the client our timeout
        if self.keepalive:
            response['headers'][
                'Keep-Alive'] = 'timeout={}'.format(self._timeout)

        # Set Content-Type
        response['headers']['Content-Type'] = mimetypes.guess_type(
            filename)[0] or 'text/html'

        # Generate E-tag
        sha1 = hashlib.sha1()
        with open(filename, 'rb') as fp:
            response['body'] = fp.read()
            sha1.update(response['body'])
        etag = sha1.hexdigest()

        # Create 304 response if if-none-match matches etag
        if request.get('If-None-Match') == '"{}"'.format(etag):
            # 304 responses shouldn't contain many headers we might already
            # have added.
            response = self._get_response(code=304)

        response['headers']['Etag'] = '"{}"'.format(etag)

        self._write_response(response)

    def _handle_timeout(self):
        """Handle a timeout"""
        self.transport.close()



class HttpHoneypot(BaseHoneypot):
    """common class to all trapster instance"""

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = lambda: HttpProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
