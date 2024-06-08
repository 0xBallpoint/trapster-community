import unittest
import asyncio
from unittest.mock import Mock, patch
import sys
sys.path.append('../trapster/modules')
from trapster.modules.http import HttpProtocol, InvalidRequestError


class TestHTTPProtocol(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.transport = Mock()
        self.protocol = HttpProtocol(event_loop=self.loop)

#### Rajouter test invalidRequestError

    def test_connection_made(self):
        self.protocol.connection_made(self.transport)
        self.assertEqual(self.protocol.transport, self.transport)
        self.assertTrue(self.protocol.keepalive)


    def test_data_received(self):
        self.protocol.connection_made(self.transport)    
        with patch.object(self.protocol, '_parse_headers', return_value={'method': 'GET', 'version': 'HTTP/1.1', 'target': '/'}):
            with patch.object(self.protocol, '_handle_request') as mock_handle_request:
                self.protocol.data_received(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
                mock_handle_request.assert_called_once()

    def test_get_http_response(self):
        error = InvalidRequestError(404, 'Not Found')
        response = error.get_http_response()
        self.assertEqual(response['code'], 404)
        self.assertEqual(response['body'], 'Not Found')
        self.assertEqual(response['headers']['Content-Type'], 'text/plain')


    def test_get_response(self):
        response = self.protocol._get_response()
        expected_response = {
            'code': 200,
            'headers': {},
            'version': 'HTTP/1.1'
        }
        self.assertEqual(response, expected_response)



if __name__ == '__main__':
    unittest.main()
