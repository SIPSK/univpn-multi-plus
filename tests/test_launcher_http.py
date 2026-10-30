from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import launcher


class LauncherHTTPTests(unittest.TestCase):
    def test_constructs_and_serves_loopback_without_any_ssl_context(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'ok')

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with patch('ssl.create_default_context', side_effect=FileNotFoundError('synthetic unavailable SSL')), patch('urllib.request.HTTPSHandler', side_effect=AssertionError('HTTPS must not initialize')):
                opener = launcher.loopback_opener()
                with opener.open(f'http://127.0.0.1:{server.server_port}/', timeout=2) as response:
                    self.assertEqual(response.read(), b'ok')
                with self.assertRaises(URLError):
                    opener.open('https://127.0.0.1:1/', timeout=1)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)

    def test_redirect_is_rejected_before_following(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header('Location', 'https://127.0.0.1:1/')
                self.send_header('Content-Length', '0')
                self.end_headers()

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with self.assertRaises(HTTPError) as error:
                launcher.loopback_opener().open(f'http://127.0.0.1:{server.server_port}/', timeout=2)
            self.assertEqual(error.exception.code, 302)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)


if __name__ == '__main__':
    unittest.main()
