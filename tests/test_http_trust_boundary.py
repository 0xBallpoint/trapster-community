"""HTTP trust boundary: attacker paths and input.

The request line, headers and body are attacker-controlled. They must never
read a file outside the skin, be evaluated as a template, or break a response.
"""

import asyncio
import os

from trapster.modules.http import HttpHoneypot

from .helpers import HoneypotTestCase, RecordingLogger, raw_http

SECRET = b"trapster-test-secret-6f1c"


class StaticFileTraversalTests(HoneypotTestCase):
    """The static file handler only serves files inside the skin's files/."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        # A static folder we control, with a secret file just outside it and
        # symlinks pointing at that secret.
        files = self.tmp / "files"
        files.mkdir()
        (files / "ok.txt").write_bytes(b"public file")
        (self.tmp / "secret.txt").write_bytes(SECRET)
        os.symlink(self.tmp / "secret.txt", files / "link.txt")
        os.symlink(self.tmp, files / "dirlink")

        self.logger = RecordingLogger()
        honeypot, self.port = await self.start_honeypot(
            HttpHoneypot, {"skin": "default_apache"}, self.logger)
        honeypot.handler.static_folder = files

        self.missing = await raw_http(self.port, "GET /definitely-missing HTTP/1.1")

    async def test_files_inside_the_folder_are_served(self):
        """Files inside the skin's static folder are served normally."""
        status, _, body = await raw_http(self.port, "GET /ok.txt HTTP/1.1")
        self.assertEqual((status, body), (200, b"public file"))

    async def test_traversal_looks_like_an_ordinary_missing_page(self):
        """Path traversal and symlinks never leak files outside the folder, and look like a missing page."""
        attacks = [
            "/../secret.txt",
            "/..%2fsecret.txt",
            "/%2e%2e/secret.txt",
            "/%2e%2e%2fsecret.txt",
            "/%252e%252e%252fsecret.txt",
            "/..%5csecret.txt",
            "/link.txt",
            "/dirlink/secret.txt",
            "/ok.txt%00.png",
            "/%2fetc%2fpasswd",
            "//etc/passwd",
        ]
        for path in attacks:
            with self.subTest(path=path):
                status, _, body = await raw_http(self.port, f"GET {path} HTTP/1.1")
                self.assertNotIn(SECRET, body)
                self.assertNotIn(b"root:x:0:0", body)
                # Same as a miss, unless the HTTP parser itself refuses the
                # request line (400) before it reaches the honeypot.
                if status != 400:
                    self.assertEqual((status, body), (self.missing[0], self.missing[2]))
        self.assertNoLoopErrors()


class TemplateInjectionTests(HoneypotTestCase):
    """Request data reflected by a skin is rendered as text, never as a template."""

    async def start_skin(self, skin):
        _, port = await self.start_honeypot(HttpHoneypot, {"skin": skin}, RecordingLogger())
        return port

    async def test_query_string_is_not_evaluated(self):
        """A template expression in the query string is shown as text, never run."""
        port = await self.start_skin("demo_api")
        # /api/v1/search reflects ?q= into its JSON body.
        _, _, body = await raw_http(port, "GET /api/v1/search?q=%7B%7B7*7%7D%7D HTTP/1.1")
        self.assertIn(b'"query": "{{7*7}}"', body)

        _, _, body = await raw_http(
            port, "GET /api/v1/search?q=%7B%7B''.__class__.__mro__%7D%7D HTTP/1.1")
        self.assertIn(b"__mro__", body)
        self.assertNotIn(b"<class", body)

    async def test_host_header_is_not_evaluated(self):
        """A template expression in the Host header is shown as text, never run."""
        port = await self.start_skin("demo_api")
        # /redirect reflects the Host header into Location.
        _, headers, _ = await raw_http(port, "GET /redirect HTTP/1.1", host="{{7*7}}")
        self.assertEqual(headers["location"], "https://{{7*7}}/api/v1/user?id=1")

    async def test_form_field_is_not_evaluated_and_is_escaped(self):
        """A reflected form field is neither run as a template nor injected as HTML."""
        # A minimal skin whose login page reflects the submitted username into
        # the input's value, like real login pages do.
        skin = self.tmp / "reflect"
        (skin / "files").mkdir(parents=True)
        (skin / "templates").mkdir()
        (skin / "config.yaml").write_text(
            "name: reflect\n"
            "endpoints:\n"
            "  - \"/login\":\n"
            "    - method: POST\n"
            "      status_code: 200\n"
            "      file: login.html\n")
        (skin / "templates" / "login.html").write_text(
            '<input name="username" value="{{ request.form.get(\'username\', \'\') }}">')
        (skin / "templates" / "404.html").write_text("not found")

        def use_test_skin(honeypot):
            honeypot.handler.data_folder = self.tmp

        _, port = await self.start_honeypot(
            HttpHoneypot, {"skin": "reflect"}, RecordingLogger(), prepare=use_test_skin)
        status, _, body = await raw_http(
            port, "POST /login HTTP/1.1",
            headers=["Content-Type: application/x-www-form-urlencoded"],
            body=b"username=%7B%7B7*7%7D%7D%22%3E%3Cscript%3E&password=x")
        self.assertEqual(status, 200)
        self.assertIn(b'value="{{7*7}}&#34;&gt;&lt;script&gt;"', body)
        self.assertNotIn(b'"><script>', body)


class BinaryBodyTests(HoneypotTestCase):
    """A body that is not UTF-8 gets a normal response and one event."""

    async def test_non_utf8_form_body_is_answered_and_logged(self):
        """Binary form data gets the normal response (not a 500) and its raw bytes are logged."""
        logger = RecordingLogger()
        _, port = await self.start_honeypot(HttpHoneypot, {"skin": "demo_api"}, logger)
        login = "POST /api/v1/login HTTP/1.1"
        form = ["Content-Type: application/x-www-form-urlencoded"]

        # Reference: a wrong login in plain ASCII.
        expected_status, _, expected_body = await raw_http(
            port, login, headers=form, body=b"username=a&password=b")
        await asyncio.sleep(0.1)
        logger.events.clear()

        binary = b"username=\xff\xfe&password=\x80\x81"
        status, _, body = await raw_http(port, login, headers=form, body=binary)
        await asyncio.sleep(0.1)

        self.assertEqual((status, body), (expected_status, expected_body))
        self.assertEqual(logger.logtypes(), ["http.login"])
        self.assertEqual(bytes.fromhex(logger.events[0]["data"]), binary)
        self.assertNoLoopErrors()
