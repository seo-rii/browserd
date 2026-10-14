"""Sandboxed Chromium capture primitives and exact production scrape JavaScript.

These tests do not qualify gateway/worker routing or artifact persistence. Generic
unittest discovery skips without BROWSERD_TEST_CHROMIUM; direct invocation requires it.
"""
from __future__ import annotations

import base64
import json
import os
import re
import struct
import sys
import unittest

import test_chromium_behavior as behavior


def scrape_expression(**overrides) -> str:
    source = (behavior.REPOSITORY / "crates/browserd-worker/src/chromium_owner/capture.rs").read_text()
    match = re.search(r'let expression = format!\(\s*r#"(.*?)"#,', source, re.S)
    if not match:
        raise ValueError("production scrape literal unavailable")
    options = dict(html=True, text=True, metadata=True, links=True, accessibility=False,
                   max_nodes=3000, max_output_bytes=1024 * 1024, delivery="artifact")
    options.update(overrides)
    return match[1].replace("const o={};", "const o=" + json.dumps(options) + ";").replace("{{", "{").replace("}}", "}")


class ChromiumCaptureBehavior(unittest.TestCase):
    # Share the sandbox-enabled browser setup without inheriting unrelated tests.
    setUpClass = classmethod(behavior.ChromiumHelperBehavior.setUpClass.__func__)
    setUp = behavior.ChromiumHelperBehavior.setUp

    def cdp(self):
        session = self.context.new_cdp_session(self.page)
        self.addCleanup(session.detach)
        return session

    def test_png_jpeg_and_clip_dimensions(self):
        self.page.set_content('<body style="margin:0;background:#123456"><h1>한글 capture</h1></body>')
        cdp = self.cdp()
        metrics = cdp.send("Page.getLayoutMetrics")
        self.assertEqual(metrics["cssLayoutViewport"]["clientWidth"], 800)
        for fmt in ("png", "jpeg"):
            args = dict(format=fmt, fromSurface=True, captureBeyondViewport=True,
                        clip=dict(x=0, y=0, width=320, height=200, scale=1))
            if fmt == "jpeg":
                args["quality"] = 80
            data = base64.b64decode(cdp.send("Page.captureScreenshot", args)["data"], validate=True)
            if fmt == "png":
                self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(struct.unpack(">II", data[16:24]), (320, 200))
            else:
                self.assertEqual(data[:2], b"\xff\xd8")
                self.assertEqual(data[-2:], b"\xff\xd9")

    def test_pdf_stream_is_bounded_and_closed(self):
        self.page.set_content('<h1>PDF capture</h1>' + '<p>bounded stream</p>' * 1200)
        cdp = self.cdp()
        printed = cdp.send("Page.printToPDF", dict(transferMode="ReturnAsStream", printBackground=True))
        self.assertEqual(printed.get("data", ""), "")
        stream = printed["stream"]
        prefix = b""
        total = 0
        reads = 0
        try:
            while True:
                response = cdp.send("IO.read", dict(handle=stream, size=64 * 1024))
                data = response["data"]
                chunk = base64.b64decode(data, validate=True) if response.get("base64Encoded") else data.encode()
                self.assertLessEqual(len(chunk), 64 * 1024)
                prefix = (prefix + chunk)[:8]
                total += len(chunk)
                reads += 1
                self.assertLess(total, 8 * 1024 * 1024)
                if response["eof"]:
                    break
                self.assertTrue(chunk)
        finally:
            cdp.send("IO.close", dict(handle=stream))
        self.assertTrue(prefix.startswith(b"%PDF-"))
        self.assertGreater(total, 64 * 1024)
        self.assertGreater(reads, 1)
        with self.assertRaises(Exception):
            cdp.send("IO.read", dict(handle=stream, size=1))

    def test_production_scrape_values_and_no_resource_fetch(self):
        self.page.set_content('<html lang="ko"><head><title>capture fixture</title></head><body>'
                              '<h1>한글 본문</h1><a href="https://example.invalid/destination">link</a>'
                              '<script>window.scriptRuns=(window.scriptRuns||0)+1</script></body></html>')
        requests = []
        self.context.on("request", lambda request: requests.append(request.url))
        cdp = self.cdp()
        expression = scrape_expression()
        preflight = expression.replace("const out=", "return true; const out=", 1)
        checked = cdp.send("Runtime.evaluate", dict(expression=preflight, returnByValue=True))
        self.assertEqual(checked["result"]["value"], True)
        result = cdp.send("Runtime.evaluate", dict(expression=expression, returnByValue=True))
        self.assertNotIn("exceptionDetails", result)
        data = json.loads(result["result"]["value"])
        self.assertIn("한글 본문", data["text"])
        self.assertIn("<h1>", data["html"])
        self.assertEqual(data["metadata"]["title"], "capture fixture")
        self.assertEqual(data["links"][0]["url"], "https://example.invalid/destination")
        self.assertEqual(data["scripts"], "unchanged")
        self.assertEqual(data["resources"], "not_fetched")
        self.assertEqual(self.page.evaluate("scriptRuns"), 1)
        self.assertEqual(requests, [])

    def test_production_scrape_bounds_fail_before_serialized_result(self):
        self.page.set_content('<div>' + '<span>x</span>' * 20 + '</div>')
        cdp = self.cdp()
        response = cdp.send("Runtime.evaluate", dict(expression=scrape_expression(max_nodes=5), returnByValue=True))
        self.assertIn("exceptionDetails", response)
        self.assertNotIn("value", response["result"])


if __name__ == "__main__":
    if not os.environ.get("BROWSERD_TEST_CHROMIUM"):
        print("BROWSERD_TEST_CHROMIUM is required for the live capture gate", file=sys.stderr)
        raise SystemExit(2)
    unittest.main(verbosity=2)
