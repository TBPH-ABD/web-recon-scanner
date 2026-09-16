"""Tests for web-recon-scanner header, cookie, form, and finding logic."""
from __future__ import annotations

import unittest

import web_recon
from tests.support.fakes import capture_cli, http_fake
from web_recon import FormParser, ScanReport, analyse, parse_cookies, scan

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}


def report_for(headers: dict, body: str = "", is_https: bool = True) -> ScanReport:
    report = ScanReport(target="https://t", scanned_at="now")
    analyse(report, {k.lower(): v for k, v in headers.items()},
            body.encode(), is_https)
    return report


def titles(report: ScanReport) -> str:
    return " | ".join(f.title for f in report.findings)


class TestSecurityHeaders(unittest.TestCase):
    def test_all_headers_present_yields_no_header_findings(self):
        report = report_for(SECURE_HEADERS)
        self.assertEqual(report.headers_missing, [])
        self.assertNotIn("Missing security header", titles(report))

    def test_missing_hsts_is_high_severity(self):
        report = report_for({})
        finding = next(f for f in report.findings
                       if "strict-transport-security" in f.title)
        self.assertEqual(finding.severity, "high")

    def test_missing_csp_is_high_severity(self):
        report = report_for({})
        finding = next(f for f in report.findings
                       if "content-security-policy" in f.title)
        self.assertEqual(finding.severity, "high")

    def test_missing_referrer_policy_is_low_severity(self):
        report = report_for({})
        finding = next(f for f in report.findings
                       if "referrer-policy" in f.title)
        self.assertEqual(finding.severity, "low")

    def test_present_headers_are_listed(self):
        report = report_for({"Content-Security-Policy": "default-src 'self'"})
        self.assertIn("content-security-policy", report.headers_present)


class TestInformationDisclosure(unittest.TestCase):
    def test_server_header_is_flagged(self):
        report = report_for({"Server": "nginx/1.25.3"})
        self.assertIn("Information disclosure via server", titles(report))

    def test_powered_by_header_is_flagged(self):
        report = report_for({"X-Powered-By": "PHP/8.2.1"})
        self.assertIn("x-powered-by", titles(report))

    def test_absent_leaky_headers_produce_nothing(self):
        report = report_for(SECURE_HEADERS)
        self.assertNotIn("Information disclosure", titles(report))


class TestCookies(unittest.TestCase):
    def test_all_attributes_are_parsed(self):
        cookies = parse_cookies(
            {"set-cookie": "sid=abc; Secure; HttpOnly; SameSite=Strict"})
        self.assertEqual(len(cookies), 1)
        self.assertTrue(cookies[0]["secure"])
        self.assertTrue(cookies[0]["httponly"])
        self.assertEqual(cookies[0]["samesite"], "strict")

    def test_missing_attributes_are_reported_as_absent(self):
        cookies = parse_cookies({"set-cookie": "sid=abc"})
        self.assertFalse(cookies[0]["secure"])
        self.assertFalse(cookies[0]["httponly"])
        self.assertEqual(cookies[0]["samesite"], "not set")

    def test_no_set_cookie_header_yields_nothing(self):
        self.assertEqual(parse_cookies({}), [])

    def test_weak_cookie_produces_a_medium_finding(self):
        report = report_for({"Set-Cookie": "sid=abc"})
        finding = next(f for f in report.findings
                       if "Weak cookie attributes" in f.title)
        self.assertEqual(finding.severity, "medium")
        self.assertIn("HttpOnly", finding.detail)

    def test_hardened_cookie_is_not_flagged(self):
        report = report_for(
            {"Set-Cookie": "sid=abc; Secure; HttpOnly; SameSite=Strict"})
        self.assertNotIn("Weak cookie attributes", titles(report))

    def test_secure_is_not_required_over_plain_http(self):
        report = report_for({"Set-Cookie": "sid=abc; HttpOnly; SameSite=Lax"},
                            is_https=False)
        self.assertNotIn("Weak cookie attributes", titles(report))


class TestFormParsing(unittest.TestCase):
    def parse(self, html: str) -> list[dict]:
        parser = FormParser()
        parser.feed(html)
        return parser.forms

    def test_form_action_and_method_are_captured(self):
        forms = self.parse('<form action="/login" method="POST"></form>')
        self.assertEqual(forms[0]["action"], "/login")
        self.assertEqual(forms[0]["method"], "post")

    def test_inputs_are_collected(self):
        forms = self.parse(
            '<form><input name="u" type="text">'
            '<textarea name="b"></textarea></form>')
        self.assertEqual({i["name"] for i in forms[0]["inputs"]}, {"u", "b"})

    def test_method_defaults_to_get(self):
        self.assertEqual(self.parse("<form></form>")[0]["method"], "get")

    def test_multiple_forms_are_found(self):
        self.assertEqual(len(self.parse("<form></form><form></form>")), 2)

    def test_page_without_forms_yields_none(self):
        self.assertEqual(self.parse("<p>hello</p>"), [])


class TestCsrfHeuristic(unittest.TestCase):
    def test_post_form_without_a_token_is_flagged(self):
        report = report_for(
            SECURE_HEADERS,
            '<form method="post" action="/x"><input name="u"></form>')
        self.assertIn("CSRF", titles(report))

    def test_post_form_with_a_csrf_field_is_not_flagged(self):
        report = report_for(
            SECURE_HEADERS,
            '<form method="post"><input name="csrf_token" value="t"></form>')
        self.assertNotIn("CSRF", titles(report))

    def test_get_form_is_not_flagged(self):
        report = report_for(SECURE_HEADERS,
                            '<form method="get"><input name="q"></form>')
        self.assertNotIn("CSRF", titles(report))

    def test_malformed_html_does_not_abort_the_scan(self):
        report = report_for(SECURE_HEADERS, "<form><div><p>unclosed")
        self.assertIsInstance(report.forms, list)


class TestTransport(unittest.TestCase):
    def test_plain_http_is_high_severity(self):
        report = report_for(SECURE_HEADERS, is_https=False)
        finding = next(f for f in report.findings if "plain HTTP" in f.title)
        self.assertEqual(finding.severity, "high")

    def test_https_is_not_flagged(self):
        report = report_for(SECURE_HEADERS, is_https=True)
        self.assertNotIn("plain HTTP", titles(report))


class TestLiveScan(unittest.TestCase):
    """Exercises fetch/scan end to end against a local fake server."""

    def test_scan_reads_status_and_server_header(self):
        routes = {"/": (200, {"Server": "nginx/1.25"}, "<html></html>")}
        with http_fake(routes) as (base, _):
            report = scan(base, timeout=5.0)
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.server, "nginx/1.25")

    def test_scan_discovers_metadata_files(self):
        routes = {"/": (200, {}, "<html></html>"),
                  "/robots.txt": (200, {}, "User-agent: *")}
        with http_fake(routes) as (base, _):
            report = scan(base, timeout=5.0)
        self.assertIn("/robots.txt", report.metadata_files)
        self.assertNotIn("/sitemap.xml", report.metadata_files)

    def test_scan_finds_forms_in_the_returned_page(self):
        routes = {"/": (200, {}, '<form method="post"><input name="u"></form>')}
        with http_fake(routes) as (base, _):
            report = scan(base, timeout=5.0)
        self.assertEqual(len(report.forms), 1)

    def test_error_status_is_still_analysed(self):
        with http_fake({}, default=(500, {}, "error")) as (base, _):
            report = scan(base, timeout=5.0)
        self.assertEqual(report.status_code, 500)

    def test_http_target_produces_a_transport_finding(self):
        with http_fake({"/": (200, {}, "ok")}) as (base, _):
            report = scan(base, timeout=5.0)
        self.assertIn("plain HTTP", " | ".join(f.title for f in report.findings))


class TestCli(unittest.TestCase):
    def test_refuses_without_authorization(self):
        code, out = capture_cli(web_recon.main, ["https://example.com"])
        self.assertEqual(code, 2)
        self.assertIn("--authorized", out)

    def test_exits_nonzero_on_high_severity(self):
        with http_fake({"/": (200, {}, "ok")}) as (base, _):
            code, _ = capture_cli(web_recon.main, [base, "--authorized"])
        # Plain HTTP alone is a high-severity finding.
        self.assertEqual(code, 1)

    def test_unreachable_target_reports_cleanly(self):
        code, out = capture_cli(
            web_recon.main, ["http://127.0.0.1:1", "--authorized", "-t", "1"])
        self.assertEqual(code, 1)
        self.assertIn("Could not reach", out)


if __name__ == "__main__":
    unittest.main()
