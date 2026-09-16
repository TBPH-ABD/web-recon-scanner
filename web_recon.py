#!/usr/bin/env python3
"""web-recon-scanner — passive web application security reconnaissance.

Audits a web application's externally observable security posture: HTTP
security headers, cookie attributes, TLS certificate health, server
fingerprint, exposed metadata files, and HTML form surface.

Every check is passive: the scanner sends ordinary GET requests and reads
what the server volunteers. It sends no payloads and attempts no exploitation.

Standard library only. For AUTHORIZED testing and educational use.
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html.parser import HTMLParser

USER_AGENT = "web-recon-scanner/1.0 (authorized security assessment)"

# header -> (severity, why it matters)
SECURITY_HEADERS = {
    "strict-transport-security": ("high", "Forces HTTPS and blocks protocol downgrade attacks."),
    "content-security-policy": ("high", "Primary defence against cross-site scripting (XSS)."),
    "x-frame-options": ("medium", "Prevents the page being framed for clickjacking."),
    "x-content-type-options": ("medium", "Stops browsers MIME-sniffing a response."),
    "referrer-policy": ("low", "Limits how much URL data leaks to third parties."),
    "permissions-policy": ("low", "Restricts access to camera, microphone, geolocation."),
}

# Headers that reveal more than they should.
LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

METADATA_PATHS = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]


@dataclass
class Finding:
    severity: str
    title: str
    detail: str


@dataclass
class ScanReport:
    target: str
    scanned_at: str
    status_code: int | None = None
    final_url: str = ""
    server: str = ""
    tls: dict = field(default_factory=dict)
    headers_present: list[str] = field(default_factory=list)
    headers_missing: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    metadata_files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class FormParser(HTMLParser):
    """Collects <form> elements and their inputs to map the input surface."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "form":
            self._current = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "get").lower(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._current is not None:
            self._current["inputs"].append({
                "name": attributes.get("name", ""),
                "type": attributes.get("type", tag),
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def fetch(url: str, timeout: float) -> tuple[int, dict, bytes, str]:
    """GET a URL. Returns (status, headers, body, final_url)."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            return response.status, headers, response.read(200_000), response.url
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, headers, exc.read(50_000), url


def inspect_tls(hostname: str, port: int, timeout: float) -> dict:
    """Read the certificate and negotiated protocol without validating trust."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                not_after = cert.get("notAfter", "")
                issuer = dict(x[0] for x in cert.get("issuer", ())).get(
                    "organizationName", "unknown")
                return {
                    "protocol": tls_sock.version(),
                    "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else "",
                    "issuer": issuer,
                    "expires": not_after,
                    "valid": True,
                }
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": f"certificate verification failed: {exc.verify_message}"}
    except (OSError, ssl.SSLError) as exc:
        return {"valid": False, "error": str(exc)}


def parse_cookies(headers: dict) -> list[dict]:
    """Extract cookie attributes from Set-Cookie headers."""
    raw = headers.get("set-cookie", "")
    if not raw:
        return []
    cookies = []
    for part in raw.split(","):
        if "=" not in part:
            continue
        attrs = [a.strip().lower() for a in part.split(";")]
        name = attrs[0].split("=", 1)[0]
        if not name:
            continue
        cookies.append({
            "name": name,
            "secure": "secure" in attrs,
            "httponly": "httponly" in attrs,
            "samesite": next((a.split("=", 1)[1] for a in attrs
                              if a.startswith("samesite=")), "not set"),
        })
    return cookies


def analyse(report: ScanReport, headers: dict, body: bytes, is_https: bool) -> None:
    """Turn the raw observations into prioritised findings."""
    for header, (severity, why) in SECURITY_HEADERS.items():
        if header in headers:
            report.headers_present.append(header)
        else:
            report.headers_missing.append(header)
            report.findings.append(Finding(
                severity, f"Missing security header: {header}", why))

    for header in LEAKY_HEADERS:
        if header in headers:
            report.findings.append(Finding(
                "low", f"Information disclosure via {header}",
                f"Response advertises '{headers[header]}', which helps an "
                f"attacker fingerprint the stack and match known exploits."))

    report.cookies = parse_cookies(headers)
    for cookie in report.cookies:
        problems = []
        if not cookie["secure"] and is_https:
            problems.append("missing Secure")
        if not cookie["httponly"]:
            problems.append("missing HttpOnly")
        if cookie["samesite"] == "not set":
            problems.append("missing SameSite")
        if problems:
            report.findings.append(Finding(
                "medium", f"Weak cookie attributes: {cookie['name']}",
                ", ".join(problems) + " — increases session theft and CSRF risk."))

    parser = FormParser()
    try:
        parser.feed(body.decode("utf-8", "replace"))
    except Exception:  # malformed markup should not abort the scan
        pass
    report.forms = parser.forms
    for form in parser.forms:
        has_token = any("csrf" in (i["name"] or "").lower() or
                        "token" in (i["name"] or "").lower() for i in form["inputs"])
        if form["method"] == "post" and not has_token:
            report.findings.append(Finding(
                "medium", f"POST form without an obvious CSRF token",
                f"Form action '{form['action'] or '/'}' has no field that looks "
                f"like an anti-CSRF token. Verify protection server-side."))

    if not is_https:
        report.findings.append(Finding(
            "high", "Site served over plain HTTP",
            "Traffic including credentials and session cookies is transmitted "
            "in cleartext and can be read or modified in transit."))


def check_metadata(base: str, timeout: float) -> list[str]:
    found = []
    for path in METADATA_PATHS:
        try:
            status, _, _, _ = fetch(urllib.parse.urljoin(base, path), timeout)
            if status == 200:
                found.append(path)
        except Exception:
            continue
    return found


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def print_report(report: ScanReport) -> None:
    print(f"\n  Target      : {report.target}")
    print(f"  Final URL   : {report.final_url}")
    print(f"  Status      : {report.status_code}")
    if report.server:
        print(f"  Server      : {report.server}")
    if report.tls:
        if report.tls.get("valid"):
            print(f"  TLS         : {report.tls['protocol']} / "
                  f"{report.tls['issuer']} / expires {report.tls['expires']}")
        else:
            print(f"  TLS         : ISSUE - {report.tls.get('error')}")
    if report.metadata_files:
        print(f"  Metadata    : {', '.join(report.metadata_files)}")
    print(f"  Forms found : {len(report.forms)}")

    print(f"\n  Findings ({len(report.findings)}):")
    if not report.findings:
        print("    None — the observable posture looks clean.")
    for finding in sorted(report.findings, key=lambda f: SEVERITY_ORDER[f.severity]):
        print(f"    [{finding.severity.upper():<6}] {finding.title}")
        print(f"             {finding.detail}")
    print()


def scan(url: str, timeout: float) -> ScanReport:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    is_https = parsed.scheme == "https"

    report = ScanReport(target=url,
                        scanned_at=datetime.now(timezone.utc).isoformat())

    status, headers, body, final_url = fetch(url, timeout)
    report.status_code = status
    report.final_url = final_url
    report.server = headers.get("server", "")

    if is_https:
        report.tls = inspect_tls(parsed.hostname, parsed.port or 443, timeout)

    analyse(report, headers, body, is_https)
    report.metadata_files = check_metadata(url, timeout)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Passive web application security reconnaissance.")
    parser.add_argument("url", help="target URL (https:// assumed if omitted)")
    parser.add_argument("-t", "--timeout", type=float, default=10.0,
                        help="request timeout in seconds (default 10)")
    parser.add_argument("-o", "--output", help="write the JSON report to this file")
    parser.add_argument("--authorized", action="store_true",
                        help="confirm you are authorized to scan the target")
    args = parser.parse_args(argv)

    if not args.authorized:
        print("Refusing to scan: pass --authorized to confirm you have "
              "explicit permission to test this application.", file=sys.stderr)
        return 2

    try:
        report = scan(args.url, args.timeout)
    except (urllib.error.URLError, OSError) as exc:
        print(f"Could not reach target: {exc}", file=sys.stderr)
        return 1

    print_report(report)
    if args.output:
        payload = asdict(report)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"Report written to {args.output}")

    # Non-zero exit when high severity issues exist — useful in CI pipelines.
    return 1 if any(f.severity == "high" for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
