# web-recon-scanner

Passive web application security reconnaissance. Audits a target's externally
observable security posture and produces a prioritised list of findings with
the reasoning behind each one.

Every check is passive. The scanner sends ordinary `GET` requests and reports
what the server volunteers — it sends no payloads and attempts no exploitation.

## What it checks

| Area | Checks performed |
| --- | --- |
| **Security headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Information disclosure** | `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` |
| **TLS** | Negotiated protocol and cipher, certificate issuer, expiry, trust validation |
| **Cookies** | `Secure`, `HttpOnly`, and `SameSite` attributes on every `Set-Cookie` |
| **Input surface** | Discovers HTML forms and their inputs; flags POST forms with no visible CSRF token |
| **Transport** | Flags applications still served over plain HTTP |
| **Metadata** | `robots.txt`, `sitemap.xml`, `.well-known/security.txt` |

Findings are graded **high / medium / low** and each one explains *why* it
matters, so the output can go straight into an assessment report.

## Requirements

Python 3.10 or newer. No packages to install.

## Usage

```bash
# Audit a site
python3 web_recon.py https://example.com --authorized

# Save a machine-readable report
python3 web_recon.py example.com -o report.json --authorized
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `-t`, `--timeout` | Request timeout in seconds | `10` |
| `-o`, `--output` | Write the JSON report to this file | none |
| `--authorized` | Required. Confirms you have permission to scan | off |

## Example output

```
  Target      : https://example.com
  Final URL   : https://example.com
  Status      : 200
  Server      : cloudflare
  TLS         : TLSv1.3 / SSL Corporation / expires Oct 27 22:17:21 2026 GMT
  Forms found : 0

  Findings (7):
    [HIGH  ] Missing security header: strict-transport-security
             Forces HTTPS and blocks protocol downgrade attacks.
    [MEDIUM] Missing security header: x-frame-options
             Prevents the page being framed for clickjacking.
    [LOW   ] Information disclosure via server
             Response advertises 'cloudflare', which helps an attacker
             fingerprint the stack and match known exploits.
```

## Use in CI

The scanner exits with status `1` when any **high** severity finding is present,
and `0` otherwise. That makes it usable as a deployment gate:

```yaml
- name: Web security posture check
  run: python3 web_recon.py https://staging.example.com --authorized
```

## Responsible use

Scan only applications you own or have written permission to test. The
`--authorized` flag makes that decision explicit.

## Tests

45 tests, 84% line coverage. No dependencies, and **no test contacts a
real external service** — network-facing code is exercised against local fake
servers bound to an ephemeral port.

```bash
# Run the suite
python3 -m unittest discover -s tests -v

# Fail on any leaked socket, file, or database connection
python3 -W error::ResourceWarning -m unittest discover -s tests
```

CI runs the suite on Python 3.10–3.13 on every push, plus a coverage gate and a
3.10 syntax check. See [.github/workflows/tests.yml](.github/workflows/tests.yml).

## License

MIT — see [LICENSE](LICENSE).
