"""Safe, read-only public website inspection helpers for CyberRakshak.

These best-effort checks do not guarantee that a website is safe or malicious.
They never submit forms or execute website JavaScript. Network checks can fail
for invalid domains, blocked sites, DNS outages, or unavailable services.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests

TIMEOUT = 7
MAX_HTML_BYTES = 500_000
MAX_REDIRECTS = 5
USER_AGENT = "CyberRakshak-Educational-Inspector/1.0"
REDIRECT_CODES = {301, 302, 303, 307, 308}
SECURITY_HEADERS = (
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
    "Permissions-Policy",
)


def _parse_url(value: str):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Please enter a URL or domain name.")
    value = value.strip()
    parsed = urlparse(value if "://" in value else "https://" + value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL/domain.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing username/password components are not inspected.")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"Invalid hostname or port: {exc}") from exc
    if not host or port < 1 or port > 65535:
        raise ValueError("Invalid hostname or port.")
    normalized = parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc).geturl()
    if "://" not in value:
        normalized = "https://" + value
    return parsed, host, port, normalized


def _hostname(value: str) -> str:
    return _parse_url(value)[1]


def _public_addresses(host: str) -> list[str]:
    """Resolve host and reject any non-public IP to reduce SSRF risk."""
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(
                f"DNS resolution failed for '{host}': {exc}. Check the spelling, domain existence, and network/DNS connection."
            ) from exc
        addresses = sorted({item[4][0].split("%", 1)[0] for item in infos})
    if not addresses:
        raise ValueError(f"The hostname '{host}' did not resolve to an IP address.")
    parsed = [ipaddress.ip_address(item) for item in addresses]
    if any(not ip.is_global for ip in parsed):
        raise ValueError("Inspection blocked: hostname resolves to a non-public/reserved IP address.")
    return addresses


def _error(status: str, exc: Exception, **extra) -> dict:
    return {"status": status, "error": f"{type(exc).__name__}: {exc}", **extra}


def inspect_ssl(url: str) -> dict:
    try:
        parsed, host, port, normalized = _parse_url(url)
        if parsed.scheme.lower() != "https":
            return {"status": "SKIPPED", "hostname": host,
                    "note": "SSL/TLS certificate inspection requires an HTTPS URL."}
        addresses = _public_addresses(host)
        context = ssl.create_default_context()
        errors = []
        for address in addresses:
            try:
                raw = socket.create_connection((address, port), timeout=TIMEOUT)
                with raw:
                    with context.wrap_socket(raw, server_hostname=host) as secure:
                        cert = secure.getpeercert()
                        return {
                            "status": "PASS", "hostname": host, "port": port,
                            "certificate_verified": True, "tls_version": secure.version(),
                            "issuer": ", ".join("=".join(pair) for group in cert.get("issuer", ()) for pair in group),
                            "subject": ", ".join("=".join(pair) for group in cert.get("subject", ()) for pair in group),
                            "not_before": cert.get("notBefore", "Unavailable"),
                            "not_after": cert.get("notAfter", "Unavailable"),
                            "subject_alt_names": [v for kind, v in cert.get("subjectAltName", ()) if kind == "DNS"][:30],
                            "note": "Certificate validated by the local TLS trust store at inspection time.",
                        }
            except Exception as exc:
                errors.append(f"{address}: {type(exc).__name__}: {exc}")
        return {"status": "ERROR", "hostname": host, "errors": errors[:4],
                "note": "Could not validate a public TLS certificate. This is not, by itself, evidence of maliciousness."}
    except Exception as exc:
        return _error("ERROR", exc)


def inspect_dns(url: str) -> dict:
    try:
        _, host, _, _ = _parse_url(url)
        resolver = dns.resolver.Resolver()
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT
        result = {"status": "OK", "hostname": host, "records": {}, "note": "DNS records are informational and do not prove a site is safe."}
        failures = 0
        for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                answers = resolver.resolve(host, record_type, raise_on_no_answer=False)
                result["records"][record_type] = [] if answers.rrset is None else [str(answer) for answer in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                result["records"][record_type] = []
            except dns.resolver.NoNameservers as exc:
                failures += 1
                result["records"][record_type] = {"error": f"NoNameservers: {exc}"}
            except Exception as exc:
                failures += 1
                result["records"][record_type] = {"error": f"{type(exc).__name__}: {exc}"}
        if failures == len(result["records"]):
            result["status"] = "ERROR"
            result["note"] = "All DNS record lookups failed; check the domain and DNS/network connection."
        elif failures:
            result["status"] = "PARTIAL"
        return result
    except Exception as exc:
        return _error("ERROR", exc)


def _rdap_get(url: str) -> requests.Response:
    """Follow RDAP redirects manually, validating every destination first."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("RDAP redirect was not an HTTPS URL with a hostname; request blocked.")
        if parsed.username or parsed.password:
            raise ValueError("RDAP URL containing credentials was blocked.")
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        _public_addresses(host)
        response = requests.get(current, headers={"User-Agent": USER_AGENT,
            "Accept": "application/rdap+json, application/json"}, timeout=TIMEOUT,
            allow_redirects=False)
        if response.status_code not in REDIRECT_CODES:
            return response
        location = response.headers.get("Location")
        response.close()
        if not location:
            raise ValueError("RDAP redirect did not include a Location header.")
        current = urljoin(current, location)
    raise ValueError(f"RDAP exceeded the maximum of {MAX_REDIRECTS} redirects.")


def inspect_whois(url: str) -> dict:
    try:
        _, host, _, _ = _parse_url(url)
        # Try the full hostname first. RDAP registries may redirect from the
        # bootstrap endpoint to the appropriate registry server.
        candidates = [host]
        labels = host.split(".")
        # If a subdomain has no record, progressively try parent suffixes.
        candidates.extend(".".join(labels[i:]) for i in range(1, max(1, len(labels) - 1)))
        candidates = list(dict.fromkeys(candidates))
        last_not_found = None
        for domain in candidates:
            response = _rdap_get("https://rdap.org/domain/" + domain)
            try:
                if response.status_code == 404:
                    last_not_found = domain
                    continue
                if response.status_code in {400, 422} and domain != candidates[-1]:
                    last_not_found = domain
                    continue
                response.raise_for_status()
                try:
                    data = response.json()
                except ValueError as exc:
                    raise ValueError("RDAP server returned a non-JSON response.") from exc
                events = [{"event": e.get("eventAction"), "date": e.get("eventDate")} for e in data.get("events", [])]
                entities = []
                for entity in data.get("entities", []):
                    name = None
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item and item[0] == "fn" and len(item) > 3:
                                name = item[3]
                                break
                    entities.append({"roles": entity.get("roles", []), "name": name or "Not publicly provided"})
                return {"status": "OK", "domain": data.get("ldhName", domain),
                        "handle": data.get("handle"), "status_codes": data.get("status", []),
                        "events": events, "entities": entities,
                        "nameservers": [x.get("ldhName") for x in data.get("nameservers", [])],
                        "note": "RDAP data may be redacted or unavailable. Registration information does not prove a website is safe."}
            finally:
                response.close()
        return {"status": "NOT_FOUND", "domain": last_not_found or host,
                "note": "No RDAP registration record was returned for the checked domain names."}
    except Exception as exc:
        return _error("ERROR", exc, note="Registration lookup failed; this does not mean the website is malicious.")


def _safe_get(url: str) -> tuple[requests.Response, int, str]:
    _, _, _, normalized = _parse_url(url)
    current = normalized
    redirect_count = 0
    for _ in range(MAX_REDIRECTS + 1):
        parsed, host, _, _ = _parse_url(current)
        _public_addresses(host)
        response = requests.get(current, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT,
                                allow_redirects=False, stream=True)
        if response.status_code not in REDIRECT_CODES:
            return response, redirect_count, current
        location = response.headers.get("Location")
        response.close()
        if not location:
            raise ValueError("Redirect response did not include a Location header.")
        current = urljoin(current, location)
        redirect_count += 1
    raise ValueError(f"Stopped after {MAX_REDIRECTS} redirects to avoid redirect loops.")


def inspect_web(url: str) -> dict:
    response = None
    try:
        response, redirect_count, final_url = _safe_get(url)
        headers = response.headers
        security_headers = {key: headers.get(key, "Missing") for key in SECURITY_HEADERS}
        return {"status": "OK", "requested_url": url, "final_url": final_url,
                "http_status": response.status_code, "reason": response.reason,
                "redirect_count": redirect_count,
                "content_type": headers.get("Content-Type", "Unknown"),
                "server_header": headers.get("Server", "Not disclosed"),
                "security_headers": security_headers,
                "note": "Missing headers are observations, not proof of vulnerability."}
    except Exception as exc:
        return _error("ERROR", exc, note="Web inspection could not complete. A timeout or connection error does not indicate maliciousness.")
    finally:
        if response is not None:
            response.close()


class _PageInspector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self.scripts, self.links, self.issues = [], [], [], []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()
        if tag == "form":
            method = attrs.get("method", "get").lower()
            self.forms.append({"action": attrs.get("action", "(same page)"), "method": method.upper()})
            if method == "get" and "password" in str(attrs).lower():
                self.issues.append("A form may combine password-related fields with GET; review manually.")
        elif tag == "script":
            self.scripts.append(attrs.get("src", "inline script"))
        elif tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])


def inspect_html(url: str) -> dict:
    response = None
    try:
        response, redirect_count, final_url = _safe_get(url)
        content_type = response.headers.get("Content-Type", "")
        if "html" not in content_type.lower():
            return {"status": "SKIPPED", "http_status": response.status_code,
                    "content_type": content_type or "Unknown", "final_url": final_url,
                    "note": "Response did not identify itself as HTML; no HTML parsing was performed."}
        chunks, size, truncated = [], 0, False
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = MAX_HTML_BYTES - size
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                size += remaining
                truncated = True
                break
            chunks.append(chunk)
            size += len(chunk)
            if size >= MAX_HTML_BYTES:
                truncated = True
                break
        parser = _PageInspector()
        parser.feed(b"".join(chunks).decode(response.encoding or "utf-8", errors="replace"))
        return {"status": "OK", "http_status": response.status_code, "content_type": content_type,
                "final_url": final_url, "redirect_count": redirect_count,
                "bytes_inspected": size, "truncated": truncated,
                "forms": parser.forms[:100], "scripts": parser.scripts[:100],
                "links": parser.links[:100], "potential_review_items": parser.issues,
                "note": "Static HTML only: scripts are never executed and forms are never submitted. Findings require manual review."}
    except Exception as exc:
        return _error("ERROR", exc, note="HTML inspection could not complete. The site may be unavailable or block automated requests.")
    finally:
        if response is not None:
            response.close()
