"""WebGuard scanner: passive, read-only checks (one GET request + TLS handshake)."""
import socket, ssl, time, ipaddress, datetime as dt
from urllib.parse import urlparse, urljoin
import requests

UA = {"User-Agent": "WebGuard-Educational-Scanner/1.0"}

# key: (title, tamil_if_ok, tamil_if_bad, problem, solution, nginx snippet)
META = {
 "https": ("HTTPS Usage", "இது நல்லது. உங்கள் தகவல்கள் encrypt ஆகி பாதுகாப்பாக இருக்கும். (Good! Your data is encrypted.)",
   "இணையதளம் HTTPS பயன்படுத்தவில்லை. தகவல்கள் திருடப்பட வாய்ப்பு உள்ளது. (Data may be intercepted.)",
   "Site is served over plain HTTP.", "Install a TLS certificate (e.g. Let's Encrypt) and redirect HTTP to HTTPS.",
   "return 301 https://$host$request_uri;"),
 "ssl": ("Valid SSL Certificate", "சான்றிதழ் (certificate) செல்லுபடியாகும். (Certificate is valid.)",
   "சான்றிதழ் காலாவதி அல்லது தவறானது. (Certificate is expired or invalid.)",
   "Certificate is missing, expired or untrusted.", "Renew or install a certificate from a trusted CA.",
   "certbot renew --nginx"),
 "csp": ("Content Security Policy", "CSP சரியாக உள்ளது. XSS தாக்குதல் ஆபத்து குறையும். (CSP is set; lowers XSS risk.)",
   "CSP header இல்லாததால் malicious scripts (XSS) ரன் ஆக வாய்ப்பு அதிகம். (May allow certain attacks.)",
   "No Content-Security-Policy header, so injected scripts are not restricted.", "Add a CSP header that only allows trusted sources.",
   "add_header Content-Security-Policy \"default-src 'self'\" always;"),
 "xfo": ("X-Frame-Options", "Clickjacking-இலிருந்து பாதுகாப்பு உள்ளது. (Protected from clickjacking.)",
   "இந்த header இல்லாததால் உங்கள் பக்கத்தை வேறு தளம் frame செய்யலாம். (Clickjacking possible.)",
   "Page can be embedded in another site's frame.", "Add X-Frame-Options DENY or SAMEORIGIN.",
   "add_header X-Frame-Options \"SAMEORIGIN\" always;"),
 "xcto": ("X-Content-Type-Options", "MIME sniffing தடுக்கப்படுகிறது. (Prevents MIME sniffing.)",
   "Browser கோப்பு வகையை ஊகிக்கலாம். (Browser may guess file types.)",
   "Header missing, so browsers may MIME-sniff.", "Set the header to nosniff.",
   "add_header X-Content-Type-Options \"nosniff\" always;"),
 "ref": ("Referrer-Policy", "Referrer தகவல் கட்டுப்படுத்தப்படுகிறது. (Controls referrer information.)",
   "Referrer தகவல் மற்ற தளங்களுக்கு கசியலாம். (URL info may leak.)",
   "Referrer-Policy missing; full URLs may leak to other sites.", "Set Referrer-Policy to strict-origin-when-cross-origin.",
   "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"),
 "hsts": ("HSTS (Strict-Transport-Security)", "HSTS உள்ளது; browser எப்போதும் HTTPS பயன்படுத்தும். (Browser forces HTTPS.)",
   "இது இல்லாததால் HTTPS-க்கு பதில் HTTP பயன்படுத்த வைக்கும் ஆபத்து உள்ளது. (May allow downgrade attacks.)",
   "HSTS header is not present, so attackers may force HTTP.", "Add the Strict-Transport-Security header.",
   "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"),
 "server": ("Server Information", "Server version வெளிப்படுத்தப்படவில்லை. (Version not disclosed.)",
   "Server details வெளிப்படுகிறது. (May reveal server info.)",
   "Server header reveals software/version.", "Hide the version number.", "server_tokens off;"),
}
ORDER = ["https", "ssl", "csp", "xfo", "xcto", "ref", "hsts", "server"]


def _item(key, status, detail):
    t, ok, bad, prob, sol, snip = META[key]
    ta = ok if status == "pass" else ("Local HTTP practice mode-ல் இது பொருந்தாது. (Not applicable on local HTTP.)" if status == "na" else bad)
    return {"key": key, "title": t, "status": status, "detail": detail, "ta": ta,
            "fix": {"problem": prob, "solution": sol, "snippet": snip}}


def _check_target(url, mode):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Enter a valid http:// or https:// URL")
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80))
    except socket.gaierror:
        raise ValueError("Could not resolve that host name")
    ips = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}
    if mode == "local" and not all(i.is_loopback for i in ips):
        raise ValueError("Local Practice mode only allows localhost / 127.0.0.1")
    if mode == "public" and any(i.is_private or i.is_loopback or i.is_link_local or i.is_reserved for i in ips):
        raise ValueError("Public mode blocks private/local addresses. Switch to Local Practice mode.")


def _cert_days(host, port):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=6) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            c = t.getpeercert()
    return int((ssl.cert_time_to_seconds(c["notAfter"]) - time.time()) / 86400)


def _fetch(url, mode):
    ssl_err = False
    for _ in range(4):
        _check_target(url, mode)
        try:
            r = requests.get(url, timeout=8, allow_redirects=False, headers=UA)
        except requests.exceptions.SSLError:
            ssl_err = True
            r = requests.get(url, timeout=8, allow_redirects=False, headers=UA, verify=False)
        if r.is_redirect and r.headers.get("Location"):
            url = urljoin(url, r.headers["Location"]); continue
        return url, r, ssl_err
    return url, r, ssl_err


def scan(url, mode="public"):
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    final, r, ssl_err = _fetch(url, mode)
    h = {k.lower(): v for k, v in r.headers.items()}
    p = urlparse(final)
    https, local = p.scheme == "https", mode == "local"
    out = []

    out.append(_item("https", "na" if local else ("pass" if https else "review"),
                     "Local HTTP practice server." if local else ("The website uses HTTPS." if https else "Site is served over HTTP.")))
    if local:
        out.append(_item("ssl", "na", "Not applicable locally."))
    elif not https:
        out.append(_item("ssl", "review", "No certificate: site is HTTP."))
    else:
        try:
            d = _cert_days(p.hostname, p.port or 443)
            ok = d > 0 and not ssl_err
            out.append(_item("ssl", "pass" if ok else "review", f"Certificate valid, {d} days left." if ok else "Certificate expired or untrusted."))
        except Exception as e:
            out.append(_item("ssl", "review", f"Certificate check failed: {type(e).__name__}"))
    csp = h.get("content-security-policy")
    out.append(_item("csp", "pass" if csp else "review", "CSP header present." if csp else "CSP header is missing."))
    xfo = h.get("x-frame-options") or ("frame-ancestors" in (csp or ""))
    out.append(_item("xfo", "pass" if xfo else "review", "Frame protection present." if xfo else "X-Frame-Options header is missing."))
    nos = h.get("x-content-type-options", "").lower() == "nosniff"
    out.append(_item("xcto", "pass" if nos else "review", "Header present and set to nosniff." if nos else "Header is missing or not nosniff."))
    ref = h.get("referrer-policy")
    out.append(_item("ref", "pass" if ref else "review", f"Referrer-Policy set to {ref}." if ref else "Referrer-Policy is missing."))
    if local:
        out.append(_item("hsts", "na", "Not applicable on HTTP."))
    elif not https:
        out.append(_item("hsts", "review", "HSTS needs HTTPS first."))
    else:
        out.append(_item("hsts", "pass" if "strict-transport-security" in h else "review",
                         "HSTS header present." if "strict-transport-security" in h else "HSTS header is missing."))
    srv = h.get("server", "")
    if any(c.isdigit() for c in srv):
        out.append(_item("server", "info", f"Server header is present ({srv}). Consider hiding version information."))
    else:
        out.append(_item("server", "pass", f"Server header: {srv or 'not disclosed'}."))

    counted = [i for i in out if i["status"] != "na"]
    n = {s: sum(i["status"] == s for i in out) for s in ("pass", "review", "info", "na")}
    score = round((n["pass"] + 0.5 * n["info"]) / len(counted) * 100) if counted else 0
    risk = "Low Risk" if score >= 85 else "Moderate Risk" if score >= 60 else "High Risk"
    return {"url": final, "mode": mode, "scanned_at": dt.datetime.now().strftime("%d %b %Y, %H:%M"),
            "score": score, "risk": risk, "total": len(counted), "passed": n["pass"],
            "review": n["review"], "info": n["info"], "na": n["na"], "findings": out}
