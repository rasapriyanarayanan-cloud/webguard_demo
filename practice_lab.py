"""Four local practice sites with different security levels."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = b"<h1>WebGuard Practice Site</h1><p>Local test page for header scanning.</p>"
HDR = {"csp": ("Content-Security-Policy", "default-src 'self'"), "xfo": ("X-Frame-Options", "SAMEORIGIN"),
       "xcto": ("X-Content-Type-Options", "nosniff"), "ref": ("Referrer-Policy", "strict-origin-when-cross-origin")}
# port: (name, Server header, headers present)
SITES = {
    8001: ("INSECURE  (low score)", "nginx/1.18.0", []),
    8002: ("SECURE    (100)", "webserver", ["csp", "xfo", "xcto", "ref"]),
    8003: ("MEDIUM    (1 needs attention)", "webserver", ["csp", "xcto", "ref"]),
    8004: ("MIXED     (pass + needs attention + info)", "nginx/1.18.0", ["xfo", "xcto", "ref"]),
}

def make(server, present):
    class H(BaseHTTPRequestHandler):
        server_version = server
        sys_version = ""
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            for k in present:
                self.send_header(*HDR[k])
            self.end_headers(); self.wfile.write(PAGE)
    return H

if __name__ == "__main__":
    for port, (name, server, present) in SITES.items():
        s = ThreadingHTTPServer(("127.0.0.1", port), make(server, present))
        threading.Thread(target=s.serve_forever, daemon=True).start()
        print(f"http://127.0.0.1:{port}  {name}")
    print("Press Ctrl+C to stop.")
    threading.Event().wait()
