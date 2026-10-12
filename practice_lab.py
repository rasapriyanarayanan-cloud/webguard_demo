"""Two local practice sites: 8001 = weak headers (BEFORE), 8002 = hardened headers (AFTER)."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = b"<h1>WebGuard Practice Site</h1><p>Local test page for header scanning.</p>"

def make(secure):
    class H(BaseHTTPRequestHandler):
        server_version = "webserver" if secure else "nginx/1.18.0"
        sys_version = ""
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            if secure:
                self.send_header("Content-Security-Policy", "default-src 'self'")
                self.send_header("X-Frame-Options", "SAMEORIGIN")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.end_headers(); self.wfile.write(PAGE)
    return H

if __name__ == "__main__":
    for port, sec in ((8001, False), (8002, True)):
        s = ThreadingHTTPServer(("127.0.0.1", port), make(sec))
        threading.Thread(target=s.serve_forever, daemon=True).start()
        print(f"Practice site ({'SECURE' if sec else 'INSECURE'}) on http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop.")
    threading.Event().wait()
