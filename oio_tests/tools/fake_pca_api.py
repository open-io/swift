#!/usr/bin/env python

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 7000

class State:
    def __new__(cls):
        if not hasattr(cls, "inst"):
            cls.inst = super().__new__(cls)
        return cls.inst

    def __init__(self):
        self.content = None



STATE = State()


class FakePcaHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        STATE.content = self.rfile.read(content_length)
        self.send_response(201)
        self.end_headers()

    def do_GET(self):
        if STATE.content is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(STATE.content)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), FakePcaHandler)
    print(f"Starting Fake PCA API on 0.0.0.0:{PORT}...")
    server.serve_forever()


if __name__ == "__main__":
    main()
