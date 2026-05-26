"""Tiny static server for LocalPhish fixtures.

Serves test/fixtures/ at http://localhost:8765 so the extension can hit the
fake pages with a real http:// URL (file:// pages bypass content-script
matching by design).

Usage:
    cd test
    uv run python serve.py
    # then open http://localhost:8765/microsoft-365-login-fake.html
"""

from __future__ import annotations

import argparse
import http.server
import os
import socketserver
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--root", type=Path, default=Path(__file__).parent / "fixtures")
    args = parser.parse_args()

    os.chdir(args.root)
    handler = http.server.SimpleHTTPRequestHandler

    print(f"Serving {args.root.resolve()} at http://localhost:{args.port}/")
    print("Press Ctrl-C to stop.\n")
    print("Try these URLs in Chrome with LocalPhish loaded:")
    for p in sorted(args.root.glob("*.html")):
        print(f"  http://localhost:{args.port}/{p.name}")
    print()

    with socketserver.TCPServer(("127.0.0.1", args.port), handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
