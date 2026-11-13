"""AuthLens HTTP server: JSON API plus the compiled TypeScript bundle.

Stdlib only. The server is a thin transport: it decodes JSON, calls the
workbench and encodes the answer. Threaded, so a slow signature check cannot
stall the interface.
"""
from __future__ import annotations

import json
import mimetypes
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .workbench import bench

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "ui"
DIST = UI / "dist"

Handler_ = Callable[[dict[str, Any]], Any]


def endpoints() -> dict[str, Handler_]:
    b = bench()
    return {
        "/api/keys": lambda body: {"ok": True, "keys": b.key_list(), "default": b.default_key_id},
        "/api/keys/new": lambda body: {"ok": True, "key": b.new_key(body.get("curve", "P-256"))},
        "/api/analyze": lambda body: b.analyze(
            body.get("token", ""),
            jwks=body.get("jwks") or None,
            key_id=body.get("key_id") or None,
            issuer=body.get("issuer", ""),
            audience=body.get("audience", ""),
            algs=body.get("algs") or None,
            require=body.get("require") or None,
        ),
        "/api/mint": lambda body: b.mint(body.get("claims") or {}, key_id=body.get("key_id"),
                                          typ=body.get("typ", "at+jwt"), alg=body.get("alg")),
        "/api/sdjwt/issue": lambda body: b.sd_issue(
            body.get("claims") or {}, hide=body.get("hide") or [], decoys=int(body.get("decoys") or 0),
            key_id=body.get("key_id"), typ=body.get("typ", "dc+sd-jwt")),
        "/api/sdjwt/present": lambda body: b.sd_present(body.get("sd_jwt", ""), body.get("reveal") or []),
        "/api/sdjwt/verify": lambda body: b.sd_verify(
            body.get("sd_jwt", ""), key_id=body.get("key_id"), audience=body.get("audience", "")),
        "/api/pkce": lambda body: b.pkce_lab(body),
        "/api/discovery": lambda body: b.discovery_plan(body.get("issuer", ""), body.get("resource", "")),
        "/api/challenge": lambda body: b.challenge_parse(body.get("header", "")),
        "/api/dcql": lambda body: b.dcql_probe(body.get("query", "{}"), body.get("credential", "{}")),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AuthLens/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # keep the console readable
        if args and "/api/" in str(args[0]):
            super().log_message(fmt, *args)

    # ----------------------------------------------------------- utilities
    def _json(self, status: int, payload: Any) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"invalid JSON body: {e}") from e
        return parsed if isinstance(parsed, dict) else {}

    def _static(self, path: str) -> None:
        rel = (path.lstrip("/") or "index.html").replace("..", "")
        candidate = UI / rel if (UI / rel).is_file() else DIST / rel
        if not candidate.is_file():
            candidate = UI / "index.html"  # single page app fallback
        raw = candidate.read_bytes()
        ctype = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        if candidate.suffix in (".js", ".ts", ".mjs"):
            ctype = "text/javascript; charset=utf-8"
        elif candidate.suffix == ".css":
            ctype = "text/css; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    # ------------------------------------------------------------- verbs
    def do_GET(self) -> None:  # noqa: N802
        path = re.sub(r"\?.*$", "", self.path)
        if path == "/api/health":
            self._json(200, bench().health())
            return
        if path == "/api/keys":
            self._json(200, {"ok": True, "keys": bench().key_list(), "default": bench().default_key_id})
            return
        self._static(path)

    def do_POST(self) -> None:  # noqa: N802
        path = re.sub(r"\?.*$", "", self.path)
        handler = endpoints().get(path)
        if handler is None:
            self._json(404, {"ok": False, "message": f"no handler for {path}"})
            return
        try:
            self._json(200, handler(self._body()))
        except Exception as e:  # surface the class name: the UI shows it verbatim
            self._json(500, {"ok": False, "type": type(e).__name__, "message": str(e)})


def serve(host: str = "127.0.0.1", port: int = 8770) -> None:
    bench()  # generate the keyring and samples before the first request
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"AuthLens on http://{host}:{port}  (UI: {UI / 'index.html'})", flush=True)
    httpd.serve_forever()
