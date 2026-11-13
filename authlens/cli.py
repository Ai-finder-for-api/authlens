"""Command line entry point: `python -m authlens serve`."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="authlens", description="OAuth 2.0 / JOSE inspection workbench")
    parser.add_argument("--version", action="version", version=f"authlens {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    srv = sub.add_parser("serve", help="run the workbench UI")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8770)

    an = sub.add_parser("analyze", help="analyse a compact JWS/SD-JWT from stdin or --token")
    an.add_argument("--token")
    an.add_argument("--issuer", default="")
    an.add_argument("--audience", default="")

    sub.add_parser("health", help="print the layer versions")

    args = parser.parse_args(argv)
    if args.cmd == "serve":
        from .server import serve

        serve(args.host, args.port)
        return 0
    from .workbench import bench

    b = bench()
    if args.cmd == "health":
        print(json.dumps(b.health(), indent=2))
        return 0
    token = args.token or sys.stdin.read().strip()
    result = b.analyze(token, issuer=args.issuer, audience=args.audience)
    print(json.dumps({k: result[k] for k in ("format", "header", "payload", "risk", "verification")},
                     indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
