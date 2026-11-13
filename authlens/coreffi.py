"""ctypes bridge to the C++ core (libauthlens_core.so).

The native library owns the byte-level work: segment offsets, decoded sizes,
RFC 7638 thumbprints, disclosure digests and the claim risk heuristics. It has
no opinion about protocol policy -- that lives in the Python layer on top of
authlas.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
from typing import Any

_BUFFER = 1 << 20


class CoreFault(RuntimeError):
    """The native core rejected the input or failed a digest."""


def _default_library() -> Path:
    env = os.environ.get("AUTHLENS_CORE")
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent
    for candidate in (here / "libauthlens_core.so", here.parent / "build" / "libauthlens_core.so"):
        if candidate.is_file():
            return candidate
    raise CoreFault("libauthlens_core.so not found -- run `make core` first")


class NativeCore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _default_library()
        self._lib = ctypes.CDLL(str(self.path))
        self._lib.al_version.restype = ctypes.c_char_p
        self._lib.al_last_error.restype = ctypes.c_char_p
        for name in ("al_scan", "al_thumbprint", "al_sd_digests", "al_sd_match", "al_risk"):
            fn = getattr(self._lib, name)
            fn.restype = ctypes.c_int
            fn.argtypes = None  # set per call shape below

    # -- plumbing ---------------------------------------------------------
    def _invoke(self, name: str, *args: str) -> Any:
        fn = getattr(self._lib, name)
        buf = ctypes.create_string_buffer(_BUFFER)
        encoded = [a.encode("utf-8") for a in args]
        ptrs: list[Any] = [ctypes.c_char_p(a) for a in encoded]
        n = fn(*ptrs, buf, ctypes.c_int(_BUFFER))
        if n < 0:
            raise CoreFault(self._lib.al_last_error().decode("utf-8", "replace") or f"{name} failed")
        return json.loads(buf.raw[:n].decode("utf-8"))

    def _invoke_text(self, name: str, *args: str) -> str:
        fn = getattr(self._lib, name)
        buf = ctypes.create_string_buffer(4096)
        encoded = [a.encode("utf-8") for a in args]
        ptrs = [ctypes.c_char_p(a) for a in encoded]
        n = fn(*ptrs, buf, ctypes.c_int(4096))
        if n < 0:
            raise CoreFault(self._lib.al_last_error().decode("utf-8", "replace") or f"{name} failed")
        return buf.raw[:n].decode("utf-8")

    # -- public surface ---------------------------------------------------
    def version(self) -> str:
        return self._lib.al_version().decode("ascii")

    def scan(self, token: str) -> dict[str, Any]:
        return self._invoke("al_scan", token)

    def thumbprint(self, jwk: dict[str, Any] | str) -> str:
        raw = jwk if isinstance(jwk, str) else json.dumps(jwk, separators=(",", ":"))
        return self._invoke_text("al_thumbprint", raw)

    def sd_digests(self, disclosures: list[str], hash_alg: str = "sha-256") -> dict[str, Any]:
        return self._invoke("al_sd_digests", json.dumps(disclosures), hash_alg)

    def sd_match(self, sd_array: list[str], disclosures: list[str], hash_alg: str = "sha-256") -> dict[str, Any]:
        return self._invoke("al_sd_match", json.dumps(sd_array), json.dumps(disclosures), hash_alg)

    def risk(self, header: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        return self._invoke(
            "al_risk",
            json.dumps(header, separators=(",", ":")),
            json.dumps(payload, separators=(",", ":")),
        )


_singleton: NativeCore | None = None


def native() -> NativeCore:
    global _singleton
    if _singleton is None:
        _singleton = NativeCore()
    return _singleton
