"""The Python layer: protocol rules and orchestration.

Every decision that matters for security is delegated to authlas-python (Rust
core behind a C++ transport). This module adds what an *operator* needs:
a session keyring, samples, error surfaces that keep authlas' error `kind`,
and the hand-off to the C++ analyser.
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any

import authlas
from authlas import core as alcore
from authlas import dcql, discovery

from . import __version__
from .coreffi import CoreFault, native

EC_ALGS = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
SAFE_ALGS = ["ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"]


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def err(e: Exception) -> dict[str, Any]:
    return {
        "ok": False,
        "type": type(e).__name__,
        "kind": getattr(e, "kind", None),
        "message": str(e),
    }


class Workbench:
    """One operator session: a keyring, samples and the analysis pipeline."""

    def __init__(self) -> None:
        self.started = time.time()
        self.keys: dict[str, dict[str, Any]] = {}
        self.default_key_id = self.new_key("P-256")["id"]
        self.samples = self._build_samples()

    # ------------------------------------------------------------------ keys
    def new_key(self, curve: str = "P-256") -> dict[str, Any]:
        if curve not in EC_ALGS:
            raise ValueError(f"unsupported curve {curve!r}; use one of {sorted(EC_ALGS)}")
        private = alcore.generate_ec_key(curve)
        public = alcore.public_jwk(private)
        entry = {
            "id": f"key-{uuid.uuid4().hex[:6]}",
            "alg": EC_ALGS[curve],
            "curve": curve,
            "created": int(time.time()),
            "private": private,
            "public": public,
            # Two independent implementations of RFC 7638 must agree.
            "thumbprint": alcore.thumbprint(public),
            "thumbprint_native": native().thumbprint(public),
        }
        entry["thumbprint_agrees"] = entry["thumbprint"] == entry["thumbprint_native"]
        self.keys[entry["id"]] = entry
        return self.public_key(entry)

    @staticmethod
    def public_key(entry: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in entry.items() if k != "private"} | {"jwk": entry["public"]}

    def key_list(self) -> list[dict[str, Any]]:
        return [self.public_key(k) for k in self.keys.values()]

    def _key(self, key_id: str | None) -> dict[str, Any]:
        kid = key_id or self.default_key_id
        if kid not in self.keys:
            raise KeyError(f"unknown key {kid!r}")
        return self.keys[kid]

    # --------------------------------------------------------------- analyze
    def analyze(
        self,
        token: str,
        *,
        jwks: Any = None,
        key_id: str | None = None,
        issuer: str = "",
        audience: str = "",
        algs: list[str] | None = None,
        require: list[str] | None = None,
    ) -> dict[str, Any]:
        token = (token or "").strip()
        core = native()
        scan = core.scan(token)
        segments = scan.get("segments") or []
        header = next((s.get("json") for s in segments if s.get("role") == "header"), None)
        payload = next((s.get("json") for s in segments if s.get("role") == "payload"), None)
        if scan.get("key_binding"):
            payload = payload  # key binding JWT kept separately in scan

        result: dict[str, Any] = {
            "ok": True,
            "token": token,
            "format": scan.get("format"),
            "nbytes": scan.get("nbytes"),
            "segments": segments,
            "header": header,
            "payload": payload,
            "notes": scan.get("notes", []),
            "key_binding": scan.get("key_binding"),
            "risk": None,
            "thumbprint": None,
            "verification": None,
            "sd": None,
            "timeline": None,
        }
        if isinstance(header, dict) and isinstance(payload, dict):
            result["risk"] = core.risk(header, payload)
            result["timeline"] = self._timeline(payload)
        if isinstance(header, dict) and isinstance(header.get("jwk"), dict):
            try:
                result["thumbprint"] = core.thumbprint(header["jwk"])
            except CoreFault:
                result["thumbprint"] = None
        if scan.get("format") == "sd-jwt" and isinstance(payload, dict):
            result["sd"] = self._sd_view(payload, _disclosure_strings(token))
        result["verification"] = self._verify(token, header, jwks=jwks, key_id=key_id,
                                              issuer=issuer, audience=audience,
                                              algs=algs, require=require)
        return result

    def _timeline(self, payload: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {"now": int(time.time())}
        for claim, label in (("iat", "issued"), ("nbf", "not_before"), ("exp", "expires")):
            value = payload.get(claim)
            if isinstance(value, (int, float)):
                out[label] = int(value)
                out[f"{label}_in"] = int(value - time.time())
        if isinstance(payload.get("exp"), (int, float)) and isinstance(payload.get("iat"), (int, float)):
            out["lifetime"] = int(payload["exp"] - payload["iat"])
        return out

    def _verify(self, token: str, header: Any, *, jwks: Any, key_id: str | None,
                issuer: str, audience: str, algs: list[str] | None,
                require: list[str] | None) -> dict[str, Any] | None:
        if not isinstance(header, dict):
            return {"ok": False, "type": "Skip", "kind": "no-header",
                    "message": "The header could not be decoded, so there is nothing to verify against."}
        allowed = [a for a in (algs or [header.get("alg") or "ES256"]) if a in SAFE_ALGS]
        if not allowed:
            return {"ok": False, "type": "Skip", "kind": "alg-not-allowed",
                    "message": f"alg {header.get('alg')!r} is not in the verifier allow-list."}
        key: dict[str, Any] | None = None
        source = ""
        if key_id:
            if key_id not in self.keys:
                return {"ok": False, "type": "Skip", "kind": "unknown-key",
                        "message": f"no session key {key_id!r}"}
            key = self.keys[key_id]["public"]
            source = f"session keyring {key_id}"
        elif jwks:
            doc = json.loads(jwks) if isinstance(jwks, str) else jwks
            keys = doc.get("keys") if isinstance(doc, dict) else None
            if not isinstance(keys, list) or not keys:
                return {"ok": False, "type": "Skip", "kind": "bad-jwks",
                        "message": "JWKS must be an object with a non-empty 'keys' array."}
            kid = header.get("kid")
            key = next((k for k in keys if kid and k.get("kid") == kid), keys[0])
            source = f"JWKS ({len(keys)} key{'s' if len(keys) != 1 else ''})"
        if key is None:
            return {"ok": False, "type": "Skip", "kind": "no-key",
                    "message": "Provide a JWKS or pick a session key to run signature verification."}
        if not issuer or not audience:
            return {"ok": False, "type": "Skip", "kind": "needs-policy",
                    "message": "authlas requires an expected issuer and audience before it will verify.",
                    "source": source}
        try:
            verified = alcore.jwt_verify(token, key, algs=allowed, issuer=issuer,
                                         audience=audience, require=require or ())
            return {"ok": True, "source": source, "algs": allowed, **verified}
        except Exception as e:  # authlas raises typed errors with a .kind
            return {"ok": False, "source": source, "algs": allowed, **err(e)}

    # ----------------------------------------------------------------- mint
    def mint(self, claims: dict[str, Any], *, key_id: str | None = None,
             typ: str = "at+jwt", alg: str | None = None) -> dict[str, Any]:
        entry = self._key(key_id)
        alg = alg or entry["alg"]
        token = alcore.jwt_sign(alg, entry["private"], claims, typ=typ)
        return {"ok": True, "token": token, "alg": alg, "kid": entry["id"], "typ": typ,
                "claims": claims, "analysis": self.analyze(token, key_id=entry["id"])}

    # --------------------------------------------------------------- sd-jwt
    @staticmethod
    def _sd_view(payload: dict[str, Any], disclosures: list[str]) -> dict[str, Any]:
        sd_array = payload.get("_sd") if isinstance(payload.get("_sd"), list) else []
        hash_alg = payload.get("_sd_alg") or "sha-256"
        strings = [d for d in disclosures if isinstance(d, str) and d]
        try:
            match = native().sd_match([s for s in sd_array if isinstance(s, str)], strings, hash_alg)
        except CoreFault as e:
            return {"error": str(e), "digests": [], "match": None}
        return {"hash": hash_alg, "digests": native().sd_digests(strings, hash_alg)["digests"],
                "match": match, "disclosure_count": len(strings),
                "visible_claims": sorted(k for k in payload if not k.startswith("_")),
                "hidden_digests": len(sd_array)}

    def sd_issue(self, claims: dict[str, Any], *, hide: list[str] | None = None,
                 decoys: int = 0, key_id: str | None = None,
                 typ: str = "dc+sd-jwt") -> dict[str, Any]:
        entry = self._key(key_id)
        hide = [h for h in (hide or []) if h in claims]
        issued = alcore.sdjwt_issue(claims, entry["private"], alg=entry["alg"], typ=typ,
                                    hide=hide, decoys=max(0, min(int(decoys), 8)))
        sd_jwt = issued["sd_jwt"]
        return {"ok": True, "sd_jwt": sd_jwt, "disclosures": issued["disclosures"],
                "issuer_key": entry["id"], "hidden": hide,
                "analysis": self.analyze(sd_jwt, key_id=entry["id"])}

    def sd_present(self, sd_jwt: str, reveal: list[int]) -> dict[str, Any]:
        token = alcore.sdjwt_present(sd_jwt, reveal=sorted(set(int(i) for i in reveal)))
        presented = token.split("~")
        return {"ok": True, "presentation": token,
                "revealed": len([p for p in presented[1:] if p]),
                "analysis": self.analyze(token)}

    def sd_verify(self, sd_jwt: str, *, key_id: str | None = None,
                  audience: str = "") -> dict[str, Any]:
        entry = self._key(key_id)
        scan = native().scan(sd_jwt)
        payload = next((s.get("json") for s in scan.get("segments", []) if s.get("role") == "payload"), {}) or {}
        issuer = payload.get("iss", "")
        try:
            verified = alcore.sdjwt_verify(
                sd_jwt, entry["public"], algs=list(SAFE_ALGS), issuer=issuer,
                typ=payload.get("typ") or "dc+sd-jwt",
                audience=audience or None,
            )
            return {"ok": True, **verified, "issuer": issuer}
        except Exception as e:
            return {"ok": False, "issuer": issuer, **err(e)}

    # -------------------------------------------------------------- protocol
    def pkce_lab(self, body: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": True}
        pair = alcore.pkce_new()
        out["generated"] = pair
        verifier = body.get("verifier") or pair["verifier"]
        challenge = body.get("challenge") or pair["challenge"]
        try:
            alcore.pkce_verify(challenge, verifier)
            out["pkce"] = {"ok": True, "message": "challenge matches the verifier (S256)"}
        except Exception as e:
            out["pkce"] = err(e)
        checks = []
        for kind, value in (("web", body.get("redirect") or ""), ("native", body.get("native") or "")):
            v = (value or "").strip()
            if not v:
                continue
            try:
                alcore.redirect_validate(v, kind)
                checks.append({"kind": kind, "uri": v, "ok": True, "message": "accepted"})
            except Exception as e:
                checks.append({"kind": kind, "uri": v, "ok": False,
                               "message": f"{type(e).__name__}: {e}"})
        out["redirects"] = checks
        registered = (body.get("registered") or "").strip()
        presented = (body.get("presented") or "").strip()
        if registered and presented:
            out["redirect_match"] = alcore.redirect_matches(registered, presented)
        scoped = (body.get("requested"), body.get("allowed"))
        if scoped[0] and scoped[1]:
            try:
                out["scope"] = {"ok": True, **alcore.scope_check(scoped[0], scoped[1])}
            except Exception as e:
                out["scope"] = err(e)
        return out

    def discovery_plan(self, issuer: str, resource: str = "") -> dict[str, Any]:
        issuer = (issuer or "").strip()
        out: dict[str, Any] = {"ok": True, "issuer": issuer}
        if issuer:
            try:
                out["metadata_urls"] = discovery.metadata_urls(issuer, oidc_first=bool(resource))
                protected = discovery.protected_resource_metadata_url(issuer)
                out["protected_resource_url"] = protected
            except Exception as e:
                out["error"] = err(e)
        if resource:
            try:
                from authlas import mcp
                out["canonical_resource"] = mcp.canonical_resource(resource)
                out["resource_metadata_url"] = discovery.protected_resource_metadata_url(resource)
            except Exception as e:
                out["resource_error"] = err(e)
        return out

    def challenge_parse(self, value: str) -> dict[str, Any]:
        value = (value or "").strip()
        if not value:
            return {"ok": False, "type": "Input", "message": "Paste a WWW-Authenticate header value."}
        challenges = authlas.parse_www_authenticate(value)
        out: dict[str, Any] = {"ok": True, "challenges": challenges}
        known = ("realm", "scope", "error", "error_description", "resource_metadata", "algs")
        for challenge in challenges:
            if challenge.get("scheme", "").lower() != "bearer":
                continue
            params = {k: v for k, v in challenge.get("params", {}).items() if k in known}
            try:
                out["rebuilt"] = alcore.bearer_challenge(**params)
            except Exception as e:
                out["rebuild_error"] = err(e)
            break
        return out

    def dcql_probe(self, query: str, credential: str) -> dict[str, Any]:
        try:
            q = dcql.validate_query(json.loads(query))
            cred = json.loads(credential)
        except Exception as e:
            return {"ok": False, **err(e)}
        selection = dcql.select_claims(q, cred)
        return {
            "ok": True,
            "valid": True,
            "selection": None if selection is None else {
                "paths": selection.paths,
                "option": selection.option,
            },
            "satisfiable": selection is not None,
            "query_ids": [c.get("id") for c in q.get("credentials", [])],
        }

    # ----------------------------------------------------------------- meta
    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "app": "AuthLens",
            "version": __version__,
            "uptime": int(time.time() - self.started),
            "layers": {
                "core": {"language": "C++17", "version": native().version(),
                         "library": native().path.name},
                "main": {"language": "Python", "version": ".".join(map(str, __import__("sys").version_info[:3])),
                         "library": f"authlas-python {getattr(authlas, '__version__', '0.1.0')}",
                         "backend": alcore.backend()},
                "ui": {"language": "TypeScript", "version": __version__},
            },
            "keys": len(self.keys),
            "samples": [{"id": s["id"], "label": s["label"], "hint": s["hint"]} for s in self.samples],
        }

    # -------------------------------------------------------------- samples
    def _build_samples(self) -> list[dict[str, Any]]:
        now = int(time.time())
        clean = {
            "iss": "https://issuer.example", "sub": "alice@example.com",
            "aud": "api://orders", "scope": "orders:read profile",
            "iat": now - 30, "exp": now + 270, "jti": "01J8Z4C7Q3",
        }
        good = self.mint(clean, typ="at+jwt")["token"]

        evil_header = {"alg": "HS256", "typ": "JWT", "kid": "../../etc/passwd",
                       "jku": "https://keys.attacker.example/jwks.json"}
        evil_payload = {"iss": "https://legacy.example", "sub": "svc-batch",
                        "scope": "admin:*", "iat": now - 7200}
        evil = ".".join([
            b64u(json.dumps(evil_header, separators=(",", ":")).encode()),
            b64u(json.dumps(evil_payload, separators=(",", ":")).encode()),
            b64u(b"forged-signature"),
        ])

        expired = self.mint({"iss": "https://issuer.example", "sub": "bob@example.com",
                             "aud": "api://reports", "iat": now - 9000,
                             "exp": now - 300, "jti": "01J8Z4C7Q4"}, typ="JWT")["token"]

        sd = self.sd_issue({"iss": "https://issuer.example", "sub": "alice@example.com",
                            "given_name": "Alice", "age_over_18": True,
                            "address": {"locality": "Berlin", "country": "DE"}},
                           hide=["given_name", "age_over_18"], decoys=1)["sd_jwt"]
        return [
            {"id": "clean", "label": "Access token", "hint": "ES256 · short lived · scoped",
             "token": good},
            {"id": "hostile", "label": "Hostile token", "hint": "HS256 · jku · kid traversal · no exp",
             "token": evil},
            {"id": "expired", "label": "Expired ID token", "hint": "exp 5 minutes ago", "token": expired},
            {"id": "sdjwt", "label": "SD-JWT credential", "hint": "2 hidden claims · 1 decoy",
             "token": sd},
        ]


def _disclosure_strings(token: str) -> list[str]:
    """Disclosure segments exactly as they appear in the compact form.

    Re-encoding the parsed JSON would re-order nothing but could re-escape
    strings, and a digest is taken over the bytes, not over the meaning.
    """
    if "~" not in token:
        return []
    return [part for part in token.split("~")[1:] if part and "." not in part]


_bench: Workbench | None = None


def bench() -> Workbench:
    global _bench
    if _bench is None:
        _bench = Workbench()
    return _bench
