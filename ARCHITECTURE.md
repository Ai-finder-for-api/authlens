# Architecture

## Layer boundaries

```
ui/src/*.ts ──HTTP/JSON──▶ authlens/server.py ──▶ authlens/workbench.py ──┬─▶ authlas (Python)
                                                                          └─▶ ctypes ─▶ C++ core
```

The boundary between the Python layer and the core is a **C ABI with JSON payloads**, not a Python
extension module. That keeps the core usable from any language, keeps the build to one `g++`
invocation, and makes the transport of untrusted data explicit: every string crossing the boundary
is length-delimited and the core never dereferences a pointer it did not receive with a size.

## C++ core (`core/`)

| Unit | Responsibility |
| --- | --- |
| `JVal` / `Parser` | A strict JSON parser (UTF-8 passthrough, `\u` escapes with surrogate pairs, ordered object members). Needed because thumbprints are taken over canonical JSON, not over a hash map. |
| base64url | Encode/decode without padding, tolerant of `+`/`/` on decode (compact JOSE never emits them, but pasted tokens sometimes do). |
| `al_scan` | Splits a compact JWS/JWE/SD-JWT into segments and reports `offset`, `length`, decoded `bytes`, base64 validity and parsed JSON per segment. For SD-JWTs it separates disclosures from a trailing key-binding JWT. |
| `al_thumbprint` | RFC 7638: rebuild the JWK from required members only, in lexicographic order, without whitespace; SHA-256; base64url. |
| `al_sd_digests` / `al_sd_match` | SHA-256/384/512 over raw disclosure bytes and a digest → disclosure mapping against the issuer's `_sd` array, so decoys show up as unmatched. |
| `al_risk` | Header and claim heuristics (alg:none, symmetric algs, jku/x5u/jwk, crit, kid traversal, missing exp/aud/iss, lifetime, multi-audience, broad scope, cnf/act) with a 100-point score and a letter grade. |

Deliberate limit: the core does **not** verify signatures. Crypto policy is the library's job; the
core only describes what is on the wire. That separation is what lets the interface say
"structurally sound but rejected by the verifier" without conflating the two statements.

## Python layer (`authlens/`)

* `coreffi.py` — `ctypes.CDLL`, fixed argtypes, one 1 MiB output buffer per call, errors raised as
  `CoreFault` carrying `al_last_error()`.
* `workbench.py` — one operator session: an in-memory keyring, four sample tokens, the analysis
  pipeline (native scan → native risk → authlas verification), SD-JWT issue/present/verify, PKCE
  and redirect labs, discovery planning, challenge parsing, DCQL probing, and a `health()` document
  that reports the version of every layer.
* `server.py` — `ThreadingHTTPServer`, a dictionary of POST endpoints plus two GETs, static files
  from `ui/` and `ui/dist/`, SPA fallback, no caching for API responses.
* `cli.py` — `serve`, `analyze`, `health`.

Errors keep their origin: an authlas `CoreError` reaches the interface with `type: "CoreError"` and
`kind: "algorithm"`, so a policy refusal reads differently from a broken token.

## Interface (`ui/`)

* No framework, no bundler: `tsc` emits ES2020 modules, `index.html` loads `/dist/main.js`, the
  browser resolves the rest. `dom.ts` is a small `h()` helper; `ui.ts` holds cards, code blocks,
  badges and fields; each view is a function returning a detached element.
* State is local to a view instance; navigation rebuilds the view, which is cheap and makes stale
  state impossible.
* Visual system: one dark instrument palette, cyan for interaction and violet for the UI layer,
  monospace for anything that is data, severity colours only on severity.

## Data flow of an analysis

1. The interface posts the token plus optional issuer, audience, key id or JWKS.
2. `workbench.analyze` asks the core for the structural scan.
3. The core parses header and payload and returns both, plus the risk report.
4. If a key and a policy are present, authlas verifies signature, `iss`, `aud` and `exp` under an
   algorithm allow-list; the outcome or the typed error is attached.
5. For SD-JWTs the core recomputes every disclosure digest and maps it to `_sd`.
6. The interface renders score, findings, decoded parts, segment table and verdict.
