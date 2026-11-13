# AuthLens

**An OAuth 2.0 / JOSE inspection workbench built in three layers.**

AuthLens reads a token the way an attacker and a verifier both would: the C++ core measures the
bytes, `authlas-python` applies the protocol rules, and the TypeScript interface shows you the two
answers side by side.

```
        ┌──────────────────────────── TypeScript interface (ui/) ────────────────────────────┐
        │  token analyser · keyring & signing · SD-JWT studio · protocol console             │
        └──────────────────────────────────────┬─────────────────────────────────────────────┘
                                               │ JSON over HTTP
        ┌──────────────────────────────────────▼─────────────────────────────────────────────┐
        │  Python main layer (authlens/)                                                     │
        │  workbench.py  session keyring, samples, verification policy, SD-JWT flows          │
        │  server.py     threaded stdlib HTTP API + static bundle                            │
        │  ── authlas-python 0.1.0 (Rust core behind a C++ transport, AWS-LC backend) ──      │
        └──────────────────────────────────────┬─────────────────────────────────────────────┘
                                               │ ctypes, C ABI
        ┌──────────────────────────────────────▼─────────────────────────────────────────────┐
        │  C++17 core (core/authlens_core.cpp → libauthlens_core.so)                         │
        │  JSON parser · base64url · segment offsets · RFC 7638 thumbprints · SHA-2 digests  │
        │  claim-risk heuristics                                                             │
        └────────────────────────────────────────────────────────────────────────────────────┘
```

## Why the split

* **C++ does what must be exact and cheap.** A token is bytes before it is a protocol object. The
  core decodes every segment, records offsets and decoded sizes, parses header and payload with its
  own small JSON parser, computes RFC 7638 thumbprints and SD-JWT disclosure digests, and runs 20+
  claim/header heuristics. It is independent of the Python runtime, which makes it a useful second
  opinion on anything the library reports.
* **Python owns protocol policy.** Signature checks, allow-lists, issuer/audience binding, PKCE,
  redirect policy, discovery order, DCQL and SD-JWT verification come from `authlas-python`.
  AuthLens never re-implements a security rule the library already enforces.
* **TypeScript owns the human interface.** Plain ES modules compiled by `tsc`: no framework, no
  bundler, no runtime dependency — four views, one stylesheet.

## Quickstart

```bash
pip install --user authlas-python      # the protocol layer
make core                              # g++ -shared → authlens/libauthlens_core.so
make ui                                # tsc → ui/dist/*.js
python3 -m authlens.cli serve --port 8770
# open http://127.0.0.1:8770
```

Check the machine itself:

```bash
make test        # native C++ checks + python unit tests
python3 -m authlens.cli health
```

## What each view does

| View | What you get |
| --- | --- |
| **Token analyser** | Native segment table (offset, chars, decoded bytes, base64 validity), decoded header/payload, a 0–100 risk score with graded findings, and an authlas verdict once you supply an issuer, an audience and a key (session keyring or pasted JWKS). |
| **Keys & signing** | In-memory EC keyring (P-256/384/521). Every key shows **two** independently computed RFC 7638 thumbprints — one from `authlas.core.thumbprint`, one from the C++ core — and whether they agree. Mint tokens with arbitrary claims and re-analyse them immediately. |
| **SD-JWT studio** | Issue an SD-JWT with hidden claims and decoys, see every disclosure digest matched against the issuer's `_sd` array (computed natively), then build a presentation that reveals only what you tick and verify it again through authlas. |
| **Protocol console** | PKCE generation/verification, redirect-URI policy (web vs native), exact-match redirect comparison, scope excess detection, the discovery URL order for an issuer, `WWW-Authenticate` challenge parsing and rebuilding, and a DCQL satisfiability probe. |

## Samples that ship with a session

* **Access token** — ES256, scoped, five minutes of life.
* **Hostile token** — `HS256`, remote `jku`, `kid: ../../etc/passwd`, no `exp`, `scope: admin:*`.
  It is deliberately unsigned and the analyser says so without ever verifying it.
* **Expired ID token** — well-formed, `exp` in the past.
* **SD-JWT credential** — two hidden claims plus one decoy.

## Native C ABI

```c
const char* al_version(void);
const char* al_last_error(void);
int al_scan(const char* compact, char* out, int cap);                        /* structure */
int al_thumbprint(const char* jwk_json, char* out, int cap);                 /* RFC 7638  */
int al_sd_digests(const char* disclosures_json, const char* hash, char* out, int cap);
int al_sd_match(const char* sd_array_json, const char* disclosures, const char* hash, char* out, int cap);
int al_risk(const char* header_json, const char* payload_json, char* out, int cap);
```

Every entry point returns the number of bytes written or a negative code, and the reason is always
available from `al_last_error()` on the same thread. No exceptions cross the boundary.

## Tests

```
$ ./build_test_core
authlens core 1.0.0
  ok   kid traversal is reported
  ok   symmetric alg is reported
  ok   embedded jwk is reported
  ok   missing exp is reported
  ok   score lands in the bottom grades
  ok   clean token has no traversal finding
  ok   thumbprint computed
  ok   thumbprint is 43 chars of unpadded base64url
  ok   SD-JWT format detected
  ok   one disclosure decoded
all native checks passed
```

`make test` also runs the Python suite (`tests/`): thumbprint agreement between the two
implementations, the analysis pipeline, SD-JWT issue→present→verify and the HTTP API.

## Layout

```
core/          C++17 core, C ABI header, native tests
authlens/      Python: coreffi (ctypes), workbench (authlas), server (HTTP), cli
ui/            TypeScript sources, tsconfig, compiled dist/, index.html, styles.css
tests/         Python unit tests
docs/          ARCHITECTURE.md
```

## License

MIT.
