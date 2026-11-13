"""Python-side tests: the pipeline, the two thumbprint implementations, SD-JWT, HTTP."""
from __future__ import annotations

import json
import threading
import urllib.request

import pytest

from authlens.workbench import bench


@pytest.fixture(scope="module")
def wb():
    return bench()


def test_native_and_authlas_thumbprints_agree(wb):
    for key in wb.key_list():
        assert key["thumbprint"] == key["thumbprint_native"]
        assert len(key["thumbprint"]) == 43


def test_clean_token_verifies(wb):
    sample = next(s for s in wb.samples if s["id"] == "clean")
    result = wb.analyze(sample["token"], key_id=wb.default_key_id,
                        issuer="https://issuer.example", audience="api://orders")
    assert result["verification"]["ok"] is True
    assert result["verification"]["claims"]["sub"] == "alice@example.com"
    assert result["risk"]["grade"] == "A"


def test_hostile_token_is_graded_and_refused(wb):
    sample = next(s for s in wb.samples if s["id"] == "hostile")
    result = wb.analyze(sample["token"], key_id=wb.default_key_id,
                        issuer="https://legacy.example", audience="api://orders")
    ids = {f["id"] for f in result["risk"]["findings"]}
    assert {"alg.symmetric", "header.jku", "header.kid.traversal", "claim.exp.missing"} <= ids
    assert result["risk"]["grade"] == "F"
    assert result["verification"]["ok"] is False
    assert result["verification"]["kind"] == "alg-not-allowed"


def test_wrong_audience_is_rejected(wb):
    sample = next(s for s in wb.samples if s["id"] == "clean")
    result = wb.analyze(sample["token"], key_id=wb.default_key_id,
                        issuer="https://issuer.example", audience="api://other")
    assert result["verification"]["ok"] is False
    assert result["verification"]["type"] == "CoreError"


def test_sdjwt_issue_present_verify(wb):
    issued = wb.sd_issue({"iss": "https://issuer.example", "sub": "a@example.com",
                          "given_name": "Alice", "age_over_18": True},
                         hide=["given_name", "age_over_18"], decoys=2)
    sd = issued["analysis"]["sd"]
    assert sd["match"]["matched"] == 2
    assert sd["match"]["digest_count"] == 4           # two claims + two decoys
    presented = wb.sd_present(issued["sd_jwt"], [0])
    assert presented["revealed"] == 1
    verified = wb.sd_verify(issued["sd_jwt"], key_id=wb.default_key_id)
    assert verified["ok"] is True
    assert verified["claims"]["given_name"] == "Alice"


def test_pkce_and_redirect_policy(wb):
    out = wb.pkce_lab({"redirect": "http://app.example/cb",
                       "native": "com.example.app:/cb",
                       "registered": "https://app.example/cb",
                       "presented": "https://app.example/cb?code=1&state=2",
                       "requested": "openid admin", "allowed": "openid"})
    assert out["pkce"]["ok"] is True
    assert out["redirects"][0]["ok"] is False        # plain http on a public host
    assert out["redirects"][1]["ok"] is True          # native scheme
    assert out["redirect_match"] is False             # not an exact match
    assert out["scope"]["excess"] == ["admin"]


def test_http_api_serves_health_and_analysis(wb):
    from authlens.server import Handler, ThreadingHTTPServer

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        with urllib.request.urlopen(f"{base}/api/health") as res:
            health = json.load(res)
        assert health["layers"]["core"]["language"] == "C++17"
        assert health["layers"]["main"]["backend"]
        sample = wb.samples[0]["token"]
        req = urllib.request.Request(f"{base}/api/analyze", method="POST",
                                     data=json.dumps({"token": sample}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as res:
            analysis = json.load(res)
        assert analysis["format"] in ("jws", "sd-jwt")
        assert analysis["risk"]["score"] >= 0
    finally:
        httpd.shutdown()
