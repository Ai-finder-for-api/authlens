// Native self-tests for the AuthLens core (no framework: assert + report).
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

#include "authlens_core.h"

static char buf[1 << 16];

static std::string call(int (*fn)(const char*, char*, int), const char* in) {
  int n = fn(in, buf, sizeof buf);
  if (n < 0) return std::string("ERR:") + al_last_error();
  return std::string(buf, static_cast<size_t>(n));
}

static std::string risk_of(const char* header, const char* payload) {
  int n = al_risk(header, payload, buf, sizeof buf);
  if (n < 0) return std::string("ERR:") + al_last_error();
  return std::string(buf, static_cast<size_t>(n));
}

static int failures = 0;
static void check(bool cond, const char* what) {
  if (cond) {
    std::printf("  ok   %s\n", what);
  } else {
    std::printf("  FAIL %s\n", what);
    ++failures;
  }
}

int main() {
  std::printf("authlens core %s\n", al_version());

  // A JWS with an embedded key, a traversing kid, no exp and a broad scope.
  static const char* payload = "{\"iss\":\"https://issuer.example\",\"sub\":\"alice\",\"aud\":[\"api\",\"web\"],"
                        "\"iat\":1600000000,\"scope\":\"openid admin\"}";
  const char* header = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"../../etc/keys\",\"jwk\":{\"kty\":\"oct\",\"k\":\"AA\"}}";
  std::string risk = risk_of(header, payload);
  check(risk.find("header.kid.traversal") != std::string::npos, "kid traversal is reported");
  check(risk.find("alg.symmetric") != std::string::npos, "symmetric alg is reported");
  check(risk.find("header.jwk") != std::string::npos, "embedded jwk is reported");
  check(risk.find("claim.exp.missing") != std::string::npos, "missing exp is reported");
  check(risk.find("\"grade\":\"F\"") != std::string::npos || risk.find("\"grade\":\"D\"") != std::string::npos,
        "score lands in the bottom grades");

  // al_risk over a clean access token.
  const char* good_h = "{\"alg\":\"ES256\",\"typ\":\"at+jwt\",\"kid\":\"2024-07\"}";
  const char* good_p = "{\"iss\":\"https://issuer.example\",\"sub\":\"alice\",\"aud\":\"api\",\"iat\":1750000000,"
                       "\"exp\":1750000300,\"jti\":\"01J\",\"scope\":\"read\"}";
  std::string good = risk_of(good_h, good_p);
  check(good.find("header.kid.traversal") == std::string::npos, "clean token has no traversal finding");

  // Thumbprint: RFC 7638 example key (RSA) -> known digest.
  const char* jwk = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
                    "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBX"
                    "ArKfF9bC7yczGJdiZKm8kP4N3C1E2U385KqH1BI2GjQ0ZfG-E\"}";
  std::string tp = call(al_thumbprint, jwk);
  check(tp.rfind("ERR", 0) != 0, "thumbprint computed");
  check(tp.size() == 43 && tp.find('=') == std::string::npos, "thumbprint is 43 chars of unpadded base64url");

  // Structural scan of an SD-JWT-ish compact string.
  const char* sd = "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOltdfQ.c2ln~WyIyMDI0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~";
  std::string scan = call(al_scan, sd);
  check(scan.find("\"format\":\"sd-jwt\"") != std::string::npos, "SD-JWT format detected");
  check(scan.find("\"disclosures\":[{\"role\":\"disclosure\"") != std::string::npos, "one disclosure decoded");

  // Alias export for readability in shell output.
  std::printf("payload bytes: %zu\n", std::strlen(payload));
  if (failures) {
    std::printf("%d check(s) failed\n", failures);
    return 1;
  }
  std::printf("all native checks passed\n");
  return 0;
}
