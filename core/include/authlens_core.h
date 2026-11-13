/* AuthLens native core — public C ABI.
 *
 * The Python layer loads this shared library through ctypes. Every entry
 * point returns the number of bytes written into `out` (NUL not counted) or a
 * negative error code; the reason is available from al_last_error(). All
 * output is UTF-8 JSON except al_version()/al_thumbprint().
 */
#ifndef AUTHLENS_CORE_H
#define AUTHLENS_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Semantic version of the native core, e.g. "1.0.0". */
const char* al_version(void);

/* Reason for the last negative return on this thread ("" when none). */
const char* al_last_error(void);

/* Structural scan of a compact JWS / JWE / SD-JWT.
 * Reports segment offsets, decoded sizes, parsed header/payload JSON and the
 * disclosure list, without trusting any of it. */
int al_scan(const char* compact, char* out, int cap);

/* RFC 7638 JWK thumbprint (base64url SHA-256 of the canonical members). */
int al_thumbprint(const char* jwk_json, char* out, int cap);

/* SHA-2 digests of SD-JWT disclosures: input is a JSON array of base64url
 * disclosure strings; output maps index -> digest so a holder's view can be
 * checked against the issuer's `_sd` array. */
int al_sd_digests(const char* disclosures_json, const char* hash_alg, char* out, int cap);

/* Match issuer `_sd` digests against disclosures.
 * Input: JSON array of `_sd` digests, JSON array of disclosures. */
int al_sd_match(const char* sd_array_json, const char* disclosures_json,
                const char* hash_alg, char* out, int cap);

/* Claim-level risk heuristics over a decoded header and payload object.
 * Returns {"findings":[{id,severity,title,detail}], "score":int, "grade":str}. */
int al_risk(const char* header_json, const char* payload_json, char* out, int cap);

#ifdef __cplusplus
}
#endif
#endif
