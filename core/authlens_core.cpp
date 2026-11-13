// AuthLens native core.
//
// Everything here works on untrusted input: tokens, JWKs and disclosures are
// parsed but never trusted. The point of doing this in C++ is that the byte
// level structure (segment offsets, decoded lengths, digests) is cheap to
// produce at high volume and stays independent from the Python protocol layer,
// which is a useful cross-check when auditing a token.
#include "authlens_core.h"

#include <openssl/evp.h>

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <utility>
#include <vector>

namespace {

thread_local std::string g_err;
constexpr const char* kVersion = "1.0.0";

void fail(const std::string& msg) { g_err = msg; }

/* ------------------------------------------------------------------ JSON -- */

struct JVal;
using JArr = std::vector<JVal>;
using JObj = std::vector<std::pair<std::string, JVal>>;

struct JVal {
  enum Kind { NUL, BOOL, NUM, STR, ARR, OBJ };
  Kind kind = NUL;
  bool boolean = false;
  double num = 0;
  std::string str;
  JArr arr;
  JObj obj;

  bool is_obj() const { return kind == OBJ; }
  bool is_arr() const { return kind == ARR; }
  bool is_str() const { return kind == STR; }
  const JVal* get(const std::string& key) const {
    if (kind != OBJ) return nullptr;
    for (const auto& kv : obj)
      if (kv.first == key) return &kv.second;
    return nullptr;
  }
  bool has(const std::string& key) const { return get(key) != nullptr; }
};

struct Parser {
  const std::string& s;
  size_t i = 0;
  std::string err;

  explicit Parser(const std::string& src) : s(src) {}

  void ws() {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
  }

  bool value(JVal& v, int depth) {
    if (depth > 64) { err = "nesting too deep"; return false; }
    ws();
    if (i >= s.size()) { err = "unexpected end of input"; return false; }
    char c = s[i];
    if (c == '{') return object(v, depth);
    if (c == '[') return array(v, depth);
    if (c == '"') { v.kind = JVal::STR; return string(v.str); }
    if (c == 't') { if (s.compare(i, 4, "true")) return bad(); i += 4; v.kind = JVal::BOOL; v.boolean = true; return true; }
    if (c == 'f') { if (s.compare(i, 5, "false")) return bad(); i += 5; v.kind = JVal::BOOL; v.boolean = false; return true; }
    if (c == 'n') { if (s.compare(i, 4, "null")) return bad(); i += 4; v.kind = JVal::NUL; return true; }
    return number(v);
  }

  bool bad() { err = "invalid literal"; return false; }

  bool object(JVal& v, int depth) {
    v.kind = JVal::OBJ;
    ++i;  // '{'
    ws();
    if (i < s.size() && s[i] == '}') { ++i; return true; }
    while (true) {
      ws();
      std::string key;
      if (i >= s.size() || s[i] != '"') { err = "object key must be a string"; return false; }
      if (!string(key)) return false;
      ws();
      if (i >= s.size() || s[i] != ':') { err = "expected ':'"; return false; }
      ++i;
      JVal child;
      if (!value(child, depth + 1)) return false;
      v.obj.emplace_back(std::move(key), std::move(child));
      ws();
      if (i < s.size() && s[i] == ',') { ++i; continue; }
      if (i < s.size() && s[i] == '}') { ++i; return true; }
      err = "expected ',' or '}'";
      return false;
    }
  }

  bool array(JVal& v, int depth) {
    v.kind = JVal::ARR;
    ++i;  // '['
    ws();
    if (i < s.size() && s[i] == ']') { ++i; return true; }
    while (true) {
      JVal child;
      if (!value(child, depth + 1)) return false;
      v.arr.emplace_back(std::move(child));
      ws();
      if (i < s.size() && s[i] == ',') { ++i; continue; }
      if (i < s.size() && s[i] == ']') { ++i; return true; }
      err = "expected ',' or ']'";
      return false;
    }
  }

  static void put_utf8(std::string& out, unsigned cp) {
    if (cp < 0x80) {
      out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  bool hex4(unsigned& out) {
    if (i + 4 > s.size()) { err = "truncated \\u escape"; return false; }
    out = 0;
    for (int k = 0; k < 4; ++k) {
      char c = s[i++];
      out <<= 4;
      if (c >= '0' && c <= '9') out |= static_cast<unsigned>(c - '0');
      else if (c >= 'a' && c <= 'f') out |= static_cast<unsigned>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') out |= static_cast<unsigned>(c - 'A' + 10);
      else { err = "bad hex digit in \\u escape"; return false; }
    }
    return true;
  }

  bool string(std::string& out) {
    ++i;  // opening quote
    while (i < s.size()) {
      unsigned char c = static_cast<unsigned char>(s[i++]);
      if (c == '"') return true;
      if (c != '\\') { out.push_back(static_cast<char>(c)); continue; }
      if (i >= s.size()) break;
      char e = s[i++];
      switch (e) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          unsigned cp = 0;
          if (!hex4(cp)) return false;
          if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < s.size() && s[i] == '\\' && s[i + 1] == 'u') {
            size_t save = i;
            i += 2;
            unsigned lo = 0;
            if (!hex4(lo)) return false;
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
              cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else {
              i = save;  // lone surrogate: emit replacement below
              cp = 0xFFFD;
            }
          }
          put_utf8(out, cp);
          break;
        }
        default: err = "bad escape"; return false;
      }
    }
    err = "unterminated string";
    return false;
  }

  bool number(JVal& v) {
    size_t start = i;
    if (i < s.size() && (s[i] == '-' || s[i] == '+')) ++i;
    while (i < s.size() && (std::isdigit(static_cast<unsigned char>(s[i])) || s[i] == '.' ||
                            s[i] == 'e' || s[i] == 'E' || s[i] == '+' || s[i] == '-'))
      ++i;
    if (i == start) { err = "unexpected character"; return false; }
    v.kind = JVal::NUM;
    v.num = std::strtod(s.substr(start, i - start).c_str(), nullptr);
    return true;
  }
};

void dump(const JVal& v, std::string& out);

void dump_string(const std::string& s, std::string& out) {
  out.push_back('"');
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out.push_back('"');
}

void dump_number(double n, std::string& out) {
  char buf[40];
  if (n == std::floor(n) && std::fabs(n) < 1e15) {
    std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(n));
  } else {
    std::snprintf(buf, sizeof buf, "%.17g", n);
  }
  out += buf;
}

void dump(const JVal& v, std::string& out) {
  switch (v.kind) {
    case JVal::NUL: out += "null"; break;
    case JVal::BOOL: out += v.boolean ? "true" : "false"; break;
    case JVal::NUM: dump_number(v.num, out); break;
    case JVal::STR: dump_string(v.str, out); break;
    case JVal::ARR: {
      out.push_back('[');
      for (size_t k = 0; k < v.arr.size(); ++k) {
        if (k) out.push_back(',');
        dump(v.arr[k], out);
      }
      out.push_back(']');
      break;
    }
    case JVal::OBJ: {
      out.push_back('{');
      for (size_t k = 0; k < v.obj.size(); ++k) {
        if (k) out.push_back(',');
        dump_string(v.obj[k].first, out);
        out.push_back(':');
        dump(v.obj[k].second, out);
      }
      out.push_back('}');
      break;
    }
  }
}

bool parse_json(const std::string& text, JVal& out) {
  Parser p(text);
  if (!p.value(out, 0)) return false;
  p.ws();
  if (p.i != text.size()) { fail("trailing data after JSON value"); return false; }
  return true;
}

/* -------------------------------------------------------------- base64url -- */

const char* kB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string b64url_encode(const std::string& raw) {
  std::string out;
  out.reserve((raw.size() + 2) / 3 * 4);
  size_t i = 0;
  while (i + 2 < raw.size()) {
    unsigned n = (static_cast<unsigned char>(raw[i]) << 16) |
                 (static_cast<unsigned char>(raw[i + 1]) << 8) |
                 static_cast<unsigned char>(raw[i + 2]);
    out.push_back(kB64[(n >> 18) & 63]);
    out.push_back(kB64[(n >> 12) & 63]);
    out.push_back(kB64[(n >> 6) & 63]);
    out.push_back(kB64[n & 63]);
    i += 3;
  }
  size_t rest = raw.size() - i;
  if (rest == 1) {
    unsigned n = static_cast<unsigned char>(raw[i]) << 16;
    out.push_back(kB64[(n >> 18) & 63]);
    out.push_back(kB64[(n >> 12) & 63]);
  } else if (rest == 2) {
    unsigned n = (static_cast<unsigned char>(raw[i]) << 16) |
                 (static_cast<unsigned char>(raw[i + 1]) << 8);
    out.push_back(kB64[(n >> 18) & 63]);
    out.push_back(kB64[(n >> 12) & 63]);
    out.push_back(kB64[(n >> 6) & 63]);
  }
  return out;
}

int b64val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-' || c == '+') return 62;
  if (c == '_' || c == '/') return 63;
  return -1;
}

bool b64url_decode(const std::string& in, std::string& out) {
  unsigned buf = 0;
  int bits = 0;
  for (char c : in) {
    if (c == '=' || c == '\n' || c == '\r') continue;
    int v = b64val(c);
    if (v < 0) return false;
    buf = (buf << 6) | static_cast<unsigned>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buf >> bits) & 0xFF));
    }
  }
  return true;
}

bool looks_like_json(const std::string& s) {
  for (char c : s) {
    if (std::isspace(static_cast<unsigned char>(c))) continue;
    return c == '{' || c == '[' || c == '"' || c == 't' || c == 'f' || c == 'n' ||
           c == '-' || std::isdigit(static_cast<unsigned char>(c));
  }
  return false;
}

/* ---------------------------------------------------------------- digest -- */

const EVP_MD* digest_for(const std::string& name) {
  std::string a;
  for (char c : name) a.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  if (a.empty() || a == "sha-256" || a == "sha256") return EVP_sha256();
  if (a == "sha-384" || a == "sha384") return EVP_sha384();
  if (a == "sha-512" || a == "sha512") return EVP_sha512();
  if (a == "sha-1" || a == "sha1") return EVP_sha1();
  return nullptr;
}

bool sha(const std::string& data, const std::string& alg, std::string& raw) {
  const EVP_MD* md = digest_for(alg);
  if (!md) { fail("unsupported hash algorithm: " + alg); return false; }
  unsigned char buf[EVP_MAX_MD_SIZE];
  unsigned len = 0;
  if (EVP_Digest(data.data(), data.size(), buf, &len, md, nullptr) != 1) {
    fail("digest failed");
    return false;
  }
  raw.assign(reinterpret_cast<char*>(buf), len);
  return true;
}

/* ------------------------------------------------------------------ misc -- */

std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

std::vector<std::string> split(const std::string& s, char sep) {
  std::vector<std::string> out;
  size_t start = 0;
  while (true) {
    size_t p = s.find(sep, start);
    if (p == std::string::npos) { out.push_back(s.substr(start)); break; }
    out.push_back(s.substr(start, p - start));
    start = p + 1;
  }
  return out;
}

int emit(const std::string& text, char* out, int cap) {
  if (cap <= 0 || out == nullptr) { fail("null output buffer"); return -3; }
  int need = static_cast<int>(text.size());
  if (need + 1 > cap) { fail("output buffer too small"); return -2; }
  std::memcpy(out, text.data(), text.size());
  out[text.size()] = '\0';
  return need;
}

void append_segment(std::string& out, const char* role, const std::string& part, size_t offset,
                    bool parse_json_body, int index = -1) {
  std::string decoded;
  bool b64_ok = b64url_decode(part, decoded);
  out += "{\"role\":";
  dump_string(role, out);
  out += ",\"index\":";
  out += std::to_string(index);
  out += ",\"offset\":" + std::to_string(offset);
  out += ",\"length\":" + std::to_string(part.size());
  out += ",\"bytes\":" + std::to_string(decoded.size());
  out += ",\"b64_ok\":";
  out += b64_ok ? "true" : "false";
  out += ",\"json\":";
  if (b64_ok && parse_json_body) {
    JVal v;
    if (looks_like_json(decoded) && parse_json(decoded, v)) {
      dump(v, out);
    } else {
      out += "null";
    }
  } else {
    out += "null";
  }
  out += "}";
}

/* -------------------------------------------------------------- risk scan -- */

struct Finding {
  const char* id;
  const char* severity;
  std::string title;
  std::string detail;
};

void add(std::vector<Finding>& v, const char* id, const char* sev, std::string title, std::string detail) {
  v.push_back(Finding{id, sev, std::move(title), std::move(detail)});
}

const char* str_at(const JVal& o, const char* key) {
  const JVal* v = o.get(key);
  return v && v->is_str() ? v->str.c_str() : nullptr;
}

bool num_at(const JVal& o, const char* key, double& out) {
  const JVal* v = o.get(key);
  if (!v || v->kind != JVal::NUM) return false;
  out = v->num;
  return true;
}

}  // namespace

/* ----------------------------------------------------------- entry points -- */

extern "C" {

const char* al_version(void) { return kVersion; }

const char* al_last_error(void) { return g_err.c_str(); }

int al_scan(const char* compact, char* out, int cap) {
  g_err.clear();
  if (!compact) { fail("null token"); return -1; }
  std::string token = trim(compact);
  if (token.empty()) { fail("empty token"); return -1; }

  bool sd = token.find('~') != std::string::npos;
  std::vector<std::string> parts = split(token, sd ? '~' : '.');
  std::string issuer_part = sd ? parts[0] : token;
  int dots = 0;
  for (char c : issuer_part) dots += (c == '.');

  std::string out_json = "{";
  out_json += "\"nbytes\":" + std::to_string(token.size());
  out_json += ",\"format\":";
  const char* format = "unknown";
  if (sd) format = "sd-jwt";
  else if (dots == 2) format = "jws";
  else if (dots == 4) format = "jwe";
  dump_string(format, out_json);

  // --- shared JOSE header of the outer object
  std::vector<std::string> jose = split(issuer_part, '.');
  out_json += ",\"segments\":[";
  size_t offset = 0;
  static const char* kJwsRoles[] = {"header", "payload", "signature"};
  static const char* kJweRoles[] = {"header", "encrypted_key", "iv", "ciphertext", "tag"};
  const char* const* roles = (dots == 4) ? kJweRoles : kJwsRoles;
  int nseg = static_cast<int>(jose.size());
  for (int k = 0; k < nseg && k < 5; ++k) {
    if (k) out_json.push_back(',');
    append_segment(out_json, k < 5 ? roles[k] : "segment", jose[k], offset, k <= 1);
    offset += jose[k].size() + 1;
  }
  out_json += "]";

  // --- disclosures (SD-JWT only)
  out_json += ",\"disclosures\":[";
  bool first = true;
  int kb_index = -1;
  if (sd) {
    for (size_t k = 1; k < parts.size(); ++k) {
      if (parts[k].empty()) continue;
      if (k + 1 == parts.size() && parts[k].find('.') != std::string::npos) {
        kb_index = static_cast<int>(k);  // trailing key binding JWT
        continue;
      }
      if (!first) out_json.push_back(',');
      first = false;
      append_segment(out_json, "disclosure", parts[k], 0, true, static_cast<int>(k - 1));
    }
  }
  out_json += "]";
  out_json += ",\"key_binding\":";
  if (kb_index >= 0) {
    std::string kbj;
    append_segment(kbj, "key_binding", parts[kb_index], 0, true);
    out_json += kbj;
  } else {
    out_json += "null";
  }

  // --- a few structural observations that are cheap and genuinely useful
  out_json += ",\"notes\":[";
  std::string decoded_header;
  bool header_ok = nseg > 0 && b64url_decode(jose[0], decoded_header);
  JVal hdr;
  bool hdr_parsed = header_ok && parse_json(decoded_header, hdr);
  std::string notes;
  auto note = [&](const std::string& n) {
    if (!notes.empty()) notes += ",";
    dump_string(n, notes);
  };
  if (!header_ok) note("header is not valid base64url");
  else if (!hdr_parsed) note("header is not valid JSON");
  if (hdr_parsed && hdr.has("crit")) note("header declares crit parameters — every one must be understood");
  if (hdr_parsed && hdr.has("jwk")) note("header carries an embedded jwk — the verifier's key choice is attacker-influenced");
  if (hdr_parsed && (hdr.has("jku") || hdr.has("x5u"))) note("header points at a remote key set (jku/x5u)");
  if (nseg == 3 && jose[0].size() + jose[1].size() + jose[2].size() + 2 != issuer_part.size())
    note("segment lengths do not add up to the input length");
  out_json += notes;
  out_json += "]";
  out_json += "}";
  return emit(out_json, out, cap);
}

int al_thumbprint(const char* jwk_json, char* out, int cap) {
  g_err.clear();
  if (!jwk_json) { fail("null JWK"); return -1; }
  JVal jwk;
  if (!parse_json(jwk_json, jwk) || !jwk.is_obj()) { fail("JWK is not a JSON object"); return -1; }
  const char* kty = str_at(jwk, "kty");
  if (!kty) { fail("JWK has no kty"); return -1; }

  // RFC 7638 section 3.2: required members only, lexicographic order, no
  // whitespace. We rebuild the object rather than trusting the input order.
  JVal canon;
  canon.kind = JVal::OBJ;
  auto take = [&](const char* name) -> bool {
    const JVal* v = jwk.get(name);
    if (!v || !v->is_str()) { fail(std::string("JWK is missing required member '") + name + "'"); return false; }
    canon.obj.emplace_back(name, *v);
    return true;
  };
  std::string kind(kty);
  if (kind == "EC") {
    if (!take("crv") || !take("kty") || !take("x") || !take("y")) return -1;
  } else if (kind == "RSA") {
    if (!take("e") || !take("kty") || !take("n")) return -1;
  } else if (kind == "OKP") {
    if (!take("crv") || !take("kty") || !take("x")) return -1;
  } else if (kind == "oct") {
    if (!take("k") || !take("kty")) return -1;
  } else {
    fail("unsupported kty: " + kind);
    return -1;
  }
  std::string canonical;
  dump(canon, canonical);
  std::string raw;
  if (!sha(canonical, "sha-256", raw)) return -1;
  return emit(b64url_encode(raw), out, cap);
}

int al_sd_digests(const char* disclosures_json, const char* hash_alg, char* out, int cap) {
  g_err.clear();
  if (!disclosures_json) { fail("null disclosures"); return -1; }
  JVal arr;
  if (!parse_json(disclosures_json, arr) || !arr.is_arr()) { fail("disclosures must be a JSON array"); return -1; }
  std::string alg = hash_alg && *hash_alg ? hash_alg : "sha-256";
  std::string o = "{\"hash\":";
  dump_string(alg, o);
  o += ",\"digests\":[";
  for (size_t k = 0; k < arr.arr.size(); ++k) {
    if (k) o.push_back(',');
    const JVal& d = arr.arr[k];
    if (!d.is_str()) { fail("each disclosure must be a string"); return -1; }
    std::string raw, dig;
    if (!sha(d.str, alg, raw)) return -1;
    dig = b64url_encode(raw);
    o += "{\"index\":" + std::to_string(k) + ",\"bytes\":" + std::to_string(d.str.size()) +
         ",\"digest\":";
    dump_string(dig, o);
    o += ",\"json\":";
    std::string decoded;
    JVal dv;
    if (b64url_decode(d.str, decoded) && parse_json(decoded, dv)) dump(dv, o);
    else o += "null";
    o += "}";
  }
  o += "]}";
  return emit(o, out, cap);
}

int al_sd_match(const char* sd_array_json, const char* disclosures_json, const char* hash_alg,
                char* out, int cap) {
  g_err.clear();
  if (!sd_array_json || !disclosures_json) { fail("null input"); return -1; }
  JVal sd, disc;
  if (!parse_json(sd_array_json, sd) || !sd.is_arr()) { fail("_sd must be a JSON array of digests"); return -1; }
  if (!parse_json(disclosures_json, disc) || !disc.is_arr()) { fail("disclosures must be a JSON array"); return -1; }
  std::string alg = hash_alg && *hash_alg ? hash_alg : "sha-256";

  std::vector<std::string> digests;
  for (const JVal& d : disc.arr) {
    if (!d.is_str()) { fail("each disclosure must be a string"); return -1; }
    std::string raw;
    if (!sha(d.str, alg, raw)) return -1;
    digests.push_back(b64url_encode(raw));
  }
  std::string o = "{\"hash\":";
  dump_string(alg, o);
  o += ",\"pairs\":[";
  std::vector<bool> used(digests.size(), false);
  int matched = 0, idx = 0;
  for (const JVal& s : sd.arr) {
    if (!s.is_str()) { fail("_sd entries must be strings"); return -1; }
    if (idx) o.push_back(',');
    o += "{\"digest\":";
    dump_string(s.str, o);
    int found = -1;
    for (size_t k = 0; k < digests.size(); ++k)
      if (digests[k] == s.str) { found = static_cast<int>(k); used[k] = true; break; }
    o += ",\"disclosure\":";
    if (found >= 0) { o += std::to_string(found); ++matched; }
    else o += "null";
    o += "}";
    ++idx;
  }
  o += "],\"matched\":" + std::to_string(matched) + ",\"digest_count\":" +
       std::to_string(sd.arr.size()) + ",\"unused_disclosures\":[";
  bool first = true;
  for (size_t k = 0; k < used.size(); ++k) {
    if (used[k]) continue;
    if (!first) o.push_back(',');
    first = false;
    o += std::to_string(k);
  }
  o += "]}";
  return emit(o, out, cap);
}

int al_risk(const char* header_json, const char* payload_json, char* out, int cap) {
  g_err.clear();
  JVal h, p;
  if (!header_json || !parse_json(header_json, h) || !h.is_obj()) { fail("header is not a JSON object"); return -1; }
  if (!payload_json || !parse_json(payload_json, p) || !p.is_obj()) { fail("payload is not a JSON object"); return -1; }

  std::vector<Finding> f;
  const char* alg = str_at(h, "alg");
  if (!alg) add(f, "header.alg.missing", "critical", "No alg in the header",
                "A token without an algorithm leaves the verifier to guess; reject it.");
  else {
    std::string a(alg);
    if (a == "none")
      add(f, "alg.none", "critical", "Unsecured JWS (alg: none)",
          "The signature is empty. Any party can mint this token; only accept it in a closed test.");
    else if (a.size() > 2 && a[0] == 'H' && a[1] == 'S')
      add(f, "alg.symmetric", "high", "Symmetric algorithm " + a,
          "Every verifier holds the signing secret, so any of them can forge tokens. Prefer an asymmetric algorithm.");
  }
  if (h.has("jku")) add(f, "header.jku", "high", "Remote key set (jku)",
                        "The key is fetched from a URL the token chooses; allow-list the host before trusting it.");
  if (h.has("x5u")) add(f, "header.x5u", "high", "Remote certificate chain (x5u)",
                        "Same risk as jku: the token picks where the trust anchor comes from.");
  if (h.has("jwk")) add(f, "header.jwk", "high", "Embedded key (jwk)",
                        "A self-signed token is valid against its own key. Only accept embedded keys under an allow-listed issuer.");
  if (h.has("crit")) add(f, "header.crit", "medium", "Critical header extensions",
                         "Every crit parameter must be understood and enforced; otherwise the token must be rejected.");
  if (const char* kid = str_at(h, "kid")) {
    std::string k(kid);
    if (k.find("..") != std::string::npos || k.find('/') != std::string::npos || k.find('\\') != std::string::npos)
      add(f, "header.kid.traversal", "high", "kid looks like a path",
          "kid is often used to build a key file name; '" + k + "' can escape the key directory.");
  } else {
    add(f, "header.kid.absent", "info", "No kid",
        "Fine for single-key issuers, awkward for rotation and for JWKS lookups.");
  }
  if (const char* typ = str_at(h, "typ")) {
    std::string t(typ);
    if (t == "JWT" || t == "at+jwt" || t == "application/at+jwt" || t == "secevent+jwt" ||
        t == "JOSE" || t == "application/jwt" || t == "kb+jwt" || t == "vc+sd-jwt" || t == "dc+sd-jwt") {
      add(f, "header.typ", "info", "typ is " + t, "Explicit typing keeps access tokens from being replayed as ID tokens.");
    } else {
      add(f, "header.typ.unusual", "low", "Unusual typ: " + t,
          "Only the registered media types are meaningful; anything else is a hint, not a constraint.");
    }
  } else {
    add(f, "header.typ.missing", "low", "No typ",
        "Without typ, a token minted for one audience can be replayed at another endpoint that shares the key.");
  }

  double exp = 0, iat = 0, nbf = 0;
  const double now = static_cast<double>(std::time(nullptr));
  bool has_exp = num_at(p, "exp", exp);
  bool has_iat = num_at(p, "iat", iat);
  bool has_nbf = num_at(p, "nbf", nbf);
  if (!has_exp) add(f, "claim.exp.missing", "high", "No exp claim",
                    "A token without an expiry is valid forever. Resource servers should reject it.");
  else if (exp < now) add(f, "claim.exp.past", "high", "Expired",
                          "exp is " + std::to_string(static_cast<long long>(now - exp)) + "s in the past.");
  if (has_exp && has_iat) {
    double life = exp - iat;
    if (life <= 0) add(f, "claim.life.nonpositive", "high", "Expiry before issue",
                       "exp - iat <= 0: the token is born expired or the timestamps disagree.");
    else if (life > 86400) add(f, "claim.life.long", "medium", "Long-lived access token",
                               "Lifetime is " + std::to_string(static_cast<long long>(life / 3600)) +
                                   "h. Access tokens are usually minutes; long ones cannot be revoked cheaply.");
  }
  if (!p.has("iss")) add(f, "claim.iss.missing", "high", "No iss claim", "Nothing binds the token to an issuer.");
  if (!p.has("aud")) add(f, "claim.aud.missing", "high", "No aud claim",
                         "Without an audience, the token is valid at every resource server that shares the key.");
  if (p.has("aud")) {
    const JVal* aud = p.get("aud");
    if (aud->is_arr() && aud->arr.size() > 1)
      add(f, "claim.aud.multiple", "medium", "Multiple audiences",
          "A token accepted by several services is a token that leaks between them.");
  }
  if (!p.has("sub")) add(f, "claim.sub.missing", "low", "No sub claim", "The token does not name a principal.");
  if (!p.has("jti")) add(f, "claim.jti.missing", "low", "No jti claim",
                         "Without a unique id the token cannot be replay-tracked or revoked individually.");
  if (has_nbf && nbf > now + 60)
    add(f, "claim.nbf.future", "low", "Not valid yet",
        "nbf is " + std::to_string(static_cast<long long>(nbf - now)) + "s in the future.");
  if (p.has("cnf")) add(f, "claim.cnf", "info", "Proof-of-possession token",
                        "cnf binds the token to a key; the caller must present a matching DPoP proof or mTLS cert.");
  if (p.has("act")) add(f, "claim.act", "info", "Delegated token (act)",
                        "The token carries an actor chain; authorise the leaf, not the chain's head.");
  if (const char* scope = str_at(p, "scope")) {
    std::string s(scope);
    if (s.find("admin") != std::string::npos || s.find("root") != std::string::npos ||
        s.find("*") != std::string::npos)
      add(f, "claim.scope.broad", "medium", "Broad scope",
          "Scope contains admin/root/wildcard: " + s);
  }

  int score = 100;
  for (const auto& x : f) {
    if (std::strcmp(x.severity, "critical") == 0) score -= 40;
    else if (std::strcmp(x.severity, "high") == 0) score -= 18;
    else if (std::strcmp(x.severity, "medium") == 0) score -= 8;
    else if (std::strcmp(x.severity, "low") == 0) score -= 3;
  }
  if (score < 0) score = 0;
  const char* grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  std::string o = "{\"findings\":[";
  for (size_t k = 0; k < f.size(); ++k) {
    if (k) o.push_back(',');
    o += "{\"id\":";
    dump_string(f[k].id, o);
    o += ",\"severity\":";
    dump_string(f[k].severity, o);
    o += ",\"title\":";
    dump_string(f[k].title, o);
    o += ",\"detail\":";
    dump_string(f[k].detail, o);
    o += "}";
  }
  o += "],\"score\":" + std::to_string(score) + ",\"grade\":";
  dump_string(grade, o);
  o += "}";
  return emit(o, out, cap);
}

}  // extern "C"
