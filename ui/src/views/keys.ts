/** Keyring and signing: key generation, RFC 7638 thumbs, token minting. */
import { api, Analysis, KeyInfo } from "../api.js";
import { h, pretty, toast } from "../dom.js";
import { badge, button, card, code, empty, field, input, kv, select, textarea } from "../ui.js";

const SAMPLE_CLAIMS = {
  iss: "https://issuer.example",
  sub: "alice@example.com",
  aud: "api://orders",
  scope: "orders:read",
  jti: "01J8Z4C7Q3",
};

export function keysView(): HTMLElement {
  const list = h("div", { class: "keylist" });
  const curve = select([{ value: "P-256", label: "P-256 · ES256" }, { value: "P-384", label: "P-384 · ES384" }, { value: "P-521", label: "P-521 · ES512" }]);
  const mintKey = select([]);
  const typ = select([{ value: "at+jwt", label: "at+jwt — access token" }, { value: "JWT", label: "JWT — generic" }, { value: "dc+sd-jwt", label: "dc+sd-jwt" }]);
  const claims = textarea({ rows: 8 });
  claims.value = pretty(SAMPLE_CLAIMS);
  const output = h("div", { class: "stack" });

  const refresh = async (): Promise<void> => {
    const data = await api<{ keys: KeyInfo[]; default: string }>("/api/keys");
    list.replaceChildren(
      ...data.keys.map((key) =>
        h("article", { class: "key" },
          h("div", { class: "key__head" },
            h("code", { class: "key__id", text: key.id }),
            badge(key.alg, "ok"),
            key.id === data.default ? badge("default", "idle") : null),
          h("div", { class: "key__rows" },
            kv("curve", key.curve),
            kv("created", new Date(key.created * 1000).toLocaleTimeString())),
          h("div", { class: "key__thumb" },
            h("span", { class: "kv__k", text: "RFC 7638 thumbprint" }),
            h("code", { class: "mono trunc", text: key.thumbprint }),
            badge(key.thumbprint_agrees ? "authlas = C++ core" : "MISMATCH", key.thumbprint_agrees ? "ok" : "bad")),
          code(pretty(key.jwk), "code--tiny", "Copy public JWK")))
    );
    mintKey.replaceChildren(...data.keys.map((k) => h("option", { value: k.id, text: `${k.id} · ${k.alg}` })));
    if (!mintKey.value) mintKey.value = data.default;
  };

  const generate = async (): Promise<void> => {
    try {
      await api("/api/keys/new", { curve: curve.value });
      toast(`Generated a fresh ${curve.value} key`, "ok");
      await refresh();
    } catch (e) {
      toast((e as Error).message, "bad");
    }
  };

  const mint = async (): Promise<void> => {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(claims.value);
    } catch (e) {
      toast(`Claims are not valid JSON: ${(e as Error).message}`, "bad");
      return;
    }
    try {
      const res = await api<{ token: string; alg: string; analysis: Analysis }>("/api/mint", {
        claims: parsed,
        key_id: mintKey.value,
        typ: typ.value,
      });
      output.replaceChildren(
        card("Signed token", `${res.alg} · ${typ.value} · ${res.token.length} characters`,
          code(res.token),
          h("p", { class: "muted", text: `Native analyser verdict: ${res.analysis.risk?.score ?? "—"} / 100 (grade ${res.analysis.risk?.grade ?? "?"}).` })),
        card("Analysis of the new token", "Straight back through the C++ core",
          res.analysis.header ? code(pretty(res.analysis.header), "code--tight") : empty("no header"),
          res.analysis.payload ? code(pretty(res.analysis.payload), "code--tight") : empty("no payload")));
    } catch (e) {
      toast((e as Error).message, "bad");
    }
  };

  const view = h("div", { class: "view" },
    h("div", { class: "grid-2" },
      card("Session keyring", "Keys live in memory only — never written to disk",
        h("div", { class: "row row--end" }, field("Curve", curve), button("Generate key", () => void generate(), "ghost")),
        list),
      card("Mint a token", "Signed by authlas-python, then audited by the C++ core",
        h("div", { class: "row" }, field("Key", mintKey), field("typ", typ)),
        field("Claims", claims),
        h("div", { class: "toolbar" }, button("Sign token", () => void mint()), h("span", { class: "spacer" }))),
    ),
    output);

  void refresh().catch((e) => toast((e as Error).message, "bad"));
  return view;
}
