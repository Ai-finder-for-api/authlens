/** SD-JWT studio: issue, reveal, present, verify — with native digest matching. */
import { api, Analysis, KeyInfo, SdView } from "../api.js";
import { h, pretty, toast } from "../dom.js";
import { badge, button, card, code, empty, field, input, kv, select, textarea } from "../ui.js";

const CLAIMS = {
  iss: "https://issuer.example",
  sub: "alice@example.com",
  given_name: "Alice",
  family_name: "Liddell",
  age_over_18: true,
  address: { locality: "Berlin", country: "DE" },
};

export function sdjwtView(): HTMLElement {
  const claims = textarea({ rows: 10 });
  claims.value = pretty(CLAIMS);
  const hideBox = h("div", { class: "checks" });
  const decoys = input({ type: "number", min: 0, max: 8, value: 1 });
  const keySel = select([]);
  const issued = h("div", { class: "stack" });
  const presentation = h("div", { class: "stack" });
  let current: { sd_jwt: string; disclosures: string[]; analysis: Analysis } | null = null;

  const syncChecks = (): void => {
    let data: Record<string, unknown> = {};
    try {
      data = JSON.parse(claims.value);
    } catch {
      hideBox.replaceChildren(h("span", { class: "muted", text: "claims are not valid JSON yet" }));
      return;
    }
    hideBox.replaceChildren(...Object.keys(data).filter((k) => !k.startsWith("_")).map((k) => {
      const box = h("input", { type: "checkbox", value: k }) as HTMLInputElement;
      if (k === "given_name" || k === "age_over_18") box.checked = true;
      return h("label", { class: "check" }, box, h("span", { text: k }));
    }));
  };
  claims.addEventListener("input", syncChecks);

  const digestTable = (sd: SdView): HTMLElement => {
    const rows = sd.digests.map((d) => {
      const parts = Array.isArray(d.json) ? d.json : [];
      const matched = sd.match.pairs.some((p) => p.disclosure === d.index);
      return h("tr", null,
        h("td", { class: "num", text: String(d.index) }),
        h("td", null, h("code", { text: String(parts[1] ?? "decoy") })),
        h("td", null, h("code", { text: JSON.stringify(parts[2] ?? null) })),
        h("td", null, h("code", { class: "trunc", text: d.digest })),
        h("td", null, badge(matched ? "in _sd" : "decoy", matched ? "ok" : "idle")));
    });
    return h("div", { class: "table-scroll" },
      h("table", { class: "table" },
        h("thead", null, h("tr", null,
          h("th", { text: "#" }), h("th", { text: "claim" }), h("th", { text: "value" }),
          h("th", { text: "sha-256 digest" }), h("th", { text: "referenced" }))),
        h("tbody", null, ...rows)));
  };

  const issue = async (): Promise<void> => {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(claims.value);
    } catch (e) {
      toast(`Claims are not valid JSON: ${(e as Error).message}`, "bad");
      return;
    }
    const hide = Array.from(hideBox.querySelectorAll<HTMLInputElement>("input[type=checkbox]"))
      .filter((b) => b.checked)
      .map((b) => b.value);
    try {
      const res = await api<{ sd_jwt: string; disclosures: string[]; analysis: Analysis }>("/api/sdjwt/issue", {
        claims: parsed, hide, decoys: Number(decoys.value) || 0, key_id: keySel.value,
      });
      current = res;
      const sd = res.analysis.sd;
      issued.replaceChildren(
        card("Issued SD-JWT", `${hide.length} hidden claim(s) · ${Number(decoys.value) || 0} decoy(ies) · ${res.sd_jwt.length} characters`,
          code(res.sd_jwt),
          sd ? digestTable(sd) : empty("no disclosure information")),
        card("Disclose", "A presentation reveals only the disclosures the verifier asked for",
          h("div", { class: "checks" }, ...res.disclosures.map((d, i) => {
            const box = h("input", { type: "checkbox", value: String(i) }) as HTMLInputElement;
            box.checked = i === 0;
            const parts = sd?.digests[i]?.json;
            const label = Array.isArray(parts) ? String(parts[1] ?? "decoy") : `disclosure ${i}`;
            return h("label", { class: "check" }, box, h("span", { text: `${i} · ${label}` }));
          })),
          h("div", { class: "toolbar" },
            button("Create presentation", () => void present()),
            button("Verify full credential", () => void verify(), "ghost"))),
      );
      presentation.replaceChildren();
    } catch (e) {
      toast((e as Error).message, "bad");
    }
  };

  const revealList = (): number[] =>
    Array.from(presentation.querySelectorAll<HTMLInputElement>(".checks input:checked")).map((b) => Number(b.value));

  const present = async (): Promise<void> => {
    if (!current) return;
    const boxes = Array.from(issued.querySelectorAll<HTMLInputElement>(".card:last-child .check input"));
    const reveal = boxes.filter((b) => b.checked).map((b) => Number(b.value));
    try {
      const res = await api<{ presentation: string; revealed: number; analysis: Analysis }>("/api/sdjwt/present", {
        sd_jwt: current.sd_jwt, reveal,
      });
      const visible = res.analysis.payload ?? {};
      presentation.replaceChildren(
        card("Presentation", `${res.revealed} disclosure(s) attached · ${res.presentation.split("~").length - 1} segment(s)`,
          code(res.presentation),
          h("p", { class: "muted", text: `Still hidden: ${(res.analysis.sd?.visible_claims ?? []).length} visible claim(s), ${res.analysis.sd?.hidden_digests ?? 0} digests remain in _sd.` }),
          code(pretty(visible), "code--tight", "Copy visible claims")));
    } catch (e) {
      toast((e as Error).message, "bad");
    }
  };

  const verify = async (): Promise<void> => {
    if (!current) return;
    try {
      const res = await api<{ ok: boolean; claims?: Record<string, unknown>; message?: string; kind?: string; issuer?: string }>(
        "/api/sdjwt/verify", { sd_jwt: current.sd_jwt, key_id: keySel.value });
      presentation.replaceChildren(
        card("Verification", "authlas re-checks the issuer signature, the disclosures and every digest",
          res.ok
            ? h("div", { class: "verdict verdict--ok" },
                h("div", { class: "verdict__head" }, badge("verified", "ok"), h("span", { class: "muted", text: res.issuer ?? "" })),
                code(pretty(res.claims ?? {}), "code--tight", "Copy claims"))
            : h("div", { class: "verdict verdict--bad" },
                h("div", { class: "verdict__head" }, badge("rejected", "bad")),
                h("p", { class: "verdict__note", text: res.message ?? "unknown error" }))));
    } catch (e) {
      toast((e as Error).message, "bad");
    }
  };

  const load = async (): Promise<void> => {
    const keys = await api<{ keys: KeyInfo[]; default: string }>("/api/keys");
    keySel.replaceChildren(...keys.keys.map((k) => h("option", { value: k.id, text: `${k.id} · ${k.curve}` })));
    keySel.value = keys.default;
    syncChecks();
  };

  const view = h("div", { class: "view" },
    h("div", { class: "grid-2" },
      card("Credential claims", "Tick a claim to hide it behind a salted digest",
        field("Claims", claims),
        field("Hide", hideBox),
        h("div", { class: "row row--end" },
          field("Decoys", decoys, "Noise digests that hide the real claim count"),
          field("Issuer key", keySel),
          button("Issue credential", () => void issue()))),
      h("div", { class: "stack" },
        card("How it works", "Three lines of protocol, one native digest check",
          h("ol", { class: "steps" },
            h("li", null, h("b", { text: "Issue " }), "authlas signs the payload and replaces each hidden claim with a salted SHA-256 digest in ",
              h("code", { text: "_sd" }), "."),
            h("li", null, h("b", { text: "Present " }), "the holder attaches only the disclosures the verifier needs."),
            h("li", null, h("b", { text: "Check " }), "the C++ core recomputes every digest and maps it back to the ",
              h("code", { text: "_sd" }), " array before authlas accepts the signature."))))),
    issued,
    presentation);

  void load().catch((e) => toast((e as Error).message, "bad"));
  return view;
}
