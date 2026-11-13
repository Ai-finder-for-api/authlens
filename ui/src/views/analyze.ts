/** Token analyser: the native scan, the risk heuristics and the authlas verdict. */
import { api, Analysis, Finding, Health, KeyInfo, Verification } from "../api.js";
import { h, pretty, toast } from "../dom.js";
import { badge, button, card, code, empty, field, input, kv, select, textarea } from "../ui.js";

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function scoreRing(score: number, grade: string): HTMLElement {
  const r = 42;
  const circumference = 2 * Math.PI * r;
  const offset = circumference * (1 - Math.max(0, Math.min(100, score)) / 100);
  const tone = score >= 90 ? "ok" : score >= 75 ? "good" : score >= 60 ? "warn" : "bad";
  const el = h("div", { class: "ring" });
  el.innerHTML = `
    <svg viewBox="0 0 100 100" aria-hidden="true">
      <circle class="ring__track" cx="50" cy="50" r="${r}"></circle>
      <circle class="ring__bar ring__bar--${tone}" cx="50" cy="50" r="${r}"
        stroke-dasharray="${circumference.toFixed(1)}"
        stroke-dashoffset="${offset.toFixed(1)}"></circle>
    </svg>
    <div class="ring__text"><strong>${score}</strong><span>grade ${grade}</span></div>`;
  return el;
}

function findingsList(findings: Finding[]): HTMLElement {
  if (!findings.length) return empty("Nothing to report — the token carries no risky header or claim shape.");
  const sorted = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  return h(
    "ul",
    { class: "findings" },
    ...sorted.map((f) =>
      h(
        "li",
        { class: `finding finding--${f.severity}` },
        h("span", { class: "finding__sev", text: f.severity }),
        h("div", { class: "finding__body" },
          h("p", { class: "finding__title", text: f.title }),
          h("p", { class: "finding__detail", text: f.detail }),
          h("code", { class: "finding__id", text: f.id })),
      ),
    ),
  );
}

function verificationPanel(v: Verification | null): HTMLElement {
  if (!v) return empty("No verification was attempted.");
  if (v.ok) {
    return h(
      "div",
      { class: "verdict verdict--ok" },
      h("div", { class: "verdict__head" }, badge("verified", "ok"), h("span", { class: "muted", text: v.source ?? "" })),
      h("p", { class: "verdict__note", text: `Signature, iss, aud and exp accepted for alg ${(v.algs ?? []).join(", ")}.` }),
      code(pretty(v.claims ?? {}), "code--tight", "Copy claims"),
    );
  }
  const skipped = v.kind === "needs-policy" || v.kind === "no-key" || v.kind === "bad-jwks";
  return h(
    "div",
    { class: `verdict ${skipped ? "verdict--idle" : "verdict--bad"}` },
    h("div", { class: "verdict__head" },
      badge(v.type ?? "error", skipped ? "idle" : "bad"),
      v.kind ? h("code", { class: "finding__id", text: String(v.kind) }) : null),
    h("p", { class: "verdict__note", text: v.message ?? "rejected" }),
    v.source ? h("p", { class: "muted", text: `key source: ${v.source}` }) : null,
  );
}

function structure(analysis: Analysis): HTMLElement {
  const table = h(
    "table",
    { class: "table" },
    h("thead", null,
      h("tr", null,
        ...["segment", "offset", "chars", "bytes", "b64", "json"].map((t) => h("th", { text: t })))),
    h("tbody", null,
      ...analysis.segments.map((s) =>
        h("tr", null,
          h("td", null, h("code", { text: s.role })),
          h("td", { class: "num", text: String(s.offset) }),
          h("td", { class: "num", text: String(s.length) }),
          h("td", { class: "num", text: String(s.bytes) }),
          h("td", null, badge(s.b64_ok ? "ok" : "bad", s.b64_ok ? "ok" : "bad")),
          h("td", null, s.json ? badge("parsed", "ok") : h("span", { class: "muted", text: "—" }))))),
  );
  const t = analysis.timeline;
  const timeline = t
    ? h("div", { class: "timeline" },
        kv("lifetime", t.lifetime !== undefined ? `${t.lifetime}s` : "—"),
        kv("expires in", t.expires_in !== undefined ? `${t.expires_in}s` : "—"),
        kv("issued", t.issued ? new Date(t.issued * 1000).toLocaleString() : "—"))
    : null;
  return h("div", { class: "stack" }, table, timeline);
}

export function analyzeView(): HTMLElement {
  const tokenBox = textarea({ rows: 3, placeholder: "Paste a compact JWS, JWE or SD-JWT…" });
  const result = h("div", { class: "stack result" });
  const chips = h("div", { class: "chips" });
  const keySelect = select([{ value: "", label: "No key (structure only)" }]);
  const jwksBox = textarea({ rows: 3, placeholder: "Optional JWKS: {\"keys\":[…]} — paste an issuer's key set to verify against it" });
  const issuerBox = input({ placeholder: "https://issuer.example" });
  const audienceBox = input({ placeholder: "api://orders" });
  const status = h("span", { class: "muted mono", text: "idle" });

  const run = async (): Promise<void> => {
    const token = tokenBox.value.trim();
    if (!token) {
      toast("Paste a token first — or pick a sample", "bad");
      return;
    }
    status.textContent = "analysing…";
    try {
      const body: Record<string, unknown> = { token, issuer: issuerBox.value.trim(), audience: audienceBox.value.trim() };
      if (keySelect.value) body.key_id = keySelect.value;
      if (jwksBox.value.trim()) body.jwks = jwksBox.value.trim();
      const analysis = await api<Analysis>("/api/analyze", body);
      status.textContent = `${analysis.format} · ${analysis.nbytes} B`;
      const kids: (Node | null | undefined)[] = [
        analysis.risk
          ? h("section", { class: `card verdict-card grade-${analysis.risk.grade}` },
              h("div", { class: "verdict-grid" },
                scoreRing(analysis.risk.score, analysis.risk.grade),
                h("div", { class: "verdict-summary" },
                  h("h2", { class: "card__title", text: analysis.risk.score >= 90 ? "Structurally sound" :
                    analysis.risk.score >= 60 ? "Needs review" : "Do not ship this token" }),
                  h("p", { class: "card__sub", text: `${analysis.risk.findings.length} observation(s) from the native analyser, ${analysis.format.toUpperCase()}, ${analysis.nbytes} bytes.` }),
                  h("div", { class: "chips" },
                    ...["critical", "high", "medium", "low", "info"].map((sev) => {
                      const n = analysis.risk!.findings.filter((f) => f.severity === sev).length;
                      return badge(`${n} ${sev}`, n ? sev : "idle");
                    })))))
          : empty("This token has no decodable header and payload, so the analyser stayed silent."),

        h("div", { class: "grid-2" },
          card("Findings", "Heuristics run in C++ over the decoded header and payload", findingsList(analysis.risk?.findings ?? [])),
          card("Verification", "Policy and signature by authlas-python", verificationPanel(analysis.verification))),

        h("div", { class: "grid-2" },
          card("Decoded header", "Protected header as JSON",
            analysis.header ? code(pretty(analysis.header), "code--tight") : empty("not JSON")),
          card("Decoded payload", analysis.sd ? "Issuer-signed payload, minus the hidden claims" : "Claims as JSON",
            analysis.payload ? code(pretty(analysis.payload), "code--tight") : empty("not JSON"))),

        card("Compact structure", "Offset and decoded size of every segment, measured natively", structure(analysis)),

        analysis.sd
          ? card("Selective disclosure", `${analysis.sd.hash} · ${analysis.sd.match.matched}/${analysis.sd.match.digest_count} digests matched`,
              h("div", { class: "table-scroll" },
                h("table", { class: "table" },
                  h("thead", null, h("tr", null, ...["#", "claim", "value", "digest (sha-256)", "in _sd"].map((t) => h("th", { text: t })))),
                  h("tbody", null, ...analysis.sd.digests.map((d) => {
                    const claims = Array.isArray(d.json) ? d.json : [];
                    const matched = analysis.sd!.match.pairs.some((p) => p.disclosure === d.index);
                    return h("tr", null,
                      h("td", { class: "num", text: String(d.index) }),
                      h("td", null, h("code", { text: String(claims[1] ?? "—") })),
                      h("td", null, h("code", { text: JSON.stringify(claims[2] ?? null) })),
                      h("td", null, h("code", { class: "trunc", text: d.digest })),
                      h("td", null, badge(matched ? "yes" : "no", matched ? "ok" : "bad")));
                  })))))
          : undefined,

        analysis.notes.length
          ? h("section", { class: "card card--notes" },
              h("header", { class: "card__head" }, h("h2", { class: "card__title", text: "Structural notes" })),
              h("ul", { class: "bullets" }, ...analysis.notes.map((n) => h("li", { text: n }))))
          : undefined,
            ];
      result.replaceChildren(...kids.filter((n): n is Node => n != null));
    } catch (e) {
      status.textContent = "failed";
      toast((e as Error).message, "bad");
    }
  };

  const loadSamples = async (): Promise<void> => {
    const health = await api<Health>("/api/health");
    for (const sample of health.samples) {
      const chip = h("button", { class: "chip", type: "button" },
        h("span", { class: "chip__label", text: sample.label }),
        h("span", { class: "chip__hint", text: sample.hint }));
      chip.addEventListener("click", () => {
        tokenBox.value = sample.token;
        void run();
      });
      chips.append(chip);
    }
    const keys = await api<{ keys: KeyInfo[]; default: string }>("/api/keys");
    for (const key of keys.keys) {
      keySelect.append(h("option", { value: key.id, text: `${key.id} · ${key.curve} · ${key.alg}` }));
    }
  };

  tokenBox.addEventListener("keydown", (ev) => {
    if ((ev.metaKey || ev.ctrlKey) && ev.key === "Enter") void run();
  });

  const view = h("div", { class: "view" },
    card("Token under inspection", "Nothing leaves this machine: the analyser is native, the verdict is local",
      chips,
      tokenBox,
      h("div", { class: "toolbar" },
        button("Analyse ⌘↵", () => void run()),
        button("Clear", () => { tokenBox.value = ""; result.replaceChildren(); status.textContent = "idle"; }, "quiet"),
        h("span", { class: "spacer" }),
        status)),
    h("div", { class: "grid-2" },
      card("Verify against", "authlas needs an expected issuer and audience before it will check a signature",
        field("Key source", keySelect),
        h("div", { class: "row" }, field("Expected issuer", issuerBox), field("Expected audience", audienceBox)),
        field("…or paste a JWKS", jwksBox, "The key is picked by kid, or the first key when the header has none."))),
    result);

  void loadSamples().catch((e) => toast((e as Error).message, "bad"));
  return view;
}
