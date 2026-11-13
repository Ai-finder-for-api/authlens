/** Protocol console: PKCE, redirect policy, discovery order, challenges, DCQL. */
import { api } from "../api.js";
import { h, pretty, toast } from "../dom.js";
import { badge, button, card, code, empty, field, input, kv, textarea } from "../ui.js";

interface PkceResult {
  generated: { verifier: string; challenge: string; method: string };
  pkce?: { ok: boolean; message?: string; kind?: string };
  redirects: { kind: string; uri: string; ok: boolean; message: string }[];
  redirect_match?: boolean;
  scope?: { ok: boolean; excess?: string[]; missing?: string[] };
}

export function protocolView(): HTMLElement {
  /* ------------------------------------------------------- PKCE + redirect */
  const verifier = input({ placeholder: "43-128 char verifier (leave empty to generate one)" });
  const challenge = input({ placeholder: "S256 challenge (leave empty to pair with the verifier)" });
  const webRedirect = input({ value: "http://app.example/cb" });
  const nativeRedirect = input({ value: "com.example.app:/oauth2redirect" });
  const registered = input({ value: "https://app.example/cb" });
  const presented = input({ value: "https://app.example/cb?code=abc&state=xyz" });
  const requested = input({ value: "openid profile admin" });
  const allowed = input({ value: "openid profile" });
  const pkceOut = h("div", { class: "stack" });

  const runPkce = async (): Promise<void> => {
    try {
      const res = await api<PkceResult>("/api/pkce", {
        verifier: verifier.value.trim(), challenge: challenge.value.trim(),
        redirect: webRedirect.value.trim(), native: nativeRedirect.value.trim(),
        registered: registered.value.trim(), presented: presented.value.trim(),
        requested: requested.value.trim(), allowed: allowed.value.trim(),
      });
      verifier.value = res.generated.verifier;
      challenge.value = res.generated.challenge;
      pkceOut.replaceChildren(
        h("div", { class: "pairs" },
          kv("verifier", res.generated.verifier.slice(0, 18) + "…", true),
          kv("challenge", res.generated.challenge.slice(0, 18) + "…", true)),
        h("ul", { class: "checks checks--result" },
          h("li", null, badge(res.pkce?.ok ? "PKCE ok" : "PKCE rejected", res.pkce?.ok ? "ok" : "bad"),
            h("span", { text: res.pkce?.message ?? "verifier does not match challenge" })),
          ...res.redirects.map((r) =>
            h("li", null, badge(`${r.kind} redirect`, r.ok ? "ok" : "bad"),
              h("span", { class: "mono trunc", text: r.uri }),
              h("span", { class: "muted", text: r.message }))),
          h("li", null, badge(res.redirect_match ? "exact match" : "no match", res.redirect_match ? "ok" : "bad"),
            h("span", { class: "muted", text: "registered vs presented redirect_uri" })),
          res.scope
            ? h("li", null, badge(res.scope.ok ? "scope ok" : "scope excess", res.scope.ok ? "ok" : "warn"),
                h("span", { class: "muted", text: res.scope.excess?.length ? `excess: ${res.scope.excess.join(", ")}` : "requested scope is inside the allowed set" }))
            : null));
    } catch (e) {
      toast((e as Error).message, "bad");
    }
  };

  /* --------------------------------------------------------------- discovery */
  const issuer = input({ value: "https://issuer.example" });
  const resource = input({ value: "https://api.example/orders" });
  const discOut = h("div", { class: "stack" });
  const runDiscovery = async (): Promise<void> => {
    try {
      const res = await api<{ metadata_urls?: string[]; protected_resource_url?: string; canonical_resource?: string; resource_metadata_url?: string }>(
        "/api/discovery", { issuer: issuer.value.trim(), resource: resource.value.trim() });
      const urls = res.metadata_urls ?? [];
      discOut.replaceChildren(
        urls.length
          ? h("ol", { class: "urls" }, ...urls.map((u) => h("li", null, h("code", { text: u }))))
          : empty("no metadata URLs"),
        h("div", { class: "pairs" },
          kv("protected resource", res.protected_resource_url ?? "—", true),
          kv("canonical resource", res.canonical_resource ?? "—", true),
          kv("resource metadata", res.resource_metadata_url ?? "—", true)));
    } catch (e) {
      toast((e as Error).message, "bad");
    }
  };

  /* --------------------------------------------------------------- challenge */
  const header = textarea({ rows: 3 });
  header.value = 'Bearer realm="api", error="insufficient_scope", scope="orders:write", resource_metadata="https://api.example/.well-known/oauth-protected-resource/orders"';
  const chalOut = h("div", { class: "stack" });
  const runChallenge = async (): Promise<void> => {
    try {
      const res = await api<{ challenges?: { scheme: string; params: Record<string, string> }[]; rebuilt?: string; message?: string }>(
        "/api/challenge", { header: header.value.trim() });
      const rows: HTMLElement[] = [];
      for (const c of res.challenges ?? []) {
        for (const [k, v] of Object.entries(c.params)) {
          rows.push(h("tr", null,
            h("td", null, h("code", { text: c.scheme })),
            h("td", null, h("code", { text: k })),
            h("td", null, h("span", { class: "mono trunc", text: v }))));
        }
      }
      chalOut.replaceChildren(
        h("div", { class: "table-scroll" },
          h("table", { class: "table" },
            h("thead", null, h("tr", null,
              h("th", { text: "scheme" }), h("th", { text: "parameter" }), h("th", { text: "value" }))),
            h("tbody", null, ...rows))),
        res.rebuilt ? code(res.rebuilt, "code--tight", "Copy rebuilt header") : empty(res.message ?? "nothing parsed"));
    } catch (e) {
      toast((e as Error).message, "bad");
    }
  };

  /* -------------------------------------------------------------------- DCQL */
  const query = textarea({ rows: 8 });
  query.value = pretty({
    credentials: [{
      id: "pid", format: "dc+sd-jwt", meta: { vct_values: ["https://issuer.example/pid"] },
      claims: [{ path: ["given_name"] }, { path: ["age_over_18"] }],
    }],
  });
  const credential = textarea({ rows: 6 });
  credential.value = pretty({ given_name: "Alice", age_over_18: true });
  const dcqlOut = h("div", { class: "stack" });
  const runDcql = async (): Promise<void> => {
    try {
      const res = await api<{ ok: boolean; satisfiable?: boolean; selection?: { paths: unknown[]; option: number | null }; query_ids?: string[]; message?: string }>(
        "/api/dcql", { query: query.value, credential: credential.value });
      dcqlOut.replaceChildren(
        h("div", { class: "pairs" },
          kv("valid query", res.ok ? "yes" : "no"),
          kv("satisfiable", res.satisfiable ? "yes" : "no"),
          kv("query ids", (res.query_ids ?? []).join(", ") || "—")),
        res.selection ? code(pretty(res.selection), "code--tight") : empty(res.message ?? "no selection"));
    } catch (e) {
      toast((e as Error).message, "bad");
    }
  };

  const view = h("div", { class: "view" },
    h("div", { class: "grid-2" },
      card("PKCE & redirect policy", "Every check below is enforced by authlas at runtime",
        h("div", { class: "row" }, field("verifier", verifier), field("challenge", challenge)),
        h("div", { class: "row" }, field("web redirect", webRedirect), field("native redirect", nativeRedirect)),
        h("div", { class: "row" }, field("registered", registered), field("presented", presented)),
        h("div", { class: "row" }, field("scope requested", requested), field("scope allowed", allowed)),
        h("div", { class: "toolbar" }, button("Run checks", () => void runPkce())),
        pkceOut),
      card("Discovery planner", "The order in which an issuer is probed (RFC 8414 / OIDC / RFC 9728)",
        h("div", { class: "row" }, field("issuer", issuer), field("resource", resource)),
        h("div", { class: "toolbar" }, button("Build plan", () => void runDiscovery(), "ghost")),
        discOut)),
    h("div", { class: "grid-2" },
      card("WWW-Authenticate", "Parse a challenge, see the parameters, rebuild it",
        field("Header value", header),
        h("div", { class: "toolbar" }, button("Parse", () => void runChallenge(), "ghost")),
        chalOut),
      card("DCQL probe", "Would this credential satisfy that query? (OpenID4VP 1.0 §6)",
        h("div", { class: "row" }, field("query", query), field("credential", credential)),
        h("div", { class: "toolbar" }, button("Evaluate", () => void runDcql(), "ghost")),
        dcqlOut)));

  void runDiscovery();
  return view;
}
