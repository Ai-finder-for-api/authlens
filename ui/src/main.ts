/** Shell: navigation, layer chips, hash routing. */
import { api, Health } from "./api.js";
import { h } from "./dom.js";
import { analyzeView } from "./views/analyze.js";
import { keysView } from "./views/keys.js";
import { protocolView } from "./views/protocol.js";
import { sdjwtView } from "./views/sdjwt.js";

interface View {
  id: string;
  label: string;
  hint: string;
  icon: string;
  subtitle: string;
  build: () => HTMLElement;
}

const ICONS: Record<string, string> = {
  analyze: '<path d="M3 12a9 9 0 1 0 9-9 9 9 0 0 0-9 9Z"/><path d="m20 20-4.35-4.35"/><path d="M8 12h8M12 8v8"/>',
  keys: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3"/><path d="m16 7 3 3"/><path d="m13 10 2.5 2.5"/>',
  sdjwt: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 9h4M7 13h10M7 16h7"/><path d="m15 8 3 3-3 3"/>',
  protocol: '<circle cx="12" cy="12" r="3"/><circle cx="5" cy="5" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M6.5 6.5 10 10M17.5 6.5 14 10M6.5 17.5 10 14M17.5 17.5 14 14"/>',
};

const VIEWS: View[] = [
  { id: "analyze", label: "Token analyser", hint: "structure, risk, verification", icon: ICONS.analyze,
    subtitle: "Paste a JWS, JWE or SD-JWT and read it layer by layer.", build: analyzeView },
  { id: "keys", label: "Keys & signing", hint: "keyring, thumbprints, minting", icon: ICONS.keys,
    subtitle: "Generate keys, compare two RFC 7638 implementations, sign tokens.", build: keysView },
  { id: "sdjwt", label: "SD-JWT studio", hint: "issue, disclose, present", icon: ICONS.sdjwt,
    subtitle: "Selective disclosure end to end, with the digests computed natively.", build: sdjwtView },
  { id: "protocol", label: "Protocol console", hint: "PKCE, discovery, DCQL", icon: ICONS.protocol,
    subtitle: "The rules authlas enforces, made visible one check at a time.", build: protocolView },
];

function icon(paths: string): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "icon");
  svg.innerHTML = paths;
  return svg;
}

function boot(): void {
  const app = document.getElementById("app");
  if (!app) throw new Error("#app is missing");
  const nav = h("nav", { class: "nav" });
  const outlet = h("main", { class: "outlet" });
  const title = h("h1", { class: "topbar__title" });
  const sub = h("p", { class: "topbar__sub" });
  const chips = h("div", { class: "layer-chips" });

  const activate = (view: View): void => {
    for (const item of nav.querySelectorAll<HTMLElement>(".nav__item")) {
      item.classList.toggle("is-active", item.dataset.view === view.id);
    }
    title.textContent = view.label;
    sub.textContent = view.subtitle;
    outlet.replaceChildren(view.build());
    location.hash = view.id;
    outlet.scrollTop = 0;
  };

  for (const view of VIEWS) {
    const item = h("button", { class: "nav__item", type: "button", dataset: { view: view.id } },
      icon(view.icon),
      h("span", { class: "nav__text" },
        h("span", { class: "nav__label", text: view.label }),
        h("span", { class: "nav__hint", text: view.hint })));
    item.addEventListener("click", () => activate(view));
    nav.append(item);
  }

  const rail = h("aside", { class: "rail" },
    h("div", { class: "brand" },
      h("div", { class: "brand__mark" },
        icon('<circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 0 0 18M3 12h18"/><circle cx="12" cy="12" r="3"/>')),
      h("div", { class: "brand__text" }, h("strong", { text: "AuthLens" }), h("span", { text: "OAuth · JOSE workbench" }))),
    nav,
    h("div", { class: "rail__foot" },
      h("p", { class: "rail__cap", text: "three layers" }),
      h("ul", { class: "stacklist" },
        h("li", null, h("b", { text: "C++" }), " native analyser"),
        h("li", null, h("b", { text: "Python" }), " authlas-python"),
        h("li", null, h("b", { text: "TypeScript" }), " this interface"))));

  app.append(
    rail,
    h("div", { class: "main" },
      h("header", { class: "topbar" }, h("div", null, title, sub), chips),
      outlet),
  );

  const bootView = VIEWS.find((v) => v.id === location.hash.slice(1)) ?? VIEWS[0];
  activate(bootView);

  api<Health>("/api/health")
    .then((health) => {
      const layers = [
        { k: "core", ...health.layers.core },
        { k: "main", ...health.layers.main },
        { k: "ui", ...health.layers.ui },
      ];
      chips.replaceChildren(
        ...layers.map((l) =>
          h("span", { class: `lchip lchip--${l.k}` },
            h("span", { class: "lchip__dot" }),
            h("span", { class: "lchip__lang", text: l.language }),
            h("code", { text: l.library ? l.library : `v${l.version}` }))),
        h("span", { class: "lchip lchip--uptime", text: `up ${health.uptime}s` }),
      );
    })
    .catch(() => chips.replaceChildren(h("span", { class: "lchip lchip--bad", text: "API unreachable" })));
}

document.addEventListener("DOMContentLoaded", boot);
