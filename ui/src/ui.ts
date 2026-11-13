/** Shared building blocks: cards, code blocks, fields, badges. */
import { copy, h, Props } from "./dom.js";

type Child = Node | string | number | null | undefined | false;

export function card(title: string, subtitle: string, ...body: Child[]): HTMLElement {
  return h(
    "section",
    { class: "card" },
    h(
      "header",
      { class: "card__head" },
      h("h2", { class: "card__title", text: title }),
      subtitle ? h("p", { class: "card__sub", text: subtitle }) : null,
    ),
    h("div", { class: "card__body" }, ...body),
  );
}

export function code(text: string, cls = "", label = "Copy"): HTMLElement {
  const block = h("pre", { class: `code ${cls}` }, h("code", { text }));
  const btn = h("button", { class: "code__copy", type: "button", text: label }, );
  btn.addEventListener("click", () => void copy(text));
  return h("div", { class: "code-wrap" }, block, btn);
}

export function field(label: string, control: HTMLElement, hint = ""): HTMLElement {
  return h(
    "label",
    { class: "field" },
    h("span", { class: "field__label", text: label }),
    control,
    hint ? h("span", { class: "field__hint", text: hint }) : null,
  );
}

export function input(props: Props = {}): HTMLInputElement {
  return h("input", { class: "input", spellcheck: false, ...props });
}

export function textarea(props: Props = {}): HTMLTextAreaElement {
  return h("textarea", { class: "input input--area", spellcheck: false, ...props });
}

export function select(options: { value: string; label: string }[], value?: string): HTMLSelectElement {
  const el = h("select", { class: "input input--select" });
  for (const opt of options) {
    const o = h("option", { value: opt.value, text: opt.label });
    if (opt.value === value) o.selected = true;
    el.append(o);
  }
  return el;
}

export function button(label: string, onClick: () => void, kind: "primary" | "ghost" | "quiet" = "primary"): HTMLButtonElement {
  const el = h("button", { class: `btn btn--${kind}`, type: "button" }, h("span", { text: label }));
  el.addEventListener("click", onClick);
  return el;
}

export function badge(text: string, kind = ""): HTMLElement {
  return h("span", { class: `badge ${kind ? `badge--${kind}` : ""}`, text });
}

export function kv(label: string, value: string | number, mono = false): HTMLElement {
  return h(
    "div",
    { class: "kv" },
    h("span", { class: "kv__k", text: label }),
    h("span", { class: `kv__v ${mono ? "mono" : ""}`, text: String(value) }),
  );
}

export function empty(text: string): HTMLElement {
  return h("p", { class: "empty", text });
}

export function spinner(): HTMLElement {
  return h("span", { class: "spinner" });
}
