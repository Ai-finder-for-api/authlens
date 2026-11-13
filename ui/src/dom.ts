/** Tiny DOM layer: no framework, no virtual DOM, just functions. */

type Child = Node | string | number | null | undefined | false;

export interface Props {
  class?: string;
  text?: string;
  html?: string;
  dataset?: Record<string, string>;
  [key: string]: unknown;
}

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props | null = null,
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") node.className = String(value);
      else if (key === "text") node.textContent = String(value);
      else if (key === "html") node.innerHTML = String(value);
      else if (key === "dataset") Object.assign(node.dataset, value as Record<string, string>);
      else if (key.startsWith("on") && typeof value === "function") {
        node.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
      } else if (key in node && key !== "list") {
        (node as unknown as Record<string, unknown>)[key] = value;
      } else {
        node.setAttribute(key, String(value));
      }
    }
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === "string" || typeof child === "number" ? String(child) : child);
  }
  return node;
}

export function clear(node: HTMLElement): HTMLElement {
  node.replaceChildren();
  return node;
}

export function toast(message: string, kind: "ok" | "bad" | "info" = "info"): void {
  let host = document.querySelector<HTMLElement>(".toasts");
  if (!host) {
    host = h("div", { class: "toasts" });
    document.body.append(host);
  }
  const item = h("div", { class: `toast toast--${kind}`, text: message });
  host.append(item);
  setTimeout(() => item.classList.add("toast--out"), 2600);
  setTimeout(() => item.remove(), 3100);
}

export async function copy(text: string, label = "Copied"): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} to clipboard`, "ok");
  } catch {
    toast("Clipboard blocked by the browser", "bad");
  }
}

export function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export function bytes(n: number): string {
  return n < 1000 ? `${n} B` : `${(n / 1000).toFixed(1)} kB`;
}
