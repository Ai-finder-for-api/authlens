/** Typed-ish fetch helpers for the Python API. */

export interface Layer {
  language: string;
  version: string;
  library?: string;
  backend?: string;
}

export interface Health {
  ok: boolean;
  app: string;
  version: string;
  uptime: number;
  layers: { core: Layer; main: Layer; ui: Layer };
  keys: number;
  samples: { id: string; label: string; hint: string; token: string }[];
}

export interface KeyInfo {
  id: string;
  alg: string;
  curve: string;
  created: number;
  jwk: Record<string, unknown>;
  thumbprint: string;
  thumbprint_native: string;
  thumbprint_agrees: boolean;
}

export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
}

export interface Risk {
  findings: Finding[];
  score: number;
  grade: string;
}

export interface Segment {
  role: string;
  index: number;
  offset: number;
  length: number;
  bytes: number;
  b64_ok: boolean;
  json: unknown;
}

export interface DigestRow {
  index: number;
  bytes: number;
  digest: string;
  json: unknown;
}

export interface SdView {
  hash: string;
  digests: DigestRow[];
  match: {
    pairs: { digest: string; disclosure: number | null }[];
    matched: number;
    digest_count: number;
    unused_disclosures: number[];
  };
  disclosure_count: number;
  visible_claims: string[];
  hidden_digests: number;
}

export interface Verification {
  ok: boolean;
  type?: string;
  kind?: string | null;
  message?: string;
  source?: string;
  algs?: string[];
  claims?: Record<string, unknown>;
  header?: Record<string, unknown>;
}

export interface Analysis {
  ok: boolean;
  token: string;
  format: string;
  nbytes: number;
  segments: Segment[];
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
  notes: string[];
  risk: Risk | null;
  thumbprint: string | null;
  verification: Verification | null;
  sd: SdView | null;
  timeline: Record<string, number> | null;
}

export async function api<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`${res.status}: ${text.slice(0, 200)}`);
  }
  if (!res.ok) {
    const err = data as { message?: string };
    throw new Error(err.message ?? `request failed (${res.status})`);
  }
  return data as T;
}
