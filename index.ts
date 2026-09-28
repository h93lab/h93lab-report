// Shared report intake Worker for h93lab apps (docs/11-plan.md §2;
// docs/04-architecture.md §6). Each app posts to /<app>/v1/report; only apps in
// APPS are accepted and every stored key is prefixed with the app id.
// Dependency-free: only Web platform globals provided by the Workers runtime.
// Receives category, app version, OS and the user's explicitly included text or
// note. Never keys, provider URLs or chat history. Rate-limited per IP without
// ever storing the raw IP.

// Apps allowed to post reports. Add a new project's id here.
const APPS = ['hllm'] as const;
type App = (typeof APPS)[number];
const REPORT_PATH = /^\/([a-z0-9-]{1,32})\/v1\/report$/;

const CATEGORIES = ['harmful', 'inaccurate', 'sexual', 'hate', 'self-harm', 'other'] as const;
type Category = (typeof CATEGORIES)[number];

const MAX_BODY_BYTES = 8 * 1024;
const MAX_APP_VERSION = 64;
const MAX_OS = 64;
const MAX_MESSAGE_TEXT = 4_000;
const MAX_NOTE = 1_000;
const REPORT_TTL_SECONDS = 90 * 24 * 60 * 60;

const RATE_LIMIT = 10;
const RATE_WINDOW_SECONDS = 60 * 60;

// Minimal KV binding shape; avoids a dependency on @cloudflare/workers-types.
interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}

interface Env {
  REPORTS: KVNamespace;
  // Owner sets this with `wrangler secret put RATE_SALT`. Combined with the UTC
  // day it salts the IP hash and rotates the rate-limit keys daily. Required:
  // without it the worker fails closed (500) instead of hashing the raw IP.
  RATE_SALT?: string;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Returns undefined when absent, null when present but not a string, and the
// capped value otherwise. Callers turn null into a 400.
function readString(value: unknown, max: number): string | undefined | null {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') return null;
  return value.slice(0, max);
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function isRateLimited(
  request: Request,
  app: App,
  salt: string,
  env: Env,
): Promise<boolean> {
  const ip = request.headers.get('cf-connecting-ip') ?? 'unknown';
  const day = new Date().toISOString().slice(0, 10);
  const hash = await sha256Hex(`${salt}:${day}:${ip}`);
  const key = `rate:${app}:${hash}`;
  const current = Number.parseInt((await env.REPORTS.get(key)) ?? '0', 10) || 0;
  if (current >= RATE_LIMIT) return true;
  await env.REPORTS.put(key, String(current + 1), { expirationTtl: RATE_WINDOW_SECONDS });
  return false;
}

// Reads at most MAX_BODY_BYTES: the declared Content-Length is checked before
// anything is read, and a chunked body is abandoned as soon as it exceeds the
// cap. Returns null when the body is too large.
async function readBodyCapped(request: Request): Promise<string | null> {
  const declared = Number.parseInt(request.headers.get('content-length') ?? '', 10);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return null;
  const body = request.body;
  if (body === null) return '';
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  let size = 0;
  for (const chunk of chunks) size += chunk.byteLength;
  const merged = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const match = REPORT_PATH.exec(url.pathname);
    const app = match?.[1];
    if (request.method !== 'POST' || app === undefined || !APPS.includes(app as App)) {
      return new Response('Not found', { status: 404 });
    }

    // Fail closed: without the salt the rate-limit key would be an unsalted
    // hash of the IP, which is a stored IP by another name.
    const salt = env.RATE_SALT;
    if (salt === undefined || salt === '') {
      return json(500, { ok: false, error: 'server-misconfigured' });
    }

    const contentType = request.headers.get('content-type') ?? '';
    if (!contentType.toLowerCase().startsWith('application/json')) {
      return json(400, { ok: false, error: 'content-type' });
    }

    if (await isRateLimited(request, app as App, salt, env)) {
      return json(429, { ok: false, error: 'rate-limited' });
    }

    const raw = await readBodyCapped(request);
    if (raw === null) {
      return json(413, { ok: false, error: 'body-too-large' });
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return json(400, { ok: false, error: 'json' });
    }
    if (!isRecord(parsed)) {
      return json(400, { ok: false, error: 'json' });
    }

    const category = parsed.category;
    if (typeof category !== 'string' || !CATEGORIES.includes(category as Category)) {
      return json(400, { ok: false, error: 'category' });
    }

    // Rebuild the record from known fields only: unknown fields are dropped and
    // every accepted field is a capped string.
    const appVersion = readString(parsed.appVersion, MAX_APP_VERSION);
    const os = readString(parsed.os, MAX_OS);
    if (appVersion === null || os === null) {
      return json(400, { ok: false, error: 'field-type' });
    }

    const record: Record<string, string> = {
      app,
      category: category as Category,
      appVersion: appVersion ?? '',
      os: os ?? '',
    };
    if (parsed.messageText !== undefined) {
      const messageText = readString(parsed.messageText, MAX_MESSAGE_TEXT);
      if (messageText === null || messageText === undefined) {
        return json(400, { ok: false, error: 'messageText' });
      }
      record.messageText = messageText;
    }
    if (parsed.note !== undefined) {
      const note = readString(parsed.note, MAX_NOTE);
      if (note === null || note === undefined) {
        return json(400, { ok: false, error: 'note' });
      }
      record.note = note;
    }

    const key = `report:${app}:${Date.now()}-${crypto.randomUUID()}`;
    await env.REPORTS.put(
      key,
      JSON.stringify({ ...record, receivedAt: new Date().toISOString() }),
      { expirationTtl: REPORT_TTL_SECONDS },
    );

    return json(202, { ok: true });
  },
};
