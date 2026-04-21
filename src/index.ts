/**
 * apimarket.place – Alpha Edge Worker
 *
 * Exports two handlers:
 *   fetch – Hono proxy pipeline (bearer → KV → DB → upstream → waitUntil enqueue)
 *   queue – USAGE_QUEUE consumer (validate → batch insert → usage_events)
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import postgres from "postgres";
import { z } from "zod";
import { sha256Hex } from "@apimarket/shared/crypto/hash";

import type { Bindings } from "./bindings";
import { healthRoute } from "./routes/health";

// ─── Constants ────────────────────────────────────────────────────────────────

/** How long a resolved auth record lives in KV before the next DB re-check */
const KV_TTL_SECONDS = 300; // 5 min

/** Upstream request timeout — return 504 if the provider takes longer */
const UPSTREAM_TIMEOUT_MS = 30_000;

const KV_KEY_PREFIX = "key:";

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Cached, resolved record for a validated API key.
 * Stored in KV; derived from api_keys ⨝ apis ⨝ subscriptions on DB miss.
 */
type AuthRecord = {
  api_key_id: string;
  workspace_id: string;
  api_id: string;
  base_url: string;
  is_active: boolean;
  /**
   * True when the key was issued by the API's own provider workspace.
   * Owner keys (test console) bypass the subscription check — the provider
   * does not subscribe to their own API.
   */
  is_owner_key: boolean;
  /**
   * True when the consumer workspace holds at least one active subscription
   * to this API (any plan). Checked on every request to close the window
   * between subscription cancellation and key-revocation webhook delivery.
   */
  has_active_sub: boolean;
};

/**
 * Usage event enqueued to USAGE_QUEUE.
 * Field names mirror the usageEvents table in schema.ts.
 */
type UsageEventPayload = {
  api_key_id: string;
  api_id: string;
  workspace_id: string;
  endpoint_path: string;
  method: string;
  status_code: number;
  latency_ms: number;
  request_timestamp: string; // ISO-8601
  traffic_type: "buyer" | "test_console";
};

// ─── Proxy helpers ────────────────────────────────────────────────────────────

/** Extract the raw key from "Authorization: Bearer <key>" */
function extractBearerToken(headers: Headers): string | null {
  const auth = headers.get("Authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  const token = auth.slice(7).trim();
  return token.length > 0 ? token : null;
}

/** KV cache read — null on miss or stale/corrupt entry */
async function kvGet(
  kv: KVNamespace,
  keyHash: string
): Promise<AuthRecord | null> {
  return kv.get<AuthRecord>(KV_KEY_PREFIX + keyHash, "json");
}

/**
 * Postgres fallback — opens a single connection, runs one query, closes it.
 *
 * The query resolves all auth fields in a single round-trip:
 *  - api_keys ⨝ apis  → base_url, is_active, is_owner_key
 *  - EXISTS subquery   → has_active_sub (skipped for owner keys via short-circuit at callsite)
 *
 * is_owner_key: true when the key was issued by the API's provider workspace,
 * i.e. a test-console key. Provider workspace is apis.workspace_id.
 *
 * has_active_sub: true when any subscription row for this
 * (workspace, api) pair has status = 'active'.
 */
async function dbLookup(
  databaseUrl: string,
  keyHash: string
): Promise<AuthRecord | null> {
  const sql = postgres(databaseUrl, { max: 1, idle_timeout: 5 });
  try {
    const rows = await sql<AuthRecord[]>`
      SELECT
        ak.id                                  AS api_key_id,
        ak.workspace_id,
        ak.api_id,
        ak.is_active,
        a.base_url,
        (ak.workspace_id = a.workspace_id)     AS is_owner_key,
        EXISTS (
          SELECT 1
          FROM   subscriptions s
          INNER JOIN plans p ON s.plan_id = p.id
          WHERE  s.workspace_id = ak.workspace_id
            AND  p.api_id       = ak.api_id
            AND  s.status       = 'active'
        )                                      AS has_active_sub
      FROM  api_keys ak
      INNER JOIN apis a ON a.id = ak.api_id
      WHERE ak.key_hash = ${keyHash}
      LIMIT 1
    `;
    return rows[0] ?? null;
  } finally {
    await sql.end({ timeout: 5 });
  }
}

// Headers that must never reach the upstream
const BLOCKED_REQUEST_HEADERS = new Set([
  "authorization",       // consumer's API key — must not be forwarded
  "host",                // CF sets the correct Host for the upstream
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "proxy-authorization",
  "proxy-authenticate",
]);

/** Copy safe request headers, dropping auth and hop-by-hop fields */
function buildForwardHeaders(incoming: Headers): Headers {
  const out = new Headers();
  for (const [name, value] of incoming.entries()) {
    if (!BLOCKED_REQUEST_HEADERS.has(name.toLowerCase())) {
      out.set(name, value);
    }
  }
  return out;
}

// Hop-by-hop headers that should not be copied from an upstream response
const BLOCKED_RESPONSE_HEADERS = new Set([
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
]);

/** Copy safe upstream response headers and append the request-id for debugging */
function buildResponseHeaders(upstream: Headers, requestId: string): Headers {
  const out = new Headers();
  for (const [name, value] of upstream.entries()) {
    if (!BLOCKED_RESPONSE_HEADERS.has(name.toLowerCase())) {
      out.set(name, value);
    }
  }
  out.set("X-Request-Id", requestId);
  return out;
}

// ─── Hono app (fetch handler) ─────────────────────────────────────────────────

const app = new Hono<{ Bindings: Bindings }>();

// CORS — restrict origin to the configured web app
app.use("*", async (c, next) => {
  return cors({
    origin: c.env.API_MARKET_WEB_ORIGIN,
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
  })(c, next);
});

app.route("/health", healthRoute);

/**
 * Proxy route — handles all HTTP methods for any path under /:apiSlug/*.
 *
 * URL shape:  /:apiSlug/<endpoint-path>
 *
 * The :apiSlug segment is a cosmetic path prefix (typically the API's UUID
 * or a human-readable name).  It is consumed by the route pattern so that
 * the wildcard * captures only the real endpoint path forwarded upstream.
 * The slug is NOT used for auth or routing — the bearer token is the sole
 * identity mechanism.  Routing is: Bearer key → DB lookup → base_url.
 *
 * Example:
 *   GET /my-api/v1/users?page=2
 *   → slug = "my-api"  (discarded)
 *   → wildcard = "v1/users"  → upstream: {base_url}/v1/users?page=2
 */
app.all("/:apiSlug/*", async (c) => {
  const requestId = crypto.randomUUID();
  const requestTimestamp = new Date();

  if (!c.env.DATABASE_URL) {
    console.error("[proxy] DATABASE_URL is missing");
    return c.json({ error: "Worker misconfiguration: DATABASE_URL is missing" }, 503);
  }

  if (!c.env.KEY_CACHE) {
    console.error("[proxy] KEY_CACHE binding is missing");
    return c.json({ error: "Worker misconfiguration: KEY_CACHE binding is missing" }, 503);
  }

  // ── 1. Extract bearer token ────────────────────────────────────────────────
  const rawKey = extractBearerToken(c.req.raw.headers);
  if (!rawKey) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // ── 2. Hash key (Web Crypto — worker never stores raw keys) ───────────────
  const keyHash = await sha256Hex(rawKey);

  // ── 3. Resolve auth: KV first, Postgres on miss ───────────────────────────
  let auth = await kvGet(c.env.KEY_CACHE, keyHash);

  if (auth === null) {
    auth = await dbLookup(c.env.DATABASE_URL, keyHash);
    if (auth === null || !auth.is_active) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    // Subscription gate for buyer keys (owner/test-console keys skip this)
    if (!auth.is_owner_key && !auth.has_active_sub) {
      return c.json({ error: "Subscription required" }, 403);
    }

    c.executionCtx.waitUntil(
      c.env.KEY_CACHE.put(KV_KEY_PREFIX + keyHash, JSON.stringify(auth), {
        expirationTtl: KV_TTL_SECONDS,
      })
    );
  } else {
    const dbAuth = await dbLookup(c.env.DATABASE_URL, keyHash);
    if (dbAuth === null || !dbAuth.is_active) {
      c.executionCtx.waitUntil(c.env.KEY_CACHE.delete(KV_KEY_PREFIX + keyHash));
      return c.json({ error: "Unauthorized" }, 401);
    }
    // Subscription gate — evict KV entry if subscription has since lapsed
    if (!dbAuth.is_owner_key && !dbAuth.has_active_sub) {
      c.executionCtx.waitUntil(c.env.KEY_CACHE.delete(KV_KEY_PREFIX + keyHash));
      return c.json({ error: "Subscription required" }, 403);
    }
    auth = dbAuth;
  }

  // ── 4. Build upstream URL ─────────────────────────────────────────────────
  // wildcardParam: everything after "/:apiSlug/" e.g. "v1/chat/completions"
  const wildcardParam = c.req.param("*") ?? "";
  const endpointPath = wildcardParam.startsWith("/")
    ? wildcardParam
    : "/" + wildcardParam;
  const queryString = new URL(c.req.url).search; // "?k=v" or ""
  const upstreamUrl =
    auth.base_url.replace(/\/$/, "") + endpointPath + queryString;

  // ── 5. Proxy upstream ─────────────────────────────────────────────────────
  const method = c.req.method;
  const hasBody = method !== "GET" && method !== "HEAD";
  const controller = new AbortController();
  const timeoutHandle = setTimeout(
    () => controller.abort(),
    UPSTREAM_TIMEOUT_MS
  );

  let upstreamRes: Response;
  const t0 = Date.now();

  try {
    const forwardHeaders = buildForwardHeaders(c.req.raw.headers);
    forwardHeaders.set("x-internal-service-key", c.env.INTERNAL_SERVICE_SECRET);
    upstreamRes = await fetch(upstreamUrl, {
      method,
      headers: forwardHeaders,
      body: hasBody ? c.req.raw.body : undefined,
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timeoutHandle);
    if (err instanceof Error && err.name === "AbortError") {
      return c.json({ error: "Gateway Timeout" }, 504);
    }
    console.error("[proxy] upstream fetch failed:", err);
    return c.json({ error: "Bad Gateway" }, 502);
  }

  clearTimeout(timeoutHandle);
  const latencyMs = Date.now() - t0;

  // ── 6. Async usage metering — never blocks the response ───────────────────
  const usageEvent: UsageEventPayload = {
    api_key_id: auth.api_key_id,
    api_id: auth.api_id,
    workspace_id: auth.workspace_id,
    endpoint_path: endpointPath,
    method,
    status_code: upstreamRes.status,
    latency_ms: latencyMs,
    request_timestamp: requestTimestamp.toISOString(),
    traffic_type:
      c.req.raw.headers.get("X-ApiMarket-Test-Console") === "1" ? "test_console" : "buyer",
  };

  c.executionCtx.waitUntil(
    c.env.USAGE_QUEUE.send(usageEvent).catch((err) => {
      console.error("[metering] queue enqueue failed:", err);
    })
  );

  // ── 7. Return upstream response transparently ─────────────────────────────
  return new Response(upstreamRes.body, {
    status: upstreamRes.status,
    headers: buildResponseHeaders(upstreamRes.headers, requestId),
  });
});

// ─── Queue consumer ───────────────────────────────────────────────────────────

/**
 * Validates queue message bodies before DB insertion.
 * UUIDs are validated strictly; numeric fields must be non-negative integers.
 * timestamp must be a valid ISO-8601 datetime string.
 */
const queuePayloadSchema = z.object({
  api_key_id: z.string().uuid(),
  api_id: z.string().uuid(),
  workspace_id: z.string().uuid(),
  endpoint_path: z.string().min(1).max(2048),
  method: z.string().min(1).max(16),
  status_code: z.number().int().min(100).max(599),
  latency_ms: z.number().int().nonnegative(),
  request_timestamp: z.string().datetime(),
  traffic_type: z.enum(["buyer", "test_console"]).optional(),
});

type ValidatedPayload = z.infer<typeof queuePayloadSchema>;

/** Row shape expected by postgres.js bulk insert into usage_events */
type InsertRow = {
  api_key_id: string;
  api_id: string;
  workspace_id: string;
  endpoint_path: string;
  method: string;
  status_code: number;
  latency_ms: number;
  request_timestamp: Date;
};

function toInsertRow(p: ValidatedPayload): InsertRow {
  return { ...p, request_timestamp: new Date(p.request_timestamp) };
}

/**
 * Batch-insert rows into usage_events.
 * Opens a single connection, inserts all rows in one statement, closes cleanly.
 */
async function batchInsert(
  databaseUrl: string,
  rows: InsertRow[]
): Promise<void> {
  const sql = postgres(databaseUrl, { max: 1, idle_timeout: 5 });
  try {
    await sql`
      INSERT INTO usage_events
        (api_key_id, api_id, workspace_id, endpoint_path, method,
         status_code, latency_ms, request_timestamp)
      VALUES ${sql(
        rows,
        "api_key_id",
        "api_id",
        "workspace_id",
        "endpoint_path",
        "method",
        "status_code",
        "latency_ms",
        "request_timestamp"
      )}
    `;
  } finally {
    await sql.end({ timeout: 5 });
  }
}

/**
 * USAGE_QUEUE consumer.
 *
 * Retry/drop semantics:
 *   - Invalid payload  → message.ack()  (permanently dropped — retrying won't fix schema errors)
 *   - DB success       → implicit ack   (handler returns normally)
 *   - DB failure       → message.retry() on every valid message (transient — let CF re-deliver)
 */
async function queueHandler(
  batch: MessageBatch<unknown>,
  env: Bindings
): Promise<void> {
  type Pair = { message: Message<unknown>; row: InsertRow; trafficType: "buyer" | "test_console" };
  const valid: Pair[] = [];
  let invalidCount = 0;

  // ── 1. Validate each message ───────────────────────────────────────────────
  for (const message of batch.messages) {
    const result = queuePayloadSchema.safeParse(message.body);

    if (!result.success) {
      // Log enough context to debug without exposing secret values
      console.error("[consumer] invalid payload — dropping permanently", {
        messageId: message.id,
        issues: result.error.issues.map((i) => ({
          path: i.path,
          message: i.message,
        })),
      });
      message.ack(); // prevent infinite retry loop
      invalidCount++;
      continue;
    }

    valid.push({
      message,
      row: toInsertRow(result.data),
      trafficType: result.data.traffic_type ?? "buyer",
    });
  }

  const testTrafficCount = valid.filter((v) => v.trafficType === "test_console").length;
  console.log(
    `[consumer] batch=${batch.messages.length} valid=${valid.length} invalid=${invalidCount} testTraffic=${testTrafficCount}`
  );

  if (valid.length === 0) return;

  // ── 2. Batch insert all valid rows ─────────────────────────────────────────
  try {
    await batchInsert(env.DATABASE_URL, valid.map((v) => v.row));
    console.log(`[consumer] inserted ${valid.length} usage event(s)`);
    // Handler returns normally → all non-retried messages are implicitly acked
  } catch (err) {
    // Treat all DB errors as transient — retry the valid messages
    console.error(
      `[consumer] batch insert failed — marking ${valid.length} message(s) for retry`,
      err instanceof Error ? err.message : String(err)
    );
    for (const { message } of valid) message.retry();
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

export default {
  fetch: app.fetch,
  queue: queueHandler,
};
