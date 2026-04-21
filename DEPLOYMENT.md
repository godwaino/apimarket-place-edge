# Cloudflare Worker deployment checklist

## 1) Create Cloudflare resources
- KV namespace for key cache (`KEY_CACHE` binding)
- Queue: `apimarket-usage-events`
- Dead-letter queue: `apimarket-usage-events-dlq`

## 2) Wire `wrangler.jsonc`
Replace placeholders in `apps/edge/wrangler.jsonc`:
- `<local-preview-kv-namespace-id>`
- `<staging-kv-namespace-id>`
- `<prod-kv-namespace-id>`

## 3) Required secrets
Set per environment:

```bash
pnpm --filter @apimarket-place/edge wrangler secret put DATABASE_URL
pnpm --filter @apimarket-place/edge wrangler secret put INTERNAL_SERVICE_SECRET
```

Optional (reserved for upcoming billing/encryption phases):
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `ENCRYPTION_MASTER_KEY`

## 4) Local run
```bash
pnpm dev:edge
```

## 5) Deploy
```bash
pnpm --filter @apimarket-place/edge deploy --env staging
pnpm --filter @apimarket-place/edge deploy --env production
```
