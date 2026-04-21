export type Bindings = {
  APP_ENV: "local" | "staging" | "production";
  API_MARKET_WEB_ORIGIN: string;
  DATABASE_URL: string;

  // Runtime bindings
  KEY_CACHE: KVNamespace;
  USAGE_QUEUE: Queue;

  INTERNAL_SERVICE_SECRET: string;

  // Reserved for later billing/encryption phases.
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  ENCRYPTION_MASTER_KEY?: string;
};
