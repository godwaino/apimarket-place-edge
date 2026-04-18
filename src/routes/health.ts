import { Hono } from "hono";

import type { Bindings } from "../bindings";

export const healthRoute = new Hono<{ Bindings: Bindings }>();

healthRoute.get("/", (c) => {
  return c.json({ ok: true, env: c.env.APP_ENV });
});
