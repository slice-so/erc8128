import { env } from "cloudflare:workers"
import { type Context, Hono } from "hono"
import { cors } from "hono/cors"
import type { ContentfulStatusCode } from "hono/utils/http-status"
import {
  type AuthInstance,
  getAuthInstance,
  getVerifyMessageFn
} from "./lib/erc8128/backend-config"
import {
  parseStorageMode,
  type StorageMode
} from "./lib/erc8128/storage-header"
import {
  buildVerifyExceptionResponse,
  buildVerifyProtectResponse
} from "./lib/erc8128/verify-response"

// ── Shared infra ─────────────────────────────────────

type Env = {
  Variables: {
    storageMode: StorageMode
    authInstance: AuthInstance
  }
}

function jsonWithHeaders(
  c: Context<Env>,
  response: {
    payload: Record<string, unknown>
    status: ContentfulStatusCode
    headers: Headers
  }
) {
  const res = c.json(response.payload, response.status)
  for (const [key, value] of response.headers.entries()) {
    res.headers.set(key, value)
  }
  return res
}

// ── App ──────────────────────────────────────────────

const app = new Hono<Env>()

export default app
  .use(
    cors({
      origin: "*",
      allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      allowHeaders: ["*"],
      maxAge: 86400
    })
  )
  .use(async (c, next) => {
    const storageMode = parseStorageMode(c.req.raw.headers)

    const authInstance = getAuthInstance(
      storageMode,
      new URL(c.req.url).origin,
      {
        hyperdrive: env.HYPERDRIVE.connectionString,
        redisUrl: env.REDIS_URL
      },
      getVerifyMessageFn(env.SECRET_ALCHEMY_KEY)
    )
    c.set("storageMode", storageMode)
    c.set("authInstance", authInstance)
    await next()

    try {
      c.executionCtx.waitUntil(authInstance.close())
    } catch {
      await authInstance.close()
    }
  })

  // Preserve the public discovery URL while delegating document generation
  // to the erc8128 better-auth plugin.
  .get("/.well-known/erc8128", async (c) => {
    const config = await c.var.authInstance.erc8128.getConfig(c.req.raw)
    return c.json(config)
  })

  // Signature verification for the public playground route. Better-auth owns
  // verification and storage; Hono keeps owning the route.
  .all("/verify", async (c) => {
    const { storageMode, authInstance } = c.var

    const t0 = performance.now()

    try {
      const { result: protectResult, cachedVerification } =
        await authInstance.protect(c.req.raw)

      const verifyMs = Math.round((performance.now() - t0) * 10) / 10
      const response = await buildVerifyProtectResponse({
        protectResult,
        metadata: {
          verifyMs,
          storageMode,
          cacheStrategy: authInstance.cacheStrategy,
          cachedVerification
        }
      })

      const res = jsonWithHeaders(c, response)
      res.headers.set("cache-control", "no-store")
      return res
    } catch (error) {
      const verifyMs = Math.round((performance.now() - t0) * 10) / 10
      const response = buildVerifyExceptionResponse({
        error,
        verifyMs
      })

      const res = jsonWithHeaders(c, response)
      res.headers.set("cache-control", "no-store")
      return res
    }
  })

  // Pass all /api/auth/* requests to better-auth so plugin-registered
  // endpoints (discovery document, verify, invalidate) work natively.
  .on(
    ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    "/api/auth/*",
    (c) => c.var.authInstance.handler(c.req.raw)
  )
