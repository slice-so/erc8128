import { env } from "cloudflare:workers"
import { Hono } from "hono"
import { cors } from "hono/cors"
import {
  type AuthInstance,
  getAuthInstance
} from "./lib/erc8128/backend-config"
import {
  parseStorageMode,
  parseStorageModeFromEnv,
  type StorageMode
} from "./lib/erc8128/storage-header"
import {
  buildVerifyExceptionResponse,
  buildVerifyProtectResponse
} from "./lib/erc8128/verify-response"

declare global {
  namespace Cloudflare {
    interface Env {
      SECRET_ALCHEMY_KEY?: string
      ERC8128_STORAGE_DEFAULT?: string
    }
  }
}

// ── Shared infra ─────────────────────────────────────

type Env = {
  Variables: {
    storageMode: StorageMode
    authInstance: AuthInstance
  }
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
    await next()
    c.res.headers.set("cache-control", "no-store")
  })
  .use(async (c, next) => {
    const envDefault = parseStorageModeFromEnv(env.ERC8128_STORAGE_DEFAULT)
    const storageMode = parseStorageMode(c.req.raw.headers, envDefault)
    const authInstance = getAuthInstance(storageMode, new URL(c.req.url).origin)
    c.set("storageMode", storageMode)
    c.set("authInstance", authInstance)
    await next()
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
    const request = c.req.raw
    const { storageMode, authInstance } = c.var
    const verbose =
      c.req.query("verbose") === "1" || c.req.query("verbose") === "true"

    const t0 = performance.now()

    try {
      const protectResult = await authInstance.erc8128.protect(request)
      const verifyMs = Math.round((performance.now() - t0) * 10) / 10
      const response = await buildVerifyProtectResponse({
        request,
        protectResult,
        verbose,
        metadata: {
          verifyMs,
          storageMode,
          cacheStrategy: authInstance.cacheStrategy
        }
      })

      const res = c.json(response.payload, response.status)
      for (const [key, value] of response.headers.entries()) {
        res.headers.set(key, value)
      }
      return res
    } catch (error) {
      const verifyMs = Math.round((performance.now() - t0) * 10) / 10
      const response = buildVerifyExceptionResponse({
        request,
        error,
        verifyMs,
        verbose
      })

      const res = c.json(response.payload, response.status)
      for (const [key, value] of response.headers.entries()) {
        res.headers.set(key, value)
      }
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
