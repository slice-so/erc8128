import { env } from "cloudflare:workers"
import { Hono } from "hono"
import { cors } from "hono/cors"
import type { ContentfulStatusCode } from "hono/utils/http-status"
import { createPublicClient, http } from "viem"
import { mainnet } from "viem/chains"
import {
  type AuthInstance,
  getAuthInstance
} from "./lib/erc8128/backend-config"
import { verifyDeletePlaygroundRequest } from "./lib/erc8128/playground-delete-verify"
import { prepareVerifyRequest } from "./lib/erc8128/playground-forwarding"
import {
  parseStorageMode,
  parseStorageModeFromEnv,
  type StorageMode
} from "./lib/erc8128/storage-header"

declare global {
  namespace Cloudflare {
    interface Env {
      SECRET_ALCHEMY_KEY?: string
      ERC8128_STORAGE_DEFAULT?: string
    }
  }
}

// ── Shared infra ─────────────────────────────────────

const rpcUrl = `https://eth-mainnet.g.alchemy.com/v2/${env.SECRET_ALCHEMY_KEY ?? ""}`
const publicClient = createPublicClient({
  chain: mainnet,
  transport: http(rpcUrl)
})

type Env = {
  Variables: {
    storageMode: StorageMode
    authInstance: AuthInstance
  }
}

// ── Helpers ──────────────────────────────────────────

const mapErrorReason = (reason: string): string => {
  if (reason === "missing_signature") return "missing_headers"
  if (reason === "missing_request_context") return "missing_headers"
  return reason
}

const reasonToStatus = (reason: string): number => {
  if (
    reason === "missing_headers" ||
    reason === "bad_signature_input" ||
    reason === "bad_keyid"
  )
    return 400
  return 401
}

type HeaderMap = Record<string, string[]>

const collectHeaders = (headers: Headers): HeaderMap => {
  const result: HeaderMap = {}
  for (const [key, value] of headers.entries()) {
    const k = key.toLowerCase()
    if (!result[k]) {
      result[k] = []
    }
    result[k].push(value)
  }
  return result
}

const verbosePayload = (
  request: Request,
  verification: Record<string, unknown>
) => {
  const url = new URL(request.url)
  return {
    ok: verification.ok,
    verified: verification.ok,
    receivedAt: new Date().toISOString(),
    request: {
      method: request.method,
      path: url.pathname,
      query: url.search,
      authority: request.headers.get("host")
    },
    signatureHeaders: {
      signatureInput: request.headers.get("signature-input"),
      signature: request.headers.get("signature")
    },
    verification,
    headers: collectHeaders(request.headers)
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
    const authInstance = getAuthInstance(
      storageMode,
      publicClient.verifyMessage,
      new URL(c.req.url).origin
    )
    c.set("storageMode", storageMode)
    c.set("authInstance", authInstance)
    await next()
  })

  // Preserve the public discovery URL while delegating document generation
  // to the erc8128 better-auth plugin.
  .get("/.well-known/erc8128", (c) => {
    const rewrittenUrl = new URL("/api/auth/.well-known/erc8128", c.req.url)
    return c.var.authInstance.handler(
      new Request(rewrittenUrl.toString(), {
        method: "GET",
        headers: c.req.raw.headers
      })
    )
  })

  // Signature verification — rewrites to /api/auth/verify so the erc8128
  // middleware intercepts. Route policy is enforced at the plugin level
  // (DELETE = non-replayable, everything else = replayable class-bound).
  .all("/verify", async (c) => {
    const request = c.req.raw
    const { storageMode, authInstance } = c.var
    const verbose =
      c.req.query("verbose") === "1" || c.req.query("verbose") === "true"

    if (request.method === "DELETE") {
      const t0 = performance.now()
      const responseHeaders = new Headers()
      const result = await verifyDeletePlaygroundRequest({
        request,
        storageMode,
        verifyMessage: publicClient.verifyMessage,
        setHeaders: (name, value) => {
          responseHeaders.set(name, value)
        }
      })
      const verifyMs = Math.round((performance.now() - t0) * 10) / 10
      const metadata = {
        verifyMs,
        storageMode,
        cacheStrategy: authInstance.cacheStrategy
      }
      const acceptSignature = responseHeaders.get("accept-signature")

      if (result.ok) {
        const payload = verbose
          ? { ...verbosePayload(request, result), ...metadata }
          : { ...result, ...metadata }

        const res = c.json(payload, 200)
        if (acceptSignature) {
          res.headers.set("accept-signature", acceptSignature)
        }
        return res
      }

      const reason = mapErrorReason(result.reason)
      const verification = {
        ok: false as const,
        reason,
        ...(result.detail ? { detail: result.detail } : {})
      }
      const status = reasonToStatus(reason)
      const payload = verbose
        ? {
            ...verbosePayload(request, verification),
            ...(acceptSignature ? { "accept-signature": acceptSignature } : {}),
            ...metadata
          }
        : {
            ...verification,
            ...(acceptSignature ? { "accept-signature": acceptSignature } : {}),
            ...metadata
          }

      const res = c.json(payload, status as ContentfulStatusCode)
      if (acceptSignature) {
        res.headers.set("accept-signature", acceptSignature)
      }
      return res
    }

    // Rewrite URL so better-auth routes to the playground endpoint
    const origin = new URL(request.url).origin
    const rewrittenUrl = new URL("/api/auth/verify", origin)
    for (const [k, v] of new URL(request.url).searchParams) {
      rewrittenUrl.searchParams.set(k, v)
    }

    const preparedRequest = await prepareVerifyRequest(request, rewrittenUrl)
    if (!preparedRequest.ok) {
      return c.json(
        {
          ok: false,
          error: preparedRequest.error,
          detail: preparedRequest.detail
        },
        400
      )
    }

    const rewrittenRequest = preparedRequest.request

    const t0 = performance.now()

    try {
      const authResponse = await authInstance.handler(rewrittenRequest)
      const verifyMs = Math.round((performance.now() - t0) * 10) / 10

      const authResponseText = await authResponse.clone().text()
      const body =
        authResponseText.length > 0
          ? (() => {
              try {
                return JSON.parse(authResponseText) as Record<string, unknown>
              } catch {
                return null
              }
            })()
          : null

      const metadata = {
        verifyMs,
        storageMode,
        cacheStrategy: authInstance.cacheStrategy
      }

      const acceptSignature = authResponse.headers.get("accept-signature")

      // Success
      if (authResponse.ok && body?.ok === true) {
        const payload = verbose
          ? { ...verbosePayload(request, body), ...metadata }
          : { ...body, ...metadata }

        const res = c.json(payload, 200)
        if (acceptSignature)
          res.headers.set("accept-signature", acceptSignature)
        return res
      }

      // Verification failure
      const reason = mapErrorReason((body?.reason as string) || "unknown")
      const detail = (body?.detail as string) || (body?.message as string) || ""
      const status = reasonToStatus(reason)

      const verification = {
        ok: false as const,
        reason,
        ...(detail ? { detail } : {})
      }

      const payload = verbose
        ? {
            ...verbosePayload(request, verification),
            ...(acceptSignature ? { "accept-signature": acceptSignature } : {}),
            ...metadata
          }
        : {
            ...verification,
            ...(acceptSignature ? { "accept-signature": acceptSignature } : {}),
            ...metadata
          }

      const res = c.json(payload, status as ContentfulStatusCode)
      if (acceptSignature) res.headers.set("accept-signature", acceptSignature)
      return res
    } catch (error) {
      const verifyMs = Math.round((performance.now() - t0) * 10) / 10
      const detail =
        error instanceof Error
          ? error.message
          : typeof error === "string"
            ? error
            : "unknown_error"

      const payload = verbose
        ? {
            ok: false,
            verified: false,
            error: "verification_error",
            detail,
            request: {
              method: request.method,
              path: new URL(request.url).pathname,
              query: new URL(request.url).search,
              authority: request.headers.get("host")
            },
            signatureHeaders: {
              signatureInput: request.headers.get("signature-input"),
              signature: request.headers.get("signature")
            },
            verifyMs
          }
        : {
            ok: false,
            verified: false,
            error: "verification_error",
            detail,
            verifyMs
          }

      return c.json(payload, 500)
    }
  })

  // Pass all /api/auth/* requests to better-auth so plugin-registered
  // endpoints (discovery document, verify, invalidate) work natively.
  .on(
    ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    "/api/auth/*",
    (c) => c.var.authInstance.handler(c.req.raw)
  )
