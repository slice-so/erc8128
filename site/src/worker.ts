import { env } from "cloudflare:workers"
import { createPublicClient, http } from "viem"
import { mainnet } from "viem/chains"
import { getAuthInstance } from "./lib/erc8128/backend-config"
import {
  parseStorageMode,
  parseStorageModeFromEnv
} from "./lib/erc8128/storage-header"

declare global {
  namespace Cloudflare {
    interface Env {
      SECRET_ALCHEMY_KEY?: string
      ERC8128_STORAGE_DEFAULT?: string
    }
  }
}

const rpcUrl = `https://eth-mainnet.g.alchemy.com/v2/${env.SECRET_ALCHEMY_KEY ?? ""}`
const publicClient = createPublicClient({
  chain: mainnet,
  transport: http(rpcUrl)
})

// ── Helpers ──────────────────────────────────────────

type HeaderMap = Record<string, string[]>

const collectHeaders = (headers: Headers): HeaderMap => {
  const result: HeaderMap = {}

  for (const [key, value] of headers.entries()) {
    const normalizedKey = key.toLowerCase()
    if (!result[normalizedKey]) {
      result[normalizedKey] = []
    }
    result[normalizedKey].push(value)
  }

  return result
}

const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers": "*"
    }
  })

const isVerboseRequest = (request: Request): boolean => {
  const verbose = new URL(request.url).searchParams.get("verbose")
  return verbose === "1" || verbose === "true"
}

/**
 * Map middleware error reason codes to verifier reason codes.
 * The erc8128 middleware pre-checks for missing signature headers and
 * returns "missing_signature"; the original verifier returned "missing_headers".
 */
const mapErrorReason = (reason: string): string => {
  if (reason === "missing_signature") return "missing_headers"
  if (reason === "missing_request_context") return "missing_headers"
  return reason
}

/**
 * Determine HTTP status from the verification failure reason,
 * matching the original verificationStatus() behavior.
 */
const verificationStatus = (reason: string): number => {
  if (
    reason === "missing_headers" ||
    reason === "bad_signature_input" ||
    reason === "bad_keyid"
  ) {
    return 400
  }

  return 401
}

const createVerbosePayload = (
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

const createErrorPayload = (
  request: Request,
  error: unknown,
  verbose: boolean
) => {
  const url = new URL(request.url)
  const detail =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "unknown_error"

  if (!verbose) {
    return {
      ok: false,
      verified: false,
      error: "verification_error",
      detail
    }
  }

  return {
    ok: false,
    verified: false,
    error: "verification_error",
    detail,
    request: {
      method: request.method,
      path: url.pathname,
      query: url.search,
      authority: request.headers.get("host")
    },
    signatureHeaders: {
      signatureInput: request.headers.get("signature-input"),
      signature: request.headers.get("signature")
    }
  }
}

const corsHeaders = new Response(null, {
  status: 204,
  headers: {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "access-control-allow-headers": "*",
    "access-control-max-age": "86400"
  }
})

// ── Main handler ─────────────────────────────────────

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)

    if (url.pathname !== "/verify" && url.pathname !== "/.well-known/erc8128") {
      return new Response("Not Found", { status: 404 })
    }

    if (request.method === "OPTIONS") {
      return corsHeaders.clone()
    }

    // ── /.well-known/erc8128 → plugin discovery document ──
    if (url.pathname === "/.well-known/erc8128") {
      const envDefault = parseStorageModeFromEnv(env.ERC8128_STORAGE_DEFAULT)
      const storageMode = parseStorageMode(request.headers, envDefault)
      const authInstance = getAuthInstance(
        storageMode,
        publicClient.verifyMessage,
        url.origin
      )
      const rewrittenRequest = new Request(
        `${url.origin}/api/auth/.well-known/erc8128`,
        { method: "GET", headers: request.headers }
      )
      return authInstance.handler(rewrittenRequest)
    }

    // ── /verify → process through better-auth erc8128 middleware ──
    // The request is rewritten to /api/auth/verify so it matches the
    // custom playground endpoint registered in better-auth. The erc8128
    // plugin's middleware hook intercepts the request BEFORE the endpoint
    // runs, performing signature verification with cache, nonce consumption,
    // and invalidation checks (all configured via routePolicy).
    //
    // If verification fails, the middleware returns a 401 directly.
    // If verification succeeds, the playground endpoint handler runs
    // and returns the parsed verification metadata.

    // Validate JSON body if present (preserves original behavior)
    if (request.headers.get("content-type")?.includes("application/json")) {
      try {
        const bodyText = await request.clone().text()
        if (bodyText) JSON.parse(bodyText)
      } catch {
        return json(
          {
            ok: false,
            error: "invalid_json",
            detail: "Request body is not valid JSON"
          },
          400
        )
      }
    }

    const envDefault = parseStorageModeFromEnv(env.ERC8128_STORAGE_DEFAULT)
    const storageMode = parseStorageMode(request.headers, envDefault)
    const verbose = isVerboseRequest(request)

    const baseURL = url.origin
    const authInstance = getAuthInstance(
      storageMode,
      publicClient.verifyMessage,
      baseURL
    )

    // Rewrite URL to the playground verification endpoint path.
    // This is NOT /api/auth/erc8128/verify (the plugin's own endpoint) —
    // it's a custom /api/auth/verify endpoint that the erc8128 middleware
    // hook will intercept (since it's not in the plugin's skiplist).
    const rewrittenUrl = new URL("/api/auth/verify", url.origin)
    for (const [k, v] of url.searchParams) {
      rewrittenUrl.searchParams.set(k, v)
    }

    const rewrittenRequest = new Request(rewrittenUrl.toString(), {
      method: request.method,
      headers: request.headers,
      body:
        request.method !== "GET" && request.method !== "HEAD"
          ? request.body
          : undefined
    })

    const t0 = performance.now()

    try {
      const authResponse = await authInstance.handler(rewrittenRequest)
      const verifyMs = Math.round((performance.now() - t0) * 10) / 10

      // Parse the response body from better-auth
      let body: Record<string, unknown> | null = null
      try {
        body = await authResponse.json()
      } catch {
        body = null
      }

      const metadata = {
        verifyMs,
        storageMode,
        cacheStrategy: authInstance.cacheStrategy
      }

      // Copy accept-signature from auth response if present
      const acceptSignature = authResponse.headers.get("accept-signature")

      // ── Success: middleware passed, playground endpoint returned metadata ──
      if (authResponse.ok && body?.ok === true) {
        // body contains: ok, address, chainId, label, components, binding, replayable, params
        const verification = { ...body }

        if (!verbose) {
          const successBody = { ...verification, ...metadata }
          const res = json(successBody, 200)
          if (acceptSignature)
            res.headers.set("accept-signature", acceptSignature)
          return res
        }

        const res = json(
          {
            ...createVerbosePayload(request, verification),
            ...metadata
          },
          200
        )
        if (acceptSignature)
          res.headers.set("accept-signature", acceptSignature)
        return res
      }

      // ── Error: middleware returned verification failure ──
      const rawReason = (body?.reason as string) || "unknown"
      const reason = mapErrorReason(rawReason)
      const detail = (body?.detail as string) || ""
      const status = verificationStatus(reason)

      // Build a verification-like object matching the original format
      const verification = {
        ok: false as const,
        reason,
        ...(detail ? { detail } : {})
      }

      if (!verbose) {
        const errorBody =
          status !== 200 && acceptSignature
            ? {
                ...verification,
                "accept-signature": acceptSignature,
                ...metadata
              }
            : { ...verification, ...metadata }

        const res = json(errorBody, status)
        if (acceptSignature)
          res.headers.set("accept-signature", acceptSignature)
        return res
      }

      const verboseBody =
        status !== 200 && acceptSignature
          ? {
              ...createVerbosePayload(request, verification),
              "accept-signature": acceptSignature,
              ...metadata
            }
          : { ...createVerbosePayload(request, verification), ...metadata }

      const res = json(verboseBody, status)
      if (acceptSignature) res.headers.set("accept-signature", acceptSignature)
      return res
    } catch (error) {
      const verifyMs = Math.round((performance.now() - t0) * 10) / 10
      const res = json(
        { ...createErrorPayload(request, error, verbose), verifyMs },
        500
      )
      return res
    }
  }
}
