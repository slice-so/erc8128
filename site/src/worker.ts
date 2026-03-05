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

const corsHeaders = new Response(null, {
  status: 204,
  headers: {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "access-control-allow-headers": "*",
    "access-control-max-age": "86400"
  }
})

/**
 * Parse binding and replayable status from the Signature-Input header.
 * This lets us include these in the playground response even though
 * the plugin's verify endpoint doesn't return them directly.
 */
function parseSignatureMetadata(request: Request): {
  binding: "request-bound" | "class-bound"
  replayable: boolean
} {
  const sigInput = request.headers.get("signature-input") || ""
  const hasNonce = /nonce="/.test(sigInput)
  // If @method is in the signed components, it's more tightly bound
  const hasMethod = sigInput.includes('"@method"')
  const hasPath =
    sigInput.includes('"@path"') || sigInput.includes('"@target-uri"')
  return {
    binding: hasMethod && hasPath ? "request-bound" : "class-bound",
    replayable: !hasNonce
  }
}

// ── Main handler ─────────────────────────────────────

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)

    // Handle CORS preflight for any path
    if (request.method === "OPTIONS") {
      return corsHeaders.clone()
    }

    // ── /verify → route through better-auth erc8128 plugin ──
    if (url.pathname === "/verify") {
      // Validate JSON body if present
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
      const verbose =
        url.searchParams.get("verbose") === "1" ||
        url.searchParams.get("verbose") === "true"

      // Get the better-auth instance for this storage mode
      const baseURL = url.origin
      const authInstance = getAuthInstance(
        storageMode,
        publicClient.verifyMessage,
        baseURL
      )

      // Rewrite URL to the plugin's verify endpoint path
      const rewrittenUrl = new URL(`/api/auth/erc8128/verify`, url.origin)
      // Preserve query params
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

      // Parse signature metadata before verification
      const sigMeta = parseSignatureMetadata(request)
      const isDelete = request.method.toUpperCase() === "DELETE"

      const t0 = performance.now()
      let response: Response
      try {
        response = await authInstance.handler(rewrittenRequest)
      } catch (error) {
        const verifyMs = Math.round((performance.now() - t0) * 10) / 10
        const detail = error instanceof Error ? error.message : "unknown_error"
        return json(
          {
            ok: false,
            verified: false,
            error: "verification_error",
            detail,
            storageMode,
            cacheStrategy: authInstance.cacheStrategy,
            verifyMs
          },
          500
        )
      }
      const verifyMs = Math.round((performance.now() - t0) * 10) / 10

      // Parse the plugin's response
      let pluginBody: Record<string, unknown> | null = null
      try {
        pluginBody = await response.json()
      } catch {
        pluginBody = null
      }

      const metadata = {
        verifyMs,
        storageMode,
        cacheStrategy: authInstance.cacheStrategy
      }

      // Success: plugin returns { token, success, user: { id, walletAddress, chainId } }
      if (response.ok && pluginBody?.success) {
        const user = pluginBody.user as
          | { walletAddress?: string; chainId?: number }
          | undefined
        const successBody = {
          ok: true,
          address: user?.walletAddress,
          chainId: user?.chainId,
          label: "eth",
          components: ["@method", "@target-uri", "@authority"],
          binding: sigMeta.binding,
          replayable: sigMeta.replayable && !isDelete,
          ...metadata
        }

        if (verbose) {
          return json(
            {
              ...successBody,
              verified: true,
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
              }
            },
            200
          )
        }

        return json(successBody, 200)
      }

      // Error: plugin returns { error, reason, detail }
      const errorBody = {
        ok: false,
        verified: false,
        ...(pluginBody ?? {}),
        ...metadata
      }

      const status = response.status || 401

      if (verbose) {
        return json(
          {
            ...errorBody,
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
            }
          },
          status
        )
      }

      return json(errorBody, status)
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

    return new Response("Not Found", { status: 404 })
  }
}
