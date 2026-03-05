import { env } from "cloudflare:workers"
import { createVerifierClient } from "@slicekit/erc8128"
import { getBackendResources } from "./lib/erc8128/backend-config"
import {
  parseStorageMode,
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

import { createPublicClient, http } from "viem"
import { mainnet } from "viem/chains"

type HeaderMap = Record<string, string[]>

const rpcUrl = `https://eth-mainnet.g.alchemy.com/v2/${env.SECRET_ALCHEMY_KEY ?? ""}`

// ── Memoized verifier instances per (mode, replayMode) ──

type VerifierKey = `${StorageMode}:${"default" | "delete"}`
const verifierCache = new Map<
  VerifierKey,
  ReturnType<typeof createVerifierClient>
>()

const getVerifier = (mode: StorageMode, isDelete: boolean) => {
  const replayMode = isDelete ? "delete" : "default"
  const key: VerifierKey = `${mode}:${replayMode}`

  let verifier = verifierCache.get(key)
  if (verifier) return verifier

  const publicClient = createPublicClient({
    chain: mainnet,
    transport: http(rpcUrl)
  })

  const resources = getBackendResources(mode)

  verifier = createVerifierClient({
    verifyMessage: publicClient.verifyMessage,
    ...(resources.nonceStore ? { nonceStore: resources.nonceStore } : {}),
    defaults: {
      strictLabel: false,
      maxValiditySec: 300,
      replayable: !isDelete,
      replayableNotBefore: () => null,
      classBoundPolicies: isDelete ? [] : [["@authority"]]
    }
  })

  verifierCache.set(key, verifier)
  return verifier
}

// ── Helpers ──────────────────────────────────────────

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

const createVerbosePayload = (
  request: Request,
  verification: Awaited<
    ReturnType<ReturnType<typeof createVerifierClient>["verifyRequest"]>
  >
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

const verificationStatus = (
  verification: Awaited<
    ReturnType<ReturnType<typeof createVerifierClient>["verifyRequest"]>
  >
): number => {
  if (verification.ok) return 200
  if (
    verification.reason === "missing_headers" ||
    verification.reason === "bad_signature_input" ||
    verification.reason === "bad_keyid"
  ) {
    return 400
  }
  return 401
}

const createErrorPayload = (
  request: Request,
  error: unknown,
  verbose: boolean,
  storageMode: StorageMode,
  cacheStrategy: string
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
      detail,
      storageMode,
      cacheStrategy
    }
  }

  return {
    ok: false,
    verified: false,
    error: "verification_error",
    detail,
    storageMode,
    cacheStrategy,
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

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)

    if (url.pathname !== "/verify") {
      return new Response("Not Found", { status: 404 })
    }

    if (request.method === "OPTIONS") {
      return corsHeaders.clone()
    }

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

    const verbose = isVerboseRequest(request)
    const storageMode = parseStorageMode(
      request.headers,
      (env.ERC8128_STORAGE_DEFAULT as StorageMode) ?? "none"
    )
    const { cacheStrategy } = getBackendResources(storageMode)

    const isDelete = request.method.toUpperCase() === "DELETE"
    const responseHeaders = new Headers()

    try {
      const v = getVerifier(storageMode, isDelete)

      const t0 = performance.now()
      const verification = await v.verifyRequest({
        request: request.clone() as Request,
        setHeaders: (name, value) => {
          responseHeaders.set(name, value)
        }
      })

      const verifyMs = Math.round((performance.now() - t0) * 10) / 10
      const status = verificationStatus(verification)
      const acceptSignature = responseHeaders.get("accept-signature")

      if (verification.ok) {
        const successBody = {
          ...verification,
          verifyMs,
          storageMode,
          cacheStrategy
        }
        if (!verbose) {
          const res = json(successBody, 200)
          for (const [k, v] of responseHeaders) res.headers.set(k, v)
          return res
        }
        const res = json(
          {
            ...createVerbosePayload(request, verification),
            verifyMs,
            storageMode,
            cacheStrategy
          },
          200
        )
        for (const [k, v] of responseHeaders) res.headers.set(k, v)
        return res
      }

      const body =
        status !== 200 && acceptSignature
          ? {
              ...verification,
              "accept-signature": acceptSignature,
              verifyMs,
              storageMode,
              cacheStrategy
            }
          : { ...verification, verifyMs, storageMode, cacheStrategy }

      if (!verbose) {
        const res = json(body, status)
        for (const [k, v] of responseHeaders) res.headers.set(k, v)
        return res
      }

      const verboseBody =
        status !== 200 && acceptSignature
          ? {
              ...createVerbosePayload(request, verification),
              "accept-signature": acceptSignature,
              verifyMs,
              storageMode,
              cacheStrategy
            }
          : {
              ...createVerbosePayload(request, verification),
              verifyMs,
              storageMode,
              cacheStrategy
            }

      const res = json(verboseBody, status)
      for (const [k, v] of responseHeaders) res.headers.set(k, v)
      return res
    } catch (error) {
      const res = json(
        createErrorPayload(request, error, verbose, storageMode, cacheStrategy),
        500
      )
      const acceptSignature = responseHeaders.get("accept-signature")

      if (acceptSignature) {
        res.headers.set("accept-signature", acceptSignature)
      }
      return res
    }
  }
}
