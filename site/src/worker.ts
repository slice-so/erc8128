import { createVerifierClient, type NonceStore } from "@slicekit/erc8128"
import { createPublicClient, http } from "viem"

interface Env {
  ASSETS: { fetch: typeof fetch }
  ERC8128_DEMO_RPC_URL?: string
}

const DEFAULT_RPC_URL = "https://eth.llamarpc.com"

type HeaderMap = Record<string, string[]>

const nonceExpirations = new Map<string, number>()
const nonceStore: NonceStore = {
  async consume(key: string, ttlSeconds: number) {
    const now = Date.now()

    for (const [storedKey, expiresAt] of nonceExpirations.entries()) {
      if (expiresAt <= now) nonceExpirations.delete(storedKey)
    }

    const existingExpiry = nonceExpirations.get(key)
    if (typeof existingExpiry === "number" && existingExpiry > now) return false

    nonceExpirations.set(key, now + Math.max(ttlSeconds, 0) * 1000)
    return true
  }
}

let verifier: ReturnType<typeof createVerifierClient> | undefined

const getVerifier = (env: Env) => {
  if (!verifier) {
    const publicClient = createPublicClient({
      transport: http(env.ERC8128_DEMO_RPC_URL ?? DEFAULT_RPC_URL)
    })

    verifier = createVerifierClient({
      verifyMessage: publicClient.verifyMessage,
      nonceStore,
      defaults: {
        strictLabel: false,
        maxValiditySec: 300
      }
    })
  }
  return verifier
}

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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    if (url.pathname !== "/verify") {
      return env.ASSETS.fetch(request)
    }

    if (request.method === "OPTIONS") {
      return corsHeaders.clone()
    }

    const verbose = isVerboseRequest(request)
    const v = getVerifier(env)

    const responseHeaders = new Headers()

    try {
      const verification = await v.verifyRequest({
        request: request.clone(),
        setHeaders: (name, value) => {
          responseHeaders.set(name, value)
        }
      })
      const status = verificationStatus(verification)
      const acceptSignature = responseHeaders.get("accept-signature")

      const body =
        status === 400 && acceptSignature
          ? { ...verification, acceptSignature }
          : verification

      if (!verbose) {
        const res = json(body, status)
        for (const [k, v] of responseHeaders) res.headers.set(k, v)
        return res
      }

      const verboseBody =
        status === 400 && acceptSignature
          ? { ...createVerbosePayload(request, verification), acceptSignature }
          : createVerbosePayload(request, verification)

      const res = json(verboseBody, status)
      for (const [k, v] of responseHeaders) res.headers.set(k, v)
      return res
    } catch (error) {
      return json(createErrorPayload(request, error, verbose), 500)
    }
  }
}
