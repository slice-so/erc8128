import type { EthHttpSigner, SignOptions } from "./lib/types.js"
import { signedFetch, signRequest } from "./sign.js"

export type ClientOptions = SignOptions & { fetch?: typeof fetch }

export type Client = {
  signRequest: {
    (input: RequestInfo, opts?: SignOptions): Promise<Request>
    (
      input: RequestInfo,
      init: RequestInit | undefined,
      opts?: SignOptions
    ): Promise<Request>
  }
  signedFetch: {
    (input: RequestInfo, opts?: ClientOptions): Promise<Response>
    (
      input: RequestInfo,
      init: RequestInit | undefined,
      opts?: ClientOptions
    ): Promise<Response>
  }
  fetch: {
    (input: RequestInfo, opts?: ClientOptions): Promise<Response>
    (
      input: RequestInfo,
      init: RequestInit | undefined,
      opts?: ClientOptions
    ): Promise<Response>
  }
}

const REQUEST_INIT_KEYS = new Set([
  "method",
  "headers",
  "body",
  "signal",
  "credentials",
  "mode",
  "cache",
  "redirect",
  "referrer",
  "integrity",
  "keepalive",
  "window"
])

function isRequestInit(value: unknown): value is RequestInit {
  if (!value || typeof value !== "object") return false
  for (const key of REQUEST_INIT_KEYS) {
    if (key in (value as Record<string, unknown>)) return true
  }
  return false
}

function splitInitAndOpts<TOpts extends SignOptions>(
  initOrOpts?: RequestInit | TOpts,
  opts?: TOpts
): { init?: RequestInit; opts?: TOpts } {
  if (opts !== undefined)
    return { init: initOrOpts as RequestInit | undefined, opts }
  if (isRequestInit(initOrOpts)) return { init: initOrOpts }
  return { opts: initOrOpts as TOpts | undefined }
}

export function createClient(
  signer: EthHttpSigner,
  defaults?: ClientOptions
): Client {
  const base = defaults ?? {}

  const signRequestBound: Client["signRequest"] = async (
    input: RequestInfo,
    initOrOpts?: RequestInit | SignOptions,
    opts?: SignOptions
  ) => {
    const { init, opts: callOpts } = splitInitAndOpts(initOrOpts, opts)
    const merged = { ...base, ...callOpts }
    return signRequest(input, init, signer, merged)
  }

  const signedFetchBound: Client["signedFetch"] = async (
    input: RequestInfo,
    initOrOpts?: RequestInit | ClientOptions,
    opts?: ClientOptions
  ) => {
    const { init, opts: callOpts } = splitInitAndOpts(initOrOpts, opts)
    const merged = { ...base, ...callOpts }
    return signedFetch(input, init, signer, merged)
  }

  const fetchBound: Client["fetch"] = async (
    input: RequestInfo,
    initOrOpts?: RequestInit | ClientOptions,
    opts?: ClientOptions
  ) => {
    const { init, opts: callOpts } = splitInitAndOpts<ClientOptions>(
      initOrOpts,
      opts
    )
    const merged = { ...base, ...callOpts }
    return signedFetch(input, init, signer, merged)
  }

  return {
    signRequest: signRequestBound,
    signedFetch: signedFetchBound,
    fetch: fetchBound
  }
}
