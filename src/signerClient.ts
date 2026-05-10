import { resolvePosture } from "./lib/resolvePosture"
import { sanitizeUrl } from "./lib/utilities"
import { signedFetch, signRequest } from "./sign"
import type {
  EthHttpSigner,
  FetchOptions,
  ServerConfig,
  SignerClient,
  SignerClientOptions,
  SignOptions
} from "./types"

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

function isRequestInit(value: object | null | undefined): value is RequestInit {
  if (!value || typeof value !== "object") return false
  for (const key of REQUEST_INIT_KEYS) {
    if (key in value) return true
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

/**
 * Extract origin, method, and pathname from a RequestInfo, factoring in an
 * optional RequestInit that may override the method.
 */
function extractRequestInfo(
  input: RequestInfo,
  init?: RequestInit
): { origin: string; method: string; pathname: string } {
  const url =
    typeof input === "string"
      ? new URL(input)
      : input instanceof URL
        ? input
        : sanitizeUrl(input.url)

  const method = (
    init?.method ??
    (typeof input === "string" || input instanceof URL ? "GET" : input.method)
  ).toUpperCase()

  return { origin: url.origin, method, pathname: url.pathname }
}

export function createSignerClient(
  signer: EthHttpSigner,
  defaults?: SignerClientOptions
): SignerClient {
  const {
    serverConfigs: initialServerConfigs,
    preferReplayable = false,
    ...baseSignOpts
  } = defaults ?? {}

  const serverConfigs = new Map<string, ServerConfig>(
    initialServerConfigs ? Object.entries(initialServerConfigs) : []
  )

  /**
   * Resolve the final SignOptions for a request, applying the posture system
   * when appropriate.
   *
   * Per-call `callOpts` can explicitly set `binding`/`replay`/`components` to
   * bypass posture resolution entirely.
   */
  function resolveOpts(
    callOpts: SignOptions | undefined, // Per-call options
    input: RequestInfo,
    init?: RequestInit
  ): SignOptions & { fetch?: typeof fetch } {
    const mergedOptions = {
      ...baseSignOpts,
      ...callOpts,
      replay:
        callOpts?.replay ?? (preferReplayable ? "replayable" : "non-replayable")
    }

    const { origin, method, pathname } = extractRequestInfo(input, init)
    const posture = resolvePosture(
      method,
      pathname,
      serverConfigs.get(origin),
      mergedOptions
    )

    return {
      ...mergedOptions,
      binding: posture.binding,
      replay: posture.replay,
      components: posture.components
    }
  }

  const signRequestBound: SignerClient["signRequest"] = async (
    input: RequestInfo,
    initOrOpts?: RequestInit | SignOptions,
    opts?: SignOptions
  ) => {
    const { init, opts: callOpts } = splitInitAndOpts(initOrOpts, opts)
    const merged = resolveOpts(callOpts, input, init)
    return signRequest(input, init, signer, merged)
  }

  const signedFetchBound: SignerClient["signedFetch"] = async (
    input: RequestInfo,
    initOrOpts?: RequestInit | FetchOptions,
    opts?: FetchOptions
  ) => {
    const { init, opts: callOpts } = splitInitAndOpts(initOrOpts, opts)
    const merged = resolveOpts(callOpts, input, init)
    return signedFetch(input, init, signer, merged)
  }

  const fetchBound: SignerClient["fetch"] = async (
    input: RequestInfo,
    initOrOpts?: RequestInit | FetchOptions,
    opts?: FetchOptions
  ) => {
    const { init, opts: callOpts } = splitInitAndOpts<FetchOptions>(
      initOrOpts,
      opts
    )
    const merged = resolveOpts(callOpts, input, init)
    return signedFetch(input, init, signer, merged)
  }

  return {
    signRequest: signRequestBound,
    signedFetch: signedFetchBound,
    fetch: fetchBound,
    setServerConfig(origin: string, config: ServerConfig | null) {
      if (config === null) {
        serverConfigs.delete(origin)
      } else {
        serverConfigs.set(origin, config)
      }
    }
  }
}
