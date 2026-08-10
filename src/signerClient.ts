import { Erc8128Error } from "./lib/Erc8128Error"
import { matchRoutePolicy } from "./lib/matchRoutePolicy"
import { resolveAuthorizedPosture } from "./lib/resolveAuthorizedPosture"
import { resolvePosture } from "./lib/resolvePosture"
import { sanitizeUrl } from "./lib/utilities"
import { signedFetchWithOptionsResolver, signRequest } from "./sign"
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

function normalizeServerConfigOrigin(value: string): string {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      `Server config key must be an absolute HTTP(S) origin: ${value}`
    )
  }
  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      `Server config key must contain only an HTTP(S) origin: ${value}`
    )
  }
  return url.origin
}

export function createSignerClient(
  signer: EthHttpSigner,
  defaults?: SignerClientOptions
): SignerClient {
  const {
    authorizationExpiresAt,
    authorizationPolicy,
    serverConfigs: initialServerConfigs,
    preferReplayable = false,
    ...baseSignOpts
  } = defaults ?? {}

  const serverConfigs = new Map<string, ServerConfig>(
    initialServerConfigs
      ? Object.entries(initialServerConfigs).map(([origin, config]) => [
          normalizeServerConfigOrigin(origin),
          config
        ])
      : []
  )

  /**
   * Resolve the final SignOptions for a request, applying the posture system
   * when appropriate.
   *
   * Per-call `callOpts` can explicitly set `binding`/`nonce`/`components` to
   * bypass posture resolution entirely.
   */
  function resolveOpts(
    callOpts: SignOptions | undefined, // Per-call options
    input: RequestInfo,
    init?: RequestInit
  ): SignOptions & { fetch?: typeof fetch } {
    const mergedOptions: SignOptions = {
      ...baseSignOpts,
      ...callOpts
    }
    const requestedReplay =
      mergedOptions.nonce === null ||
      (mergedOptions.nonce === undefined && preferReplayable)
        ? ("replayable" as const)
        : ("non-replayable" as const)

    const { origin, method, pathname } = extractRequestInfo(input, init)
    const serverConfig = serverConfigs.get(origin)
    const now = Math.floor(Date.now() / 1_000)
    if (authorizationPolicy === undefined) {
      const posture = resolvePosture(
        method,
        pathname,
        serverConfig,
        mergedOptions,
        requestedReplay
      )
      const created = mergedOptions.created ?? now
      const remainingAuthorizationSeconds =
        authorizationExpiresAt === undefined
          ? Number.POSITIVE_INFINITY
          : authorizationExpiresAt - created
      if (remainingAuthorizationSeconds <= 0) {
        throw new Erc8128Error(
          "INVALID_OPTIONS",
          "The signing authorization has expired."
        )
      }
      const maximumTtlSeconds = Math.min(
        posture.maximumTtlSeconds,
        remainingAuthorizationSeconds
      )
      const expires = Math.min(
        mergedOptions.expires ?? created + posture.defaultTtlSeconds,
        created + maximumTtlSeconds
      )
      return {
        ...mergedOptions,
        binding: posture.binding,
        nonce:
          posture.replay === "replayable"
            ? null
            : mergedOptions.nonce === null
              ? undefined
              : mergedOptions.nonce,
        components: posture.components,
        contentDigest: posture.contentDigest,
        created,
        expires,
        ttlSeconds: posture.defaultTtlSeconds
      }
    }

    const posture = resolveAuthorizedPosture({
      authorizationPolicy,
      invalidationAvailable: serverConfig?.invalidation_endpoint !== undefined,
      preferReplayable: requestedReplay === "replayable",
      ...(authorizationExpiresAt === undefined
        ? {}
        : {
            remainingAuthorizationSeconds: authorizationExpiresAt - now
          }),
      requestOptions: mergedOptions,
      routeMaxValiditySeconds: serverConfig?.max_validity_sec,
      routePolicy: matchRoutePolicy(
        method,
        pathname,
        serverConfig?.route_policies
      )
    })
    const created = mergedOptions.created ?? now
    const expires = Math.min(
      mergedOptions.expires ?? created + posture.ttlSeconds,
      created + posture.ttlSeconds,
      authorizationExpiresAt ?? Number.POSITIVE_INFINITY
    )
    return {
      ...mergedOptions,
      binding: posture.binding,
      components: posture.components,
      contentDigest: posture.contentDigest,
      created,
      expires,
      nonce:
        posture.replay === "replayable"
          ? null
          : mergedOptions.nonce === null
            ? undefined
            : mergedOptions.nonce,
      ttlSeconds: posture.ttlSeconds
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
    return signedFetchWithOptionsResolver(input, init, signer, (request) =>
      resolveOpts(callOpts, request)
    )
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
    return signedFetchWithOptionsResolver(input, init, signer, (request) =>
      resolveOpts(callOpts, request)
    )
  }

  return {
    signRequest: signRequestBound,
    signedFetch: signedFetchBound,
    fetch: fetchBound,
    setServerConfig(origin: string, config: ServerConfig | null) {
      const normalizedOrigin = normalizeServerConfigOrigin(origin)
      if (config === null) {
        serverConfigs.delete(normalizedOrigin)
      } else {
        serverConfigs.set(normalizedOrigin, config)
      }
    }
  }
}
