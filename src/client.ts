import { resolvePosture } from "./lib/resolvePosture"
import type { EthHttpSigner, ServerConfig, SignOptions } from "./lib/types"
import { sanitizeUrl } from "./lib/utilities"
import { signedFetch, signRequest } from "./sign"

/**
 * Options for {@link createSignerClient}.
 *
 * Extends `SignOptions` (minus `binding`, `replay`, and `components` which are
 * derived automatically by the posture system) with:
 * - `preferReplayable` — client *preference* for replayable signatures (default `false`).
 * - `minComponents` — minimum class-bound components the client is willing to sign.
 * - `serverConfigs` — per-origin server configs from `/.well-known/erc8128`.
 *
 * When `preferReplayable` is `false` (default) **and** `minComponents` is `undefined`,
 * every signature is non-replayable + request-bound — the safest posture — and
 * server configs are not consulted.
 */
export type ClientOptions = Omit<
  SignOptions,
  "replay" | "binding" | "components"
> & {
  fetch?: typeof fetch
  /**
   * Per-origin server configurations from `/.well-known/erc8128`.
   * Keyed by origin (e.g. `"https://api.example.com"`).
   *
   * When a request's origin matches a key, the client adapts signing per-request:
   * - `preferReplayable` is gated by the server's per-route policy.
   * - `minComponents` is merged with the route's `classBoundPolicies`.
   * - `binding` is derived automatically (class-bound when replayable + minComponents).
   *
   * Can be updated after creation via `client.setServerConfig(origin, config)`.
   */
  serverConfigs?: Record<string, ServerConfig>
  /**
   * Whether the client prefers replayable signatures.
   * When `true`, replayable mode is used **only if** the server's route policy allows it
   * (or unconditionally when no server config exists for the request's origin).
   * @default false
   */
  preferReplayable?: boolean
  /**
   * Minimum class-bound components the client is willing to sign.
   * When set **and** the request is replayable, the signing posture becomes
   * class-bound with components = union of `minComponents` + route's `classBoundPolicies`.
   * @default undefined
   */
  minComponents?: string[]
}

/** Per-call options for `signedFetch` / `fetch`. */
export type FetchOptions = SignOptions & { fetch?: typeof fetch }

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
    (input: RequestInfo, opts?: FetchOptions): Promise<Response>
    (
      input: RequestInfo,
      init: RequestInit | undefined,
      opts?: FetchOptions
    ): Promise<Response>
  }
  fetch: {
    (input: RequestInfo, opts?: FetchOptions): Promise<Response>
    (
      input: RequestInfo,
      init: RequestInit | undefined,
      opts?: FetchOptions
    ): Promise<Response>
  }
  /**
   * Set or remove the server config for a given origin.
   * Pass `null` to remove a previously set config.
   *
   * @example
   * // After fetching /.well-known/erc8128 from the target server:
   * client.setServerConfig("https://api.example.com", config)
   *
   * // Remove config (reverts to client-preference-only posture for this origin):
   * client.setServerConfig("https://api.example.com", null)
   */
  setServerConfig: (origin: string, config: ServerConfig | null) => void
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
  defaults?: ClientOptions
): Client {
  const {
    serverConfigs: initialServerConfigs,
    preferReplayable = false,
    minComponents,
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
    callOpts: SignOptions | undefined,
    input: RequestInfo,
    init?: RequestInit
  ): SignOptions & { fetch?: typeof fetch } {
    const merged = { ...baseSignOpts, ...callOpts }

    // Per-call explicit overrides bypass posture resolution
    if (
      callOpts?.binding !== undefined ||
      callOpts?.replay !== undefined ||
      callOpts?.components !== undefined
    ) {
      return merged
    }

    // Optimization: non-replayable + no min components → always request-bound +
    // non-replayable (safest posture, never rejected). signRequest defaults to
    // these values so we can pass through without resolving.
    if (!preferReplayable && !minComponents) {
      return merged
    }

    const { origin, method, pathname } = extractRequestInfo(input, init)
    const posture = resolvePosture(
      method,
      pathname,
      preferReplayable,
      minComponents,
      serverConfigs.get(origin)
    )
    return {
      ...merged,
      binding: posture.binding,
      replay: posture.replay,
      components: posture.components
    }
  }

  const signRequestBound: Client["signRequest"] = async (
    input: RequestInfo,
    initOrOpts?: RequestInit | SignOptions,
    opts?: SignOptions
  ) => {
    const { init, opts: callOpts } = splitInitAndOpts(initOrOpts, opts)
    const merged = resolveOpts(callOpts, input, init)
    return signRequest(input, init, signer, merged)
  }

  const signedFetchBound: Client["signedFetch"] = async (
    input: RequestInfo,
    initOrOpts?: RequestInit | FetchOptions,
    opts?: FetchOptions
  ) => {
    const { init, opts: callOpts } = splitInitAndOpts(initOrOpts, opts)
    const merged = resolveOpts(callOpts, input, init)
    return signedFetch(input, init, signer, merged)
  }

  const fetchBound: Client["fetch"] = async (
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
