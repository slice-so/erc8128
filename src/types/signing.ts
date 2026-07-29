import type { Address, Hex } from "./core"
import type { ServerConfig } from "./policy"

export type BindingMode = "request-bound" | "class-bound"
export type ReplayMode = "non-replayable" | "replayable"
export type ContentDigestMode = "auto" | "recompute" | "require" | "off"

export type SignOptions = {
  label?: string // default: "eth"
  /** RFC 9421 signature role, independent from the dictionary label. */
  tag?: string
  binding?: BindingMode // default: "request-bound"
  replay?: ReplayMode // default: "non-replayable"

  created?: number // unix seconds; default now
  expires?: number // unix seconds; default created + ttlSeconds
  ttlSeconds?: number // default 60

  nonce?: string | (() => Promise<string>)

  contentDigest?: ContentDigestMode
  components?: string[]
}

export interface EthHttpSigner {
  /** Address to put in keyid and to authenticate as (EOA or SCA). */
  address: Address
  chainId: number
  /**
   * Sign RFC9421 signature base bytes as an Ethereum message (EIP-191).
   * Return signature bytes as hex (may be 65 bytes for EOA, arbitrary length for SCA-style signatures).
   */
  signMessage: (message: Uint8Array) => Promise<Hex>
}

export type SignatureParams = {
  created: number
  expires: number
  keyid: string
  nonce?: string
  tag?: string
}

export type SelectedSignature = {
  label: string
  components: string[]
  params: {
    keyid: string
    created: number
    expires: number
    nonce?: string
    tag?: string
  }
  signatureParamsValue: string
  sigB64: string
}

export type ParsedSignatureInputMember = {
  label: string
  components: string[]
  params: SignatureParams
  signatureParamsValue: string // raw member value after "label=" (trimmed)
}

/**
 * Options for `createSignerClient`.
 *
 * Extends `SignOptions` (minus `replay` which is derived automatically by the
 * posture system) with:
 * - `preferReplayable` — client *preference* for replayable signatures (default `false`).
 * - `serverConfigs` — per-origin server configs from `/.well-known/erc8128`.
 *
 * When `preferReplayable` is `false` (default) **and** no class-bound components
 * are configured, every signature is non-replayable + request-bound — the safest
 * posture — and server configs are not consulted.
 */
export type SignerClientOptions = Omit<SignOptions, "replay"> & {
  /**
   * Immutable authorization constraints. Per-call options and discovered
   * route policies can tighten, but never weaken, this policy.
   */
  authorizationPolicy?: import("./policy").AuthorizationPolicy
  /** Unix timestamp after which the authorization itself is invalid. */
  authorizationExpiresAt?: number
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
}

/** Per-call options for `signedFetch` / `fetch`. */
export type FetchOptions = SignOptions & { fetch?: typeof fetch }

export type SignerClient = {
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
