import type { Hex } from "./core"
import type {
  BindingMode,
  ContentDigestMode,
  ReplayMode,
  SignOptions
} from "./signing"

export type RoutePolicy = {
  /** Restrict this policy to specific HTTP methods. If omitted, it applies to all methods. */
  methods?: string[]

  /** Allow replayable (nonce-less) signatures (default false). */
  replayable?: boolean

  /** Extra components required in addition to default request-bound set. */
  additionalRequestBoundComponents?: string[]

  /** Content-digest behavior required by this route. */
  contentDigest?: ContentDigestMode

  /**
   * Class-bound component policies.
   * - `undefined`: route is request-bound only
   * - `["@authority"]`: allow minimal class-bound
   * - entries: require @authority plus those components
   * - `[]`: supported shorthand for `["@authority"]`
   */
  classBoundPolicies?: string[] | string[][]
}

export type RoutePolicyConfig = Record<string, RoutePolicy | RoutePolicy[]> & {
  default?: RoutePolicy
}

export type VerifyPolicy = Omit<RoutePolicy, "methods"> & {
  /** Preferred label to verify (default "eth"). If not found, verifier can fall back to first label unless strictLabel=true. */
  label?: string
  strictLabel?: boolean // default false
  /** Require the exact RFC 9421 signature role. Untagged candidates never match. */
  requiredTag?: string
  /**
   * If one of these request fields is present, every eligible signature must
   * cover it. Absence is allowed.
   */
  requiredCoveredComponentsWhenPresent?: string[]

  /**
   * Optional replayable invalidation policy.
   * When set and a signature is replayable, requests with created < notBefore are rejected.
   * Return null/undefined to indicate "no cutoff".
   */
  replayableNotBefore?: (
    keyid: string
  ) => number | null | undefined | Promise<number | null | undefined>

  /**
   * Optional per-signature invalidation policy for replayable signatures.
   * Return true to mark the signature as invalidated.
   */
  replayableInvalidated?: (args: {
    keyid: string
    signature: Hex
  }) => boolean | Promise<boolean>

  /** Maximum number of signatures to verify (default 3). */
  maxSignatureVerifications?: number

  /** Time policy */
  now?: () => number // unix seconds; default unixNow()
  clockSkewSec?: number // default 0; allow +/- drift when checking created/expires
  maxValiditySec?: number // default 300; cap (expires - created)
  maxNonceWindowSec?: number // optional; cap (expires - created) for non-replayable (nonce) requests

  /** Replay protection */
  nonceKey?: (keyid: string, nonce: string) => string // default `${keyid}:${nonce}`
}

export type ServerConfig = {
  invalidation_endpoint?: string
  max_validity_sec: number
  route_policies?: RoutePolicyConfig
}

export type ClassBoundPolicy = string[]

/**
 * Immutable signing constraints imposed by an authorization grant.
 *
 * Client and request preferences are resolved inside this boundary and can
 * only tighten it.
 */
export type AuthorizationPolicy = {
  binding: BindingMode
  components: readonly string[]
  preferReplayable: boolean
  ttlSeconds: number
}

export type ResolveAuthorizedPostureParameters = {
  authorizationPolicy: AuthorizationPolicy
  invalidationAvailable?: boolean
  remainingAuthorizationSeconds?: number
  requestOptions?: SignOptions
  routeMaxValiditySeconds?: number
  routePolicy?: RoutePolicy
}

export type ResolvedAuthorizedPosture = {
  binding: BindingMode
  components: string[]
  contentDigest: ContentDigestMode
  replay: ReplayMode
  ttlSeconds: number
}
