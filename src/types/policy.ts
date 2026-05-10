import type { Hex } from "./core"

export type RoutePolicy = {
  /** Restrict this policy to specific HTTP methods. If omitted, it applies to all methods. */
  methods?: string[]

  /** Allow replayable (nonce-less) signatures (default false). */
  replayable?: boolean

  /** Extra components required in addition to default request-bound set. */
  additionalRequestBoundComponents?: string[]

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
  max_validity_sec: number
  route_policies?: RoutePolicyConfig
}

export type ClassBoundPolicy = string[]
