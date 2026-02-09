export type Hex = `0x${string}`
export type Address = `0x${string}`
export type VerifyMessageArgs = {
  address: Address
  message: {
    raw: Hex
  }
  signature: Hex
}
export type VerifyMessageFn = (
  args: VerifyMessageArgs
) => boolean | Promise<boolean>
export type SetHeadersFn = (name: string, value: string) => void
export type BindingMode = "request-bound" | "class-bound"
export type ReplayMode = "non-replayable" | "replayable"
export type ContentDigestMode = "auto" | "recompute" | "require" | "off"
export type HeaderMode = "replace" | "append"
export type SignOptions = {
  label?: string
  binding?: BindingMode
  replay?: ReplayMode
  created?: number
  expires?: number
  ttlSeconds?: number
  nonce?: string | (() => Promise<string>)
  contentDigest?: ContentDigestMode
  headerMode?: HeaderMode
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
export interface NonceStore {
  /**
   * Atomic consume: returns true if newly stored (i.e. not seen), false if already exists.
   * ttlSeconds: how long the nonce should remain reserved.
   */
  consume(key: string, ttlSeconds: number): Promise<boolean>
}
export type VerifyPolicy = {
  /** Preferred label to verify (default "eth"). If not found, verifier can fall back to first label unless strictLabel=true. */
  label?: string
  strictLabel?: boolean
  /** Extra components required in addition to default request-bound set. */
  additionalRequestBoundComponents?: string[]
  /** Class-bound components policies (one list or a list of lists). @authority is always required. */
  classBoundPolicies?: string[] | string[][]
  /** Allow replayable (nonce-less) signatures (default false). */
  replayable?: boolean
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
    created: number
    expires: number
    label: string
    signature: Hex
    signatureBase: Uint8Array
    signatureParamsValue: string
  }) => boolean | Promise<boolean>
  /** Maximum number of signatures to verify (default 3). */
  maxSignatureVerifications?: number
  /** Time policy */
  now?: () => number
  clockSkewSec?: number
  maxValiditySec?: number
  maxNonceWindowSec?: number
  /** Replay protection */
  nonceKey?: (keyid: string, nonce: string) => string
}
export type SignatureParams = {
  created: number
  expires: number
  keyid: string
  nonce?: string
  tag?: string
}
export type VerifyResult =
  | {
      ok: true
      address: Address
      chainId: number
      label: string
      components: string[]
      params: SignatureParams
      replayable: boolean
      binding: BindingMode
    }
  | {
      ok: false
      reason: VerifyFailReason
      detail?: string
    }
export type VerifyFailReason =
  | "missing_headers"
  | "label_not_found"
  | "bad_signature_input"
  | "bad_signature"
  | "bad_keyid"
  | "bad_time"
  | "not_yet_valid"
  | "expired"
  | "validity_too_long"
  | "nonce_required"
  | "replayable_not_allowed"
  | "replayable_invalidation_required"
  | "replayable_not_before"
  | "replayable_invalidated"
  | "class_bound_not_allowed"
  | "not_request_bound"
  | "nonce_window_too_long"
  | "replay"
  | "digest_mismatch"
  | "digest_required"
  | "alg_not_allowed"
  | "bad_signature_bytes"
  | "bad_signature_check"
export declare class Erc8128Error extends Error {
  code:
    | "CRYPTO_UNAVAILABLE"
    | "INVALID_OPTIONS"
    | "UNSUPPORTED_REQUEST"
    | "BODY_READ_FAILED"
    | "DIGEST_REQUIRED"
    | "BAD_DERIVED_VALUE"
    | "BAD_HEADER_VALUE"
    | "PARSE_ERROR"
  constructor(
    code:
      | "CRYPTO_UNAVAILABLE"
      | "INVALID_OPTIONS"
      | "UNSUPPORTED_REQUEST"
      | "BODY_READ_FAILED"
      | "DIGEST_REQUIRED"
      | "BAD_DERIVED_VALUE"
      | "BAD_HEADER_VALUE"
      | "PARSE_ERROR",
    message: string
  )
}
//# sourceMappingURL=types.d.ts.map
