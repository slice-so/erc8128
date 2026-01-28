//////////////////////////////
// Types
//////////////////////////////

export type Hex = `0x${string}`
export type Address = `0x${string}`

export type VerifyMessageArgs = {
  address: Address
  message: { raw: Hex }
  signature: Hex
}

export type VerifyMessageFn = (
  args: VerifyMessageArgs
) => boolean | Promise<boolean>

export type BindingMode = "request-bound" | "class-bound"
export type ReplayMode = "non-replayable" | "replayable"
export type ContentDigestMode = "auto" | "recompute" | "require" | "off"
export type HeaderMode = "replace" | "append"

export type SignOptions = {
  label?: string // default: "eth"
  binding?: BindingMode // default: "request-bound"
  replay?: ReplayMode // default: "non-replayable"

  created?: number // unix seconds; default now
  expires?: number // unix seconds; default created + ttlSeconds
  ttlSeconds?: number // default 60

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
  strictLabel?: boolean // default false

  /** Optional override. If omitted => default Request-Bound set derived from request shape. */
  requiredComponents?: string[]

  /** Params policy */
  nonce?: "required" | "optional" | "forbidden" // default "required"

  /** Time policy */
  now?: () => number // unix seconds; default unixNow()
  clockSkewSec?: number // default 0; allow +/- drift when checking created/expires
  maxValiditySec?: number // default 300; cap (expires - created)
  maxNonceWindowSec?: number // optional; cap (expires - created) for non-replayable (nonce) requests

  /** Replay protection */
  nonceStore?: NonceStore // required when verifying non-replayable (nonce) requests
  nonceKey?: (keyid: string, nonce: string) => string // default `${keyid}:${nonce}`

  /** If true: if content-digest is covered, recompute and compare (default true) */
  enforceContentDigest?: boolean

  /** Message signature verifier (viem-compatible). */
  verifyMessage?: VerifyMessageFn
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
      kind: "eoa" | "sca"
      address: Address
      chainId: number
      label: string
      components: string[]
      params: SignatureParams
    }
  | { ok: false; reason: VerifyFailReason; detail?: string }

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
  | "class_bound_not_allowed"
  | "not_request_bound"
  | "nonce_window_too_long"
  | "replay"
  | "digest_mismatch"
  | "digest_required"
  | "alg_not_allowed"
  | "bad_signature_bytes"
  | "bad_signature_check"

export class Eip8128Error extends Error {
  constructor(
    public code:
      | "CRYPTO_UNAVAILABLE"
      | "INVALID_OPTIONS"
      | "UNSUPPORTED_REQUEST"
      | "BODY_READ_FAILED"
      | "DIGEST_REQUIRED"
      | "BAD_DERIVED_VALUE"
      | "BAD_HEADER_VALUE"
      | "PARSE_ERROR",
    message: string
  ) {
    super(message)
    this.name = "Eip8128Error"
  }
}
