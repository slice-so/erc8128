import type { Address, ComponentIdentifier, Hex, SfMember } from "./core"
import type { VerifyPolicy } from "./policy"
import type {
  BindingMode,
  ReplayMode,
  SelectedSignature,
  SignatureParams
} from "./signing"

export type VerifyMessageArgs = {
  address: Address
  chainId: number
  message: { raw: Hex }
  signature: Hex
}

export type VerifyMessageFn = (
  args: VerifyMessageArgs
) => boolean | "unavailable" | Promise<boolean | "unavailable">

export type GetAccountCodeFn = (
  account: Pick<VerifyMessageArgs, "address" | "chainId">
) => Hex | undefined | "unavailable" | Promise<Hex | undefined | "unavailable">

export type VerifySmartAccountFn = (
  args: VerifyMessageArgs & {
    accountType: "counterfactual" | "deployed"
    digest: Hex
  }
) => boolean | "unavailable" | Promise<boolean | "unavailable">

export type SetHeadersFn = (name: string, value: string) => void

export interface NonceStore {
  /**
   * Atomic consume: returns true if newly stored (i.e. not seen), false if already exists.
   * ttlSeconds: how long the nonce should remain reserved.
   */
  consume(key: string, ttlSeconds: number): Promise<boolean>
}

export type VerifyRequestArgs = {
  request: Request
  verifyMessage: VerifyMessageFn
  nonceStore: NonceStore
  policy?: VerifyPolicy
  setHeaders?: SetHeadersFn
}

export type VerifyResult =
  | {
      ok: true
      principal: { address: Address; chainId: number }
      signer: { address: Address; chainId: number }
      delegated: boolean
      delegation?: {
        id: Hex
        audiences: string[]
        grantExpires: number
        extensions: Record<string, SfMember>
      }
      label: string
      components: ComponentIdentifier[]
      params: SignatureParams
      replayable: boolean
      binding: BindingMode
    }
  | { ok: false; reason: VerifyFailReason; detail?: string }

export type VerifyFailReason =
  | "missing_headers"
  | "label_not_found"
  | "tag_not_found"
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
  | "unsupported_delegation"
  | "delegation_grant_missing"
  | "delegation_grant_ambiguous"
  | "bad_delegation_field"
  | "delegation_too_large"
  | "delegation_not_covered"
  | "delegate_mismatch"
  | "grant_root_mismatch"
  | "grant_expired"
  | "grant_not_yet_valid"
  | "grant_validity_too_long"
  | "request_outside_grant_window"
  | "bad_grant_signature"
  | "audience_mismatch"
  | "delegation_nonce_required"
  | "delegation_max_age_exceeded"
  | "delegation_components_floor"
  | "unsupported_critical_extension"
  | "delegation_extension_rejected"
  | "signature_verification_unavailable"
  | "grant_verification_unavailable"
  | "critical_extension_unavailable"

export type VerifyCandidate<Key = string> = {
  candidate: SelectedSignature
  key: Key
}

export type Attempt<Key = string> = {
  candidate: VerifyCandidate<Key>
  kind: "request-bound" | "class-bound"
  policyLength: number
}

export type NoncePlan = {
  replayKey: string | null
  replayStore: NonceStore | null
  replayTtlSeconds: number
}

export type VerifierClientVerifyRequestArgs = {
  request: Request
  policy?: VerifyPolicy
  setHeaders?: SetHeadersFn
}

export type CreateVerifierClientArgs = {
  verifyMessage: VerifyMessageFn
  nonceStore: NonceStore
  defaults?: VerifyPolicy
}

export type VerifierClient = {
  verifyRequest: (
    args: VerifierClientVerifyRequestArgs
  ) => Promise<VerifyResult>
}

export type ResolvedPosture = {
  binding: BindingMode | undefined
  replay: ReplayMode
  components: import("./core").CoveredComponent[] | undefined
}

export type RedisNonceStoreClient = {
  setIfNotExists: (key: string, ttlSeconds: number) => Promise<boolean>
}

export type UniqueInsertNonceStoreClient = {
  insertUnique: (key: string, expiresAt: Date) => Promise<boolean>
}
