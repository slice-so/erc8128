import type { Address, ComponentIdentifier, Hex } from "./core"
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

export type VerifyDigestArgs = Omit<VerifyMessageArgs, "message"> & {
  digest: Hex
}

export type VerifyDigestFn = (
  args: VerifyDigestArgs
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
  verifyDigest?: VerifyDigestFn
  nonceStore: NonceStore
  policy?: VerifyPolicy
  setHeaders?: SetHeadersFn
}

export type VerifyResult =
  | {
      ok: true
      principal: { address: Address; chainId: number }
      signer: { address: Address; chainId: number }
      delegated: false
      label: string
      components: ComponentIdentifier[]
      params: SignatureParams
      replay: ReplayMode
      binding: BindingMode
    }
  | {
      ok: true
      principal: { address: Address; chainId: number }
      signer: { address: Address; chainId: number }
      delegated: true
      delegationIds: Hex[]
      replay: ReplayMode
      binding: BindingMode
    }
  | { ok: false; reason: VerifyFailReason; detail?: string }

export type VerifyFailReason =
  | "signature_missing"
  | "no_acceptable_signature"
  | "signature_input_invalid"
  | "signature_too_large"
  | "invalid_keyid"
  | "invalid_time"
  | "request_not_yet_valid"
  | "request_expired"
  | "request_validity_too_long"
  | "invalid_nonce"
  | "insufficient_coverage"
  | "content_digest_required"
  | "bad_content_digest"
  | "nonce_required"
  | "nonce_reused"
  | "replayable_not_allowed"
  | "unsupported_algorithm"
  | "bad_signature"
  | "signature_verification_unavailable"
  | "principal_not_allowed"
  | "unsupported_delegation"
  | "bad_delegation_field"
  | "delegation_too_large"
  | "delegation_not_covered"
  | "delegate_mismatch"
  | "delegation_chain_too_long"
  | "delegation_chain_discontinuous"
  | "delegation_attenuation_violation"
  | "grant_expired"
  | "grant_not_yet_valid"
  | "grant_validity_too_long"
  | "request_outside_grant_window"
  | "bad_grant_signature"
  | "audience_mismatch"
  | "delegation_nonce_required"
  | "delegation_request_validity_exceeded"
  | "delegation_components_unsupported"
  | "delegation_components_uncovered"
  | "unsupported_permissions"
  | "insufficient_permissions"
  | "grant_verification_unavailable"
  | "authorization_revoked"
  | "authorization_epoch_mismatch"
  | "revocation_unavailable"

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
  verifyDigest?: VerifyDigestFn
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
