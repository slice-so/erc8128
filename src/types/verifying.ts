import type { Address, Hex } from "./core"
import type { VerifyPolicy } from "./policy"
import type {
  BindingMode,
  ReplayMode,
  SelectedSignature,
  SignatureParams
} from "./signing"

export type VerifyMessageArgs = {
  address: Address
  message: { raw: Hex }
  signature: Hex
}

export type VerifyMessageFn = (
  args: VerifyMessageArgs
) => boolean | Promise<boolean>

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
      address: Address
      chainId: number
      label: string
      components: string[]
      params: SignatureParams
      replayable: boolean
      binding: BindingMode
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
  components: string[] | undefined
}
