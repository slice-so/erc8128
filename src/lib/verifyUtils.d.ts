import type { SelectedSignature } from "./engine/signatureHeaders.js"
import type { NonceStore, VerifyResult } from "./types.js"
export type VerifyCandidate<Key = unknown> = {
  candidate: SelectedSignature
  key: Key
}
export type Attempt<Key = unknown> = {
  candidate: VerifyCandidate<Key>
  kind: "request-bound" | "class-bound"
  policyLength: number
}
export type NoncePlan = {
  replayKey: string | null
  replayStore: NonceStore | null
  replayTtlSeconds: number
}
export declare function buildAttempts<Key>(
  candidates: VerifyCandidate<Key>[],
  options: {
    hasQuery: boolean
    hasBody: boolean
    requestBoundExtras: string[]
    requestBoundRequired: string[]
    classBoundPolicies: string[][]
  }
): {
  attempts: Attempt<Key>[]
  sawClassBound: boolean
}
export declare function runTimeChecks(options: {
  now: number
  skew: number
  maxValiditySec: number | null | undefined
  created: number | undefined
  expires: number | undefined
}): VerifyResult | null
export declare function runNonceChecks(options: {
  allowReplayable: boolean
  params: {
    nonce?: string
    keyid: string
    created?: number
    expires?: number
  }
  now: number
  nonceStore: NonceStore | undefined
  nonceKey: ((keyid: string, nonce: string) => string) | undefined
  maxNonceWindowSec: number | null | undefined
}): {
  failure: VerifyResult | null
  plan: NoncePlan
}
export declare function buildSignatureBase(options: {
  request: Request
  components: string[]
  signatureParamsValue: string
}): Uint8Array
//# sourceMappingURL=verifyUtils.d.ts.map
