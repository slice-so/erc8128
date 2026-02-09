import type {
  NonceStore,
  SetHeadersFn,
  VerifyMessageFn,
  VerifyPolicy,
  VerifyResult
} from "./lib/types.js"
export type VerifierClientOptions = VerifyPolicy
export type VerifierClient = {
  verifyRequest: (
    request: Request,
    policy?: VerifyPolicy,
    setHeaders?: SetHeadersFn
  ) => Promise<VerifyResult>
}
export declare function createVerifierClient(
  verifyMessage: VerifyMessageFn,
  nonceStore: NonceStore,
  defaults?: VerifierClientOptions
): VerifierClient
//# sourceMappingURL=verifierClient.d.ts.map
