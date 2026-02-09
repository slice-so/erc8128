import type {
  NonceStore,
  SetHeadersFn,
  VerifyMessageFn,
  VerifyPolicy,
  VerifyResult
} from "./lib/types.js"
export declare function verifyRequest(
  request: Request,
  verifyMessage: VerifyMessageFn,
  nonceStore: NonceStore,
  policy?: VerifyPolicy,
  setHeaders?: SetHeadersFn
): Promise<VerifyResult>
//# sourceMappingURL=verify.d.ts.map
