import type {
  NonceStore,
  SetHeadersFn,
  VerifyMessageFn,
  VerifyPolicy,
  VerifyResult
} from "./lib/types.js"
import { verifyRequest } from "./verify.js"

export type VerifierClientOptions = VerifyPolicy

export type VerifierClient = {
  verifyRequest: (
    request: Request,
    policy?: VerifyPolicy,
    setHeaders?: SetHeadersFn
  ) => Promise<VerifyResult>
}

export function createVerifierClient(
  verifyMessage: VerifyMessageFn,
  nonceStore: NonceStore,
  defaults?: VerifierClientOptions
): VerifierClient {
  const base = defaults ?? {}

  const verifyRequestBound: VerifierClient["verifyRequest"] = async (
    request,
    policy,
    setHeaders
  ) => {
    const merged = { ...base, ...policy }
    return verifyRequest(request, verifyMessage, nonceStore, merged, setHeaders)
  }

  return { verifyRequest: verifyRequestBound }
}
