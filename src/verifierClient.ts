import type {
  NonceStore,
  VerifyMessageFn,
  VerifyPolicy,
  VerifyResult
} from "./lib/types.js"
import { verifyRequest } from "./verify.js"

export type VerifierClientOptions = VerifyPolicy

export type VerifierClient = {
  verifyRequest: (
    request: Request,
    policy?: VerifyPolicy
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
    policy
  ) => {
    const merged = { ...base, ...policy }
    return verifyRequest(request, verifyMessage, nonceStore, merged)
  }

  return { verifyRequest: verifyRequestBound }
}
