import type {
  CreateVerifierClientArgs,
  VerifierClientVerifyRequestArgs,
  VerifyPolicy,
  VerifyResult
} from "./lib/types.js"
import { verifyRequest } from "./verify.js"

export type VerifierClientOptions = VerifyPolicy

export type VerifierClient = {
  verifyRequest: (
    args: VerifierClientVerifyRequestArgs
  ) => Promise<VerifyResult>
}

export function createVerifierClient(
  args: CreateVerifierClientArgs
): VerifierClient {
  const { verifyMessage, nonceStore, defaults } = args
  const base = defaults ?? {}

  const verifyRequestBound: VerifierClient["verifyRequest"] = async (args) => {
    const { request, policy, setHeaders } = args
    const merged = { ...base, ...policy }
    return verifyRequest({
      request,
      verifyMessage,
      nonceStore,
      policy: merged,
      setHeaders
    })
  }

  return { verifyRequest: verifyRequestBound }
}
