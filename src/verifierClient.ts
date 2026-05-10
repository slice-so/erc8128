import type { CreateVerifierClientArgs, VerifierClient } from "./types"
import { verifyRequest } from "./verify"

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
