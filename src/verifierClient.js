import { verifyRequest } from "./verify.js"
export function createVerifierClient(verifyMessage, nonceStore, defaults) {
  const base = defaults ?? {}
  const verifyRequestBound = async (request, policy, setHeaders) => {
    const merged = { ...base, ...policy }
    return verifyRequest(request, verifyMessage, nonceStore, merged, setHeaders)
  }
  return { verifyRequest: verifyRequestBound }
}
//# sourceMappingURL=verifierClient.js.map
