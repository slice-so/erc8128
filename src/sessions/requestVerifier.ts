import type {
  CreateSessionRequestVerifierParameters,
  SessionRequestVerificationResult
} from "../types"
import { verifyRequest } from "../verify"
import { verifyEoaMessage } from "./eoaVerify"

export const createSessionRequestVerifier = ({
  audience,
  nonceStore,
  policy,
  registry,
  verifyMessage = verifyEoaMessage
}: CreateSessionRequestVerifierParameters) => ({
  verify: async (
    request: Request
  ): Promise<SessionRequestVerificationResult> => {
    if (new URL(request.url).origin !== new URL(audience).origin) {
      return { ok: false, reason: "no_session" }
    }
    let sessionFailure: "no_session" | "session_expired" | null = null
    const result = await verifyRequest({
      nonceStore,
      policy,
      request,
      verifyMessage: async (args) => {
        const parsedKeyId = request.headers
          .get("Signature-Input")
          ?.match(/;keyid="(erc8128:\d+:0x[0-9a-fA-F]{40})"/)?.[1]
        if (parsedKeyId === undefined) {
          sessionFailure = "no_session"
          return false
        }
        const record = await registry.get(parsedKeyId)
        if (record === null || record.audience !== audience) {
          sessionFailure = "no_session"
          return false
        }
        if (record.expiresAt < Math.floor(Date.now() / 1000)) {
          await registry.delete(parsedKeyId)
          sessionFailure = "session_expired"
          return false
        }
        if (
          record.chainId !== Number(parsedKeyId?.split(":")[1]) ||
          record.sessionSigner.toLowerCase() !== args.address.toLowerCase()
        ) {
          sessionFailure = "no_session"
          return false
        }
        return verifyMessage(args)
      }
    })
    return !result.ok && sessionFailure !== null
      ? { ok: false, reason: sessionFailure }
      : result
  }
})
