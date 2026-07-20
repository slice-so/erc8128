import type { Hex, VerifyMessageFn, VerifySessionGrantParameters } from "../types"
import { utf8Encode } from "../lib/utilities"
import { parseSessionGrantMessage, validateSessionGrant } from "./grant"
import { verifyEoaMessage } from "./eoaVerify"

const bytesToHex = (bytes: Uint8Array): Hex =>
  `0x${[...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`

const verifyGrantSignature = async ({
  message,
  signature,
  verifyMessage
}: {
  message: string
  signature: Hex
  verifyMessage: VerifyMessageFn
}) => {
  const grant = parseSessionGrantMessage(message)
  if (grant === null) return null
  const valid = await verifyMessage({
    address: grant.account,
    message: { raw: bytesToHex(utf8Encode(message)) },
    mode: "eoa",
    signature
  })
  return valid ? grant : null
}

export const verifySessionGrant = async ({
  expected,
  message,
  nonceStore,
  signature,
  verifyMessage = verifyEoaMessage
}: VerifySessionGrantParameters) => {
  const grant = await verifyGrantSignature({ message, signature, verifyMessage })
  if (grant === null || !validateSessionGrant(grant, expected)) return null
  const ttlSeconds = Math.max(0, grant.expiresAt - (expected.now ?? Math.floor(Date.now() / 1000)))
  if (!(await nonceStore.consume(grant.nonce, ttlSeconds))) return null
  return grant
}
