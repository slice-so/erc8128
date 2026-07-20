import {
  getPublicKey,
  Point,
  recoverPublicKey,
  signAsync,
  utils
} from "@noble/secp256k1"
import { keccak_256 } from "@noble/hashes/sha3.js"
import type {
  Address,
  EoaHttpSigner,
  Hex,
  SessionSignerKeypair,
  VerifyMessageArgs
} from "../types"
import { hexToBytes, utf8Encode } from "../lib/utilities"

const bytesToHex = (bytes: Uint8Array): Hex =>
  `0x${[...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`

const concat = (...values: readonly Uint8Array[]) => {
  const output = new Uint8Array(values.reduce((total, value) => total + value.length, 0))
  let offset = 0
  for (const value of values) {
    output.set(value, offset)
    offset += value.length
  }
  return output
}

const personalMessageHash = (message: Uint8Array) =>
  keccak_256(
    concat(
      utf8Encode(`\x19Ethereum Signed Message:\n${message.length}`),
      message
    )
  )

const publicKeyAddress = (publicKey: Uint8Array): Address =>
  bytesToHex(keccak_256(publicKey.slice(1)).slice(-20)) as Address

export const verifyEoaMessage = ({
  address,
  message,
  mode,
  signature
}: VerifyMessageArgs) => {
  if (mode !== undefined && mode !== "eoa") return false
  const signatureBytes = hexToBytes(signature)
  if (signatureBytes.length !== 65) return false
  const recovery = signatureBytes[64]
  if (recovery === undefined) return false
  const recoveryId = recovery >= 27 ? recovery - 27 : recovery
  if (recoveryId !== 0 && recoveryId !== 1) return false
  try {
    const recoveredSignature = new Uint8Array(65)
    recoveredSignature[0] = recoveryId
    recoveredSignature.set(signatureBytes.slice(0, 64), 1)
    const publicKey = recoverPublicKey(
      recoveredSignature,
      personalMessageHash(hexToBytes(message.raw)),
      { prehash: false }
    )
    return (
      publicKeyAddress(Point.fromBytes(publicKey).toBytes(false)).toLowerCase() ===
      address.toLowerCase()
    )
  } catch {
    return false
  }
}

export const createSessionSignerKeypair = (): SessionSignerKeypair => {
  const privateKeyBytes = utils.randomSecretKey()
  return {
    address: publicKeyAddress(getPublicKey(privateKeyBytes, false)),
    privateKey: bytesToHex(privateKeyBytes)
  }
}

export const createEoaHttpSigner = ({
  chainId,
  privateKey
}: {
  chainId: number
  privateKey: Hex
}): EoaHttpSigner => {
  const privateKeyBytes = hexToBytes(privateKey)
  if (!utils.isValidSecretKey(privateKeyBytes)) {
    throw new Error("Session signer private key is invalid.")
  }
  const address = publicKeyAddress(getPublicKey(privateKeyBytes, false))
  return {
    address,
    chainId,
    privateKey,
    signMessage: async (message) => {
      const recovered = await signAsync(personalMessageHash(message), privateKeyBytes, {
        format: "recovered",
        prehash: false
      })
      const signature = new Uint8Array(65)
      signature.set(recovered.slice(1), 0)
      signature[64] = (recovered[0] ?? 0) + 27
      return bytesToHex(signature)
    }
  }
}
