import { keccak_256 } from "@noble/hashes/sha3.js"
import { Point, recoverPublicKey, Signature } from "@noble/secp256k1"
import type { Address, Hex } from "../types"
import { bytesToHex, hexToBytes, utf8Encode } from "./utilities"

export function recoverCanonicalEoaAddress(
  message: Uint8Array,
  signature: Hex
): Address | null {
  const bytes = hexToBytes(signature)
  if (bytes.length !== 65) return null
  const recovery = bytes[64]
  if (recovery !== 27 && recovery !== 28) return null
  try {
    const compact = bytes.slice(0, 64)
    const parsed = Signature.fromBytes(compact)
    if (parsed.hasHighS()) return null
    const publicKey = Point.fromBytes(
      recoverPublicKey(
        parsed.addRecoveryBit(recovery - 27).toBytes("recovered"),
        hashEthereumMessage(message),
        { prehash: false }
      )
    ).toBytes(false)
    return bytesToHex(keccak_256(publicKey.slice(1)).slice(-20)) as Address
  } catch {
    return null
  }
}

export function verifyCanonicalEoaSignature(args: {
  address: Address
  message: Uint8Array
  signature: Hex
}): boolean {
  const recovered = recoverCanonicalEoaAddress(args.message, args.signature)
  return recovered?.toLowerCase() === args.address.toLowerCase()
}

export function hashEthereumMessage(message: Uint8Array): Uint8Array {
  const prefix = utf8Encode(`\u0019Ethereum Signed Message:\n${message.length}`)
  const input = new Uint8Array(prefix.length + message.length)
  input.set(prefix)
  input.set(message, prefix.length)
  return keccak_256(input)
}
