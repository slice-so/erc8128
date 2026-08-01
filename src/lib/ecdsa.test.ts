import { describe, expect, test } from "bun:test"
import { privateKeyToAccount } from "viem/accounts"
import { verifyCanonicalEoaSignature } from "./ecdsa"
import { bytesToHex, hexToBytes } from "./utilities"

const secp256k1Order =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const account = privateKeyToAccount(`0x${"11".repeat(32)}`)
const message = new TextEncoder().encode("strict ERC-8128 EOA signature")

describe("canonical EOA verification", () => {
  test("accepts canonical v and rejects compact recovery values", async () => {
    const signature = await account.signMessage({
      message: { raw: bytesToHex(message) }
    })
    expect(
      verifyCanonicalEoaSignature({
        address: account.address,
        message,
        signature
      })
    ).toBe(true)
    const compactV = hexToBytes(signature)
    compactV[64] = (compactV[64] ?? 27) - 27
    expect(
      verifyCanonicalEoaSignature({
        address: account.address,
        message,
        signature: bytesToHex(compactV)
      })
    ).toBe(false)
  })

  test("rejects a high-s malleable encoding", async () => {
    const signature = hexToBytes(
      await account.signMessage({ message: { raw: bytesToHex(message) } })
    )
    const lowS = BigInt(bytesToHex(signature.slice(32, 64)))
    const highS = (secp256k1Order - lowS).toString(16).padStart(64, "0")
    signature.set(hexToBytes(`0x${highS}`), 32)
    expect(
      verifyCanonicalEoaSignature({
        address: account.address,
        message,
        signature: bytesToHex(signature)
      })
    ).toBe(false)
  })
})
