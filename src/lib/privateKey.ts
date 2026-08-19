import type { Hex } from "viem"

const privateKeyPattern = /^0x[0-9a-fA-F]{64}$/

// ERC-8128 signers are configured with raw secp256k1 private keys; reject
// malformed configuration before it reaches a signing client.
export const assertErc8128PrivateKey = (
  privateKey: string,
  name = "ERC-8128 private key"
): Hex => {
  if (!privateKeyPattern.test(privateKey)) {
    throw new Error(`Invalid ${name}`)
  }
  return privateKey as Hex
}
