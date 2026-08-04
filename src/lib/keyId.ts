//////////////////////////////
// keyid
//////////////////////////////

import type { Address } from "../types"
import { Erc8128Error } from "./Erc8128Error"
import { isValidNonce } from "./nonce"

export function formatKeyId(chainId: number, address: Address): string {
  if (!Number.isSafeInteger(chainId) || chainId <= 0)
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "chainId must be positive integer."
    )
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    throw new Erc8128Error("INVALID_OPTIONS", "address must be 20-byte hex.")
  }
  return `eip155:${chainId}:${address.toLowerCase()}`
}

export function parseKeyId(
  keyid: string
): { chainId: number; address: Address } | null {
  const m = /^eip155:([1-9]\d*):(0x[a-f0-9]{40})$/.exec(keyid)
  if (!m) return null
  const chainId = Number(m[1])
  if (!Number.isSafeInteger(chainId) || chainId <= 0) return null
  return { chainId, address: m[2].toLowerCase() as Address }
}

export function keyIdEquals(left: string, right: string): boolean {
  const parsedLeft = parseKeyId(left)
  const parsedRight = parseKeyId(right)
  return (
    parsedLeft !== null &&
    parsedRight !== null &&
    parsedLeft.chainId === parsedRight.chainId &&
    parsedLeft.address.toLowerCase() === parsedRight.address.toLowerCase()
  )
}

export function formatReplayKey(keyid: string, nonce: string): string {
  const parsed = parseKeyId(keyid)
  if (parsed === null) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Replay key requires a CAIP-10 keyid."
    )
  }
  if (!isValidNonce(nonce)) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Nonce must be 1-128 printable ASCII bytes."
    )
  }
  return `${formatKeyId(parsed.chainId, parsed.address)}:${nonce}`
}
