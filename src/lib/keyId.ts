//////////////////////////////
// keyid
//////////////////////////////

import type { Address } from "./types.js"
import { Erc8128Error } from "./types.js"

export function formatKeyId(chainId: number, address: Address): string {
  if (!Number.isInteger(chainId))
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "chainId must be positive integer."
    )
  return `erc8128:${chainId}:${address.toLowerCase()}`
}

export function parseKeyId(
  keyid: string
): { chainId: number; address: Address } | null {
  const m = /^erc8128:(\d+):(0x[a-fA-F0-9]{40})$/.exec(keyid)
  if (!m) return null
  const chainId = Number(m[1])
  if (!Number.isInteger(chainId)) return null
  return { chainId, address: m[2].toLowerCase() as Address }
}
