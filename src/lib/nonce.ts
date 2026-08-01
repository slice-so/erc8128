//////////////////////////////
// Nonce
//////////////////////////////

import type { SignOptions } from "../types"
import { Erc8128Error } from "./Erc8128Error"
import { base64UrlEncode, randomBytes } from "./utilities"

export function isValidNonce(nonce: string): boolean {
  return /^[\x20-\x7e]{16,128}$/.test(nonce)
}

export async function resolveNonce(opts: SignOptions): Promise<string> {
  const nonce =
    typeof opts.nonce === "string"
      ? opts.nonce
      : typeof opts.nonce === "function"
        ? await opts.nonce()
        : base64UrlEncode(randomBytes(16))

  if (!isValidNonce(nonce)) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Nonce must contain at least 128 bits of signer randomness and be no more than 128 ASCII bytes."
    )
  }
  return nonce
}
