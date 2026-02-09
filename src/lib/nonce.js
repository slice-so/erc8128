//////////////////////////////
// Nonce
//////////////////////////////
import { base64UrlEncode, randomBytes } from "./utilities.js"
export async function resolveNonce(opts) {
  if (typeof opts.nonce === "string") return opts.nonce
  if (typeof opts.nonce === "function") return opts.nonce()
  // Auto-generate nonce if not provided (required for non-replayable signatures)
  const rnd = randomBytes(16)
  return base64UrlEncode(rnd)
}
//# sourceMappingURL=nonce.js.map
