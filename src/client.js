import { signedFetch, signRequest } from "./sign.js"

const REQUEST_INIT_KEYS = new Set([
  "method",
  "headers",
  "body",
  "signal",
  "credentials",
  "mode",
  "cache",
  "redirect",
  "referrer",
  "integrity",
  "keepalive",
  "window"
])
function isRequestInit(value) {
  if (!value || typeof value !== "object") return false
  for (const key of REQUEST_INIT_KEYS) {
    if (key in value) return true
  }
  return false
}
function splitInitAndOpts(initOrOpts, opts) {
  if (opts !== undefined) return { init: initOrOpts, opts }
  if (isRequestInit(initOrOpts)) return { init: initOrOpts }
  return { opts: initOrOpts }
}
export function createSignerClient(signer, defaults) {
  const base = defaults ?? {}
  const signRequestBound = async (input, initOrOpts, opts) => {
    const { init, opts: callOpts } = splitInitAndOpts(initOrOpts, opts)
    const merged = { ...base, ...callOpts }
    return signRequest(input, init, signer, merged)
  }
  const signedFetchBound = async (input, initOrOpts, opts) => {
    const { init, opts: callOpts } = splitInitAndOpts(initOrOpts, opts)
    const merged = { ...base, ...callOpts }
    return signedFetch(input, init, signer, merged)
  }
  const fetchBound = async (input, initOrOpts, opts) => {
    const { init, opts: callOpts } = splitInitAndOpts(initOrOpts, opts)
    const merged = { ...base, ...callOpts }
    return signedFetch(input, init, signer, merged)
  }
  return {
    signRequest: signRequestBound,
    signedFetch: signedFetchBound,
    fetch: fetchBound
  }
}
//# sourceMappingURL=client.js.map
