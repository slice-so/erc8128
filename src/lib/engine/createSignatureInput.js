//////////////////////////////
// Parsing: Signature-Input / Signature
//////////////////////////////
import { Erc8128Error } from "../types.js"
export function parseSignatureInputDictionary(headerValue) {
  const out = []
  for (const raw of splitTopLevelCommas(headerValue)) {
    const m = raw.trim()
    if (!m) continue
    const eq = m.indexOf("=")
    if (eq <= 0)
      throw new Erc8128Error(
        "PARSE_ERROR",
        "Invalid Signature-Input member (missing '=')."
      )
    const label = m.slice(0, eq).trim()
    assertLabel(label)
    const value = m.slice(eq + 1).trim() // inner-list + params
    // Keep raw value to use for @signature-params line
    const signatureParamsValue = value
    const parsed = parseInnerListWithParams(value)
    out.push({
      label,
      components: parsed.items,
      params: parsed.params,
      signatureParamsValue
    })
  }
  return out
}
export function parseSignatureDictionary(headerValue) {
  const out = new Map()
  for (const raw of splitTopLevelCommas(headerValue)) {
    const m = raw.trim()
    if (!m) continue
    const eq = m.indexOf("=")
    if (eq <= 0)
      throw new Erc8128Error(
        "PARSE_ERROR",
        "Invalid Signature member (missing '=')."
      )
    const label = m.slice(0, eq).trim()
    assertLabel(label)
    const value = m.slice(eq + 1).trim()
    const b64 = parseBinaryItem(value)
    out.set(label, b64)
  }
  return out
}
function parseBinaryItem(v) {
  // sf-binary: :base64:
  const s = v.trim()
  if (!s.startsWith(":") || !s.endsWith(":") || s.length < 3)
    throw new Erc8128Error("PARSE_ERROR", "Invalid sf-binary.")
  const inner = s.slice(1, -1)
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(inner))
    throw new Erc8128Error("PARSE_ERROR", "Invalid base64 in sf-binary.")
  return inner
}
function parseInnerListWithParams(value) {
  // value like: ("@authority" "@method" "@path");created=...;expires=...;nonce="...";keyid="..."
  let i = 0
  const s = value.trim()
  if (s[i] !== "(")
    throw new Erc8128Error("PARSE_ERROR", "Inner list must start with '('.")
  i++ // skip '('
  const items = []
  while (i < s.length) {
    skipWs()
    if (s[i] === ")") {
      i++
      break
    }
    const str = parseSfString()
    items.push(str)
    skipWs()
  }
  if (items.length === 0)
    throw new Erc8128Error("PARSE_ERROR", "Inner list has no items.")
  const params = {}
  while (i < s.length) {
    skipWs()
    if (s[i] !== ";") break
    i++ // skip ';'
    skipWs()
    const key = parseToken()
    skipWs()
    if (s[i] !== "=")
      throw new Erc8128Error("PARSE_ERROR", `Param ${key} missing '='.`)
    i++
    skipWs()
    const val = parseParamValue()
    params[key] = val
  }
  const created = params.created
  const expires = params.expires
  const keyid = params.keyid
  const nonce = params.nonce
  const tag = params.tag
  if (
    !Number.isInteger(created) ||
    !Number.isInteger(expires) ||
    typeof keyid !== "string"
  ) {
    throw new Erc8128Error(
      "PARSE_ERROR",
      "Missing or invalid created/expires/keyid in Signature-Input."
    )
  }
  const outParams = {
    created: created,
    expires: expires,
    keyid: keyid,
    ...(typeof nonce === "string" ? { nonce } : {}),
    ...(typeof tag === "string" ? { tag } : {})
  }
  return { items, params: outParams }
  function skipWs() {
    while (i < s.length && (s[i] === " " || s[i] === "\t")) i++
  }
  function parseSfString() {
    if (s[i] !== '"')
      throw new Erc8128Error("PARSE_ERROR", "Expected sf-string.")
    i++ // skip "
    let out = ""
    while (i < s.length) {
      const ch = s[i]
      if (ch === '"') {
        i++
        break
      }
      if (ch === "\\") {
        i++
        if (i >= s.length)
          throw new Erc8128Error("PARSE_ERROR", "Bad escape in sf-string.")
        out += s[i]
        i++
        continue
      }
      // disallow controls
      const code = ch.charCodeAt(0)
      if (code < 0x20 || code === 0x7f)
        throw new Erc8128Error("PARSE_ERROR", "Control char in sf-string.")
      out += ch
      i++
    }
    return out
  }
  function parseToken() {
    const start = i
    while (i < s.length && /[A-Za-z0-9_\-*.]/.test(s[i])) i++
    if (i === start) throw new Erc8128Error("PARSE_ERROR", "Expected token.")
    return s.slice(start, i)
  }
  function parseParamValue() {
    if (s[i] === '"') return parseSfString()
    // integer
    const start = i
    if (s[i] === "-") i++
    while (i < s.length && /[0-9]/.test(s[i])) i++
    if (i === start)
      throw new Erc8128Error("PARSE_ERROR", "Expected param value.")
    const num = Number(s.slice(start, i))
    if (!Number.isFinite(num))
      throw new Erc8128Error("PARSE_ERROR", "Bad integer param value.")
    return num
  }
}
function splitTopLevelCommas(s) {
  // Split on commas not inside quotes.
  const out = []
  let cur = ""
  let inQuotes = false
  let isEscaped = false
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]
    if (isEscaped) {
      cur += ch
      isEscaped = false
      continue
    }
    if (ch === "\\" && inQuotes) {
      cur += ch
      isEscaped = true
      continue
    }
    if (ch === '"') {
      cur += ch
      inQuotes = !inQuotes
      continue
    }
    if (ch === "," && !inQuotes) {
      out.push(cur)
      cur = ""
      continue
    }
    cur += ch
  }
  if (cur) out.push(cur)
  return out
}
export function assertLabel(label) {
  // Minimal signature label: lowercase token
  if (!/^[a-z][a-z0-9_.-]*$/.test(label))
    throw new Erc8128Error("PARSE_ERROR", `Invalid signature label: ${label}`)
}
//# sourceMappingURL=createSignatureInput.js.map
