import { quoteSfString } from "./engine/serializations.js"

function serializeAcceptSignatureValue(
  components: string[],
  requireNonce: boolean
) {
  const items = components.map((c) => quoteSfString(c)).join(" ")
  let out = `(${items})`
  out += `;keyid;created;expires`
  if (requireNonce) out += `;nonce`
  return out
}

export function buildAcceptSignatureHeader(args: {
  requestBoundRequired: string[]
  classBoundPolicies: string[][]
  requireNonce: boolean
}): string {
  const { requestBoundRequired, classBoundPolicies, requireNonce } = args
  const entries: string[] = []
  const seen = new Set<string>()
  let index = 1

  const addEntry = (components: string[]) => {
    const key = components.join("\u0000")
    if (seen.has(key)) return
    seen.add(key)
    const value = serializeAcceptSignatureValue(components, requireNonce)
    entries.push(`sig${index}=${value}`)
    index++
  }

  addEntry(requestBoundRequired)
  for (const policy of classBoundPolicies) addEntry(policy)

  return entries.join(", ")
}
