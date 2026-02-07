import {
  type BindingMode,
  Erc8128Error,
  type SignatureParams
} from "../types.js"
import { assertLabel } from "./createSignatureInput.js"

export function serializeSignatureParamsInnerList(
  components: string[],
  params: SignatureParams
): string {
  const items = components.map((c) => quoteSfString(c)).join(" ")
  const inner = `(${items})`

  let out = inner
  out += `;created=${params.created}`
  out += `;expires=${params.expires}`
  if (params.nonce != null) out += `;nonce=${quoteSfString(params.nonce)}`
  if (params.tag != null) out += `;tag=${quoteSfString(params.tag)}`
  out += `;keyid=${quoteSfString(params.keyid)}`

  return out
}

/**
 * Validation helper kept separate from formatting so other call-sites can reuse it.
 * (Still throws the same error codes/messages as before.)
 */
export function assertSignatureParamsForSerialization(
  params: SignatureParams
): void {
  if (!Number.isInteger(params.created) || !Number.isInteger(params.expires))
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "created/expires must be integers."
    )
  if (params.expires <= params.created)
    throw new Erc8128Error("INVALID_OPTIONS", "expires must be > created.")
  if (!params.keyid)
    throw new Erc8128Error("INVALID_OPTIONS", "keyid is required.")
}

export function serializeSignatureInputHeader(
  label: string,
  signatureParamsValue: string
): string {
  assertLabel(label)
  return `${label}=${signatureParamsValue}`
}

export function serializeSignatureHeader(
  label: string,
  signatureB64: string
): string {
  assertLabel(label)
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureB64))
    throw new Erc8128Error("BAD_HEADER_VALUE", "Signature must be base64.")
  return `${label}=:${signatureB64}:`
}

export function appendDictionaryMember(
  existing: string | null,
  member: string
): string {
  if (!existing) return member
  return `${existing}, ${member}`
}

export function quoteSfString(value: string): string {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if ((code >= 0 && code <= 0x1f) || code === 0x7f)
      throw new Erc8128Error(
        "BAD_HEADER_VALUE",
        "sf-string cannot contain control characters."
      )
  }
  const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')
  return `"${escaped}"`
}

export function normalizeComponents(components: string[]): string[] {
  return components.map((c) => c.trim()).filter(Boolean)
}

export function defaultComponents(args: {
  binding: BindingMode
  hasQuery: boolean
  hasBody: boolean
}): string[] {
  const { binding, hasQuery, hasBody } = args

  if (binding === "class-bound") return ["@authority"]

  const c = ["@authority", "@method", "@path"]
  if (hasQuery) c.push("@query")
  if (hasBody) c.push("content-digest")
  return c
}

export function resolveComponents(args: {
  binding: BindingMode
  hasQuery: boolean
  hasBody: boolean
  providedComponents?: string[]
}): string[] {
  const { binding, hasQuery, hasBody, providedComponents } = args

  if (binding === "request-bound") {
    // Derive the minimal required set from the request and append extras if provided.
    const base = defaultComponents({ binding, hasQuery, hasBody })
    if (!providedComponents) return base
    const extra = normalizeComponents(providedComponents).filter(
      (c) => !base.includes(c)
    )
    return base.concat(extra)
  }

  // Class-bound: components are required
  if (!providedComponents) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "components are required for class-bound signatures."
    )
  }

  const components = normalizeComponents(providedComponents)
  // always include @authority
  if (!components.includes("@authority")) components.unshift("@authority")

  return components
}
