import type {
  BindingMode,
  ComponentIdentifier,
  CoveredComponent,
  SignatureParams
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import {
  componentIdentifierEquals,
  normalizeComponentIdentifiers
} from "./componentIdentifier"
import { assertLabel } from "./createSignatureInput"
import { serializeSfMember } from "./structuredFields"

export function serializeSignatureParamsInnerList(
  components: readonly CoveredComponent[],
  params: SignatureParams
): string {
  return serializeSfMember({
    items: normalizeComponentIdentifiers(components).map((component) => ({
      value: component.name,
      params: component.params
    })),
    params: {
      created: params.created,
      expires: params.expires,
      ...(params.nonce === undefined ? {} : { nonce: params.nonce }),
      keyid: params.keyid,
      ...(params.tag === undefined ? {} : { tag: params.tag })
    }
  })
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
  return serializeSfMember({ value })
}

export function normalizeComponents(
  components: readonly CoveredComponent[]
): ComponentIdentifier[] {
  return normalizeComponentIdentifiers(components)
}

export function defaultComponents(args: {
  binding: BindingMode
  hasQuery: boolean
  hasBody: boolean
}): ComponentIdentifier[] {
  const { binding, hasBody } = args

  if (binding === "class-bound") return [{ name: "@authority" }]

  const c: ComponentIdentifier[] = [
    { name: "@scheme" },
    { name: "@authority" },
    { name: "@method" },
    { name: "@path" },
    { name: "@query" }
  ]
  if (hasBody) c.push({ name: "content-digest" })
  return c
}

export function resolveComponents(args: {
  binding: BindingMode
  hasQuery: boolean
  hasBody: boolean
  providedComponents?: readonly CoveredComponent[]
}): ComponentIdentifier[] {
  const { binding, hasQuery, hasBody, providedComponents } = args

  if (binding === "request-bound") {
    // Derive the minimal required set from the request and append extras if provided.
    const base = defaultComponents({ binding, hasQuery, hasBody })
    if (!providedComponents) return base
    const extra = normalizeComponents(providedComponents).filter(
      (component) =>
        !base.some((baseComponent) =>
          componentIdentifierEquals(baseComponent, component)
        )
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
  if (!components.some((component) => component.name === "@authority")) {
    components.unshift({ name: "@authority" })
  }

  return components
}
