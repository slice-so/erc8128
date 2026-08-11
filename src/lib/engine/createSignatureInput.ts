import type {
  ComponentIdentifier,
  ParsedSignatureInputMember,
  ParsedSignatureParams,
  SfInnerList,
  SfItem
} from "../../types"
import { TAG_DELEGATED, TAG_REQUEST } from "../delegation/delegationField"
import { Erc8128Error } from "../Erc8128Error"
import {
  normalizeComponentIdentifier,
  serializeComponentIdentifier
} from "./componentIdentifier"
import {
  parseSfDictionary,
  parseSfInnerList,
  serializeSfMember
} from "./structuredFields"

const COMPONENT_PARAMETER_NAMES = new Set([
  "sf",
  "bs",
  "tr",
  "req",
  "key",
  "name"
])
export function parseSignatureInputDictionary(
  headerValue: string
): ParsedSignatureInputMember[] {
  const dictionary = parseSfDictionary(headerValue)
  const receivedMemberValues = new Map<string, string>()
  for (const rawMember of splitTopLevelCommas(headerValue)) {
    const separator = rawMember.indexOf("=")
    if (separator <= 0) continue
    receivedMemberValues.set(
      rawMember.slice(0, separator).trim(),
      rawMember.slice(separator + 1).trim()
    )
  }
  const candidates: ParsedSignatureInputMember[] = []
  for (const [label, member] of Object.entries(dictionary)) {
    try {
      assertLabel(label)
      if (!("items" in member)) {
        throw new Erc8128Error(
          "PARSE_ERROR",
          "Signature-Input members must be Inner Lists."
        )
      }
      const profileTag = member.params?.tag
      const profileCandidate =
        profileTag === TAG_REQUEST || profileTag === TAG_DELEGATED
      if (
        member.items.length > 32 ||
        Object.keys(member.params ?? {}).length > 16
      ) {
        if (profileCandidate) {
          throw new Erc8128Error(
            "LIMIT_EXCEEDED",
            "Signature candidate exceeds its component or parameter limit."
          )
        }
        continue
      }
      const components = member.items.map(parseComponentIdentifier)
      if (components.length === 0) {
        throw new Erc8128Error(
          "PARSE_ERROR",
          "Signature component list is empty."
        )
      }
      if (
        new Set(components.map(serializeComponentIdentifier)).size !==
        components.length
      ) {
        throw new Erc8128Error(
          "PARSE_ERROR",
          "Covered components must not be repeated."
        )
      }
      const params = parseSignatureParams(member)
      candidates.push({
        label,
        components,
        params,
        signatureParamsValue:
          receivedMemberValues.get(label) ?? serializeSfMember(member)
      })
    } catch (error) {
      if (error instanceof Erc8128Error && error.code === "LIMIT_EXCEEDED") {
        throw error
      }
      if (!(error instanceof Erc8128Error && error.code === "PARSE_ERROR")) {
        throw error
      }
      // The Dictionary itself is syntactically valid. A member outside the
      // RFC 9421/ERC-8128 profile is simply not an ERC-8128 candidate.
    }
  }
  return candidates
}

export function parseSignatureDictionary(
  headerValue: string
): Map<string, string> {
  const dictionary = parseSfDictionary(headerValue)
  const signatures = new Map<string, string>()
  for (const [label, member] of Object.entries(dictionary)) {
    assertLabel(label)
    if (
      !("value" in member) ||
      typeof member.value !== "object" ||
      member.value.type !== "binary" ||
      Object.keys(member.params ?? {}).length !== 0 ||
      member.value.value.length === 0
    ) {
      continue
    }
    signatures.set(label, bytesToBase64(member.value.value))
  }
  return signatures
}

export function parseSignatureInputHeader(
  headerValue: string
): ParsedSignatureInputMember[] {
  return parseSignatureInputDictionary(headerValue)
}

export function parseSignatureHeader(headerValue: string): Map<string, string> {
  return parseSignatureDictionary(headerValue)
}

export function parseInnerListWithBareParams(value: string): {
  items: ComponentIdentifier[]
  bareParams: string[]
} {
  const member = parseSfInnerList(value)
  const items = member.items.map(parseComponentIdentifier)
  const bareParams = Object.entries(member.params ?? {}).map(([key, value]) => {
    if (value !== true) {
      throw new Erc8128Error(
        "PARSE_ERROR",
        `Accept-Signature param ${key} must be bare.`
      )
    }
    return key
  })
  return { items, bareParams }
}

export function splitTopLevelCommas(value: string): string[] {
  const members: string[] = []
  let start = 0
  let inString = false
  let inBinary = false
  let escaped = false
  let depth = 0
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]
    if (inString) {
      if (escaped) escaped = false
      else if (character === "\\") escaped = true
      else if (character === '"') inString = false
      continue
    }
    if (inBinary) {
      if (character === ":") inBinary = false
      continue
    }
    if (character === '"') inString = true
    else if (character === ":") inBinary = true
    else if (character === "(") depth += 1
    else if (character === ")") depth -= 1
    else if (character === "," && depth === 0) {
      members.push(value.slice(start, index))
      start = index + 1
    }
  }
  members.push(value.slice(start))
  return members
}

export function assertLabel(label: string): void {
  if (!/^[a-z*][a-z0-9_.*-]*$/.test(label)) {
    throw new Erc8128Error("PARSE_ERROR", `Invalid signature label: ${label}`)
  }
}

function parseComponentIdentifier(item: SfItem): ComponentIdentifier {
  if (typeof item.value !== "string") {
    throw new Erc8128Error("PARSE_ERROR", "Covered components must be strings.")
  }
  const params: NonNullable<ComponentIdentifier["params"]> = {}
  for (const [key, value] of Object.entries(item.params ?? {})) {
    if (!COMPONENT_PARAMETER_NAMES.has(key)) {
      throw new Erc8128Error(
        "PARSE_ERROR",
        `Unknown component parameter: ${key}.`
      )
    }
    if (key === "key" || key === "name") {
      if (typeof value !== "string") {
        throw new Erc8128Error(
          "PARSE_ERROR",
          `Component ${key} must be a string.`
        )
      }
      Object.assign(params, { [key]: value })
    } else {
      if (value !== true) {
        throw new Erc8128Error(
          "PARSE_ERROR",
          `Component ${key} must be bare true.`
        )
      }
      Object.assign(params, { [key]: true })
    }
  }
  let component: ComponentIdentifier
  try {
    component = normalizeComponentIdentifier(
      Object.keys(params).length === 0
        ? { name: item.value }
        : { name: item.value, params }
    )
  } catch {
    throw new Erc8128Error("PARSE_ERROR", "Invalid component identifier.")
  }
  if (component.name !== item.value) {
    throw new Erc8128Error(
      "PARSE_ERROR",
      "Component identifiers must use canonical lowercase names."
    )
  }
  return component
}

function parseSignatureParams(member: SfInnerList): ParsedSignatureParams {
  const values = member.params ?? {}
  const created = values.created
  const alg = values.alg
  const expires = values.expires
  const keyid = values.keyid
  const nonce = values.nonce
  const tag = values.tag
  return {
    created: Number.isInteger(created) ? (created as number) : Number.NaN,
    expires: Number.isInteger(expires) ? (expires as number) : Number.NaN,
    keyid: typeof keyid === "string" ? keyid : "",
    ...(alg === undefined ? {} : { alg }),
    ...(nonce === undefined
      ? {}
      : { nonce: typeof nonce === "string" ? nonce : "\u0000" }),
    ...(typeof tag === "string" ? { tag } : {})
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  let result = ""
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0
    const second = bytes[index + 1] ?? 0
    const third = bytes[index + 2] ?? 0
    const combined = (first << 16) | (second << 8) | third
    result += alphabet[(combined >> 18) & 63]
    result += alphabet[(combined >> 12) & 63]
    result += index + 1 < bytes.length ? alphabet[(combined >> 6) & 63] : "="
    result += index + 2 < bytes.length ? alphabet[combined & 63] : "="
  }
  return result
}
