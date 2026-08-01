import type {
  ComponentIdentifier,
  ParsedSignatureInputMember,
  SfInnerList,
  SfItem,
  SignatureParams
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
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
const SIGNATURE_PARAMETER_NAMES = new Set([
  "created",
  "expires",
  "keyid",
  "nonce",
  "tag"
])

export function parseSignatureInputDictionary(
  headerValue: string
): ParsedSignatureInputMember[] {
  const dictionary = parseSfDictionary(headerValue)
  return Object.entries(dictionary).map(([label, member]) => {
    assertLabel(label)
    if (!("items" in member)) {
      throw new Erc8128Error(
        "PARSE_ERROR",
        "Signature-Input members must be Inner Lists."
      )
    }
    const components = member.items.map(parseComponentIdentifier)
    if (components.length === 0) {
      throw new Erc8128Error(
        "PARSE_ERROR",
        "Signature component list is empty."
      )
    }
    const params = parseSignatureParams(member)
    return {
      label,
      components,
      params,
      signatureParamsValue: serializeSfMember(member)
    }
  })
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
      throw new Erc8128Error(
        "PARSE_ERROR",
        "Signature members must be non-empty Byte Sequences."
      )
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
  return Object.keys(params).length === 0
    ? { name: item.value.toLowerCase() }
    : { name: item.value.toLowerCase(), params }
}

function parseSignatureParams(member: SfInnerList): SignatureParams {
  const values = member.params ?? {}
  for (const key of Object.keys(values)) {
    if (!SIGNATURE_PARAMETER_NAMES.has(key)) {
      throw new Erc8128Error(
        "PARSE_ERROR",
        `Unsupported signature parameter: ${key}.`
      )
    }
  }
  const created = values.created
  const expires = values.expires
  const keyid = values.keyid
  const nonce = values.nonce
  const tag = values.tag
  if (
    !Number.isInteger(created) ||
    !Number.isInteger(expires) ||
    typeof keyid !== "string" ||
    (nonce !== undefined && typeof nonce !== "string") ||
    (tag !== undefined && typeof tag !== "string")
  ) {
    throw new Erc8128Error(
      "PARSE_ERROR",
      "Missing or invalid created/expires/keyid in Signature-Input."
    )
  }
  return {
    created: created as number,
    expires: expires as number,
    keyid,
    ...(nonce === undefined ? {} : { nonce: nonce as string }),
    ...(tag === undefined ? {} : { tag: tag as string })
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
