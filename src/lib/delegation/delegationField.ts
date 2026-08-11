import { hashTypedData, type Hex as ViemHex } from "viem"
import type {
  ComponentIdentifier,
  Delegation,
  DelegationAudiencePolicy,
  DelegationChain,
  DelegationLink,
  DelegationTypedData,
  ParsedDelegationField,
  SfDictionary
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import {
  normalizeComponentIdentifier,
  serializeComponentIdentifier
} from "../engine/componentIdentifier"
import {
  parseSfDictionary,
  parseSfInnerList,
  serializeSfDictionary,
  sfBinary
} from "../engine/structuredFields"
import { formatKeyId, parseKeyId } from "../keyId"
import { bytesToHex, hexToBytes } from "../utilities"
import { decodeDelegationLinkCbor, encodeDelegationLinkCbor } from "./cbor"
import {
  MAX_DELEGATION_ARRAY_ENTRIES,
  MAX_DELEGATION_FIELD_BYTES,
  MAX_DELEGATION_LINK_BYTES,
  MAX_DELEGATION_STRING_BYTES
} from "./limits"

export const DELEGATION_FIELD_NAME = "erc-8128-delegation"
export const DELEGATION_COMPONENT = {
  name: DELEGATION_FIELD_NAME,
  params: { sf: true }
} as const satisfies ComponentIdentifier
export const TAG_REQUEST = "erc8128"
export const TAG_DELEGATED = "erc8128-delegated"
export const ZERO_DELEGATION_PARENT =
  "0x0000000000000000000000000000000000000000000000000000000000000000"

/**
 * Candidate reference deployment coordinates pinned by the Slice
 * implementation. Verifiers still fail closed on chains where this exact
 * runtime is not deployed.
 */
export const ERC8128_REVOCATION_REGISTRY_ADDRESS =
  "0xb2a9330825d6aabbf7cc7004bc0916291c3322ad" as const
export const ERC8128_REVOCATION_REGISTRY_RUNTIME_CODE_HASH =
  "0x5a93f9fbc9de24c9d2b5fe7e9fd81ac3b59a8bb6919977a844c24227b7d58804" as const

export const DELEGATION_TYPE_STRING =
  "Delegation(string issuer,string delegate,string[] audiences,bytes32 id,uint64 epoch,uint64 validAfter,uint64 validUntil,uint32 maxRequestValiditySeconds,bool delegateIsEOA,bool requireNonReplayable,string[] requiredComponents,string[] permissions,bytes32 parentGrantHash)"

export const DELEGATION_TYPES = {
  Delegation: [
    { name: "issuer", type: "string" },
    { name: "delegate", type: "string" },
    { name: "audiences", type: "string[]" },
    { name: "id", type: "bytes32" },
    { name: "epoch", type: "uint64" },
    { name: "validAfter", type: "uint64" },
    { name: "validUntil", type: "uint64" },
    { name: "maxRequestValiditySeconds", type: "uint32" },
    { name: "delegateIsEOA", type: "bool" },
    { name: "requireNonReplayable", type: "bool" },
    { name: "requiredComponents", type: "string[]" },
    { name: "permissions", type: "string[]" },
    { name: "parentGrantHash", type: "bytes32" }
  ]
} as const

export const ERC8128_REVOCATION_ABI = [
  {
    type: "function",
    name: "currentEpoch",
    stateMutability: "view",
    inputs: [{ name: "issuer", type: "address" }],
    outputs: [{ name: "currentEpoch", type: "uint64" }]
  },
  {
    type: "function",
    name: "status",
    stateMutability: "view",
    inputs: [
      { name: "issuer", type: "address" },
      { name: "id", type: "bytes32" }
    ],
    outputs: [
      { name: "isRevoked", type: "bool" },
      { name: "epoch", type: "uint64" }
    ]
  },
  {
    type: "function",
    name: "eip712Domain",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "fields", type: "bytes1" },
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "verifyingContract", type: "address" },
      { name: "salt", type: "bytes32" },
      { name: "extensions", type: "uint256[]" }
    ]
  },
  {
    type: "function",
    name: "revoke",
    stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "bytes32" }],
    outputs: []
  },
  {
    type: "function",
    name: "revokeBySig",
    stateMutability: "nonpayable",
    inputs: [
      { name: "issuer", type: "address" },
      { name: "id", type: "bytes32" },
      { name: "sig", type: "bytes" }
    ],
    outputs: []
  },
  {
    type: "function",
    name: "advanceEpoch",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [{ name: "newEpoch", type: "uint64" }]
  },
  {
    type: "event",
    name: "Revoked",
    inputs: [
      { name: "issuer", type: "address", indexed: true },
      { name: "id", type: "bytes32", indexed: true }
    ]
  },
  {
    type: "event",
    name: "EpochAdvanced",
    inputs: [
      { name: "issuer", type: "address", indexed: true },
      { name: "newEpoch", type: "uint64", indexed: false }
    ]
  }
] as const

const encoder = new TextEncoder()

export function getDelegationTypedData(grant: Delegation): DelegationTypedData {
  const issuer = requireCanonicalIdentity(grant.issuer, "issuer")
  return {
    domain: {
      name: "ERC-8128 Delegation",
      version: "1",
      chainId: issuer.chainId
    },
    types: DELEGATION_TYPES,
    primaryType: "Delegation",
    message: {
      ...grant,
      epoch: BigInt(grant.epoch),
      validAfter: BigInt(grant.validAfter),
      validUntil: BigInt(grant.validUntil)
    }
  }
}

export function hashDelegation(grant: Delegation): ViemHex {
  validateDelegationStructure(grant)
  return hashTypedData(getDelegationTypedData(grant))
}

export function encodeDelegationLink(link: DelegationLink): Uint8Array {
  validateDelegationStructure(link.grant)
  const signature = hexToBytes(link.signature)
  if (signature.length === 0) throw invalid("Delegation proof is empty.")
  return encodeDelegationLinkCbor(link)
}

export function decodeDelegationLink(bytes: Uint8Array): DelegationLink {
  if (bytes.length > MAX_DELEGATION_LINK_BYTES)
    throw tooLarge("Delegation Link is too large.")
  const link = decodeDelegationLinkCbor(bytes)
  validateDelegationStructure(link.grant)
  const canonical = encodeDelegationLink(link)
  if (bytesToHex(canonical) !== bytesToHex(bytes)) {
    throw parseError("Delegation Link CBOR is not canonical.")
  }
  return link
}

export function formatDelegationField(chain: DelegationChain): string {
  if (chain.links.length === 0) throw invalid("Delegation Chain is empty.")
  if (chain.links.length > MAX_DELEGATION_ARRAY_ENTRIES) {
    throw tooLarge("Delegation Chain has too many links.")
  }
  const dictionary: SfDictionary = {}
  for (const [index, link] of chain.links.entries()) {
    dictionary[`g${index}`] = {
      value: sfBinary(encodeDelegationLink(link))
    }
  }
  const fieldValue = serializeSfDictionary(dictionary)
  if (encoder.encode(fieldValue).length > MAX_DELEGATION_FIELD_BYTES) {
    throw tooLarge("Delegation field is too large.")
  }
  return fieldValue
}

export function parseDelegationField(
  fieldValue: string,
  policy: DelegationAudiencePolicy = {}
): ParsedDelegationField {
  if (encoder.encode(fieldValue).length > MAX_DELEGATION_FIELD_BYTES) {
    throw tooLarge("Delegation field is too large.")
  }
  let dictionary: SfDictionary
  try {
    dictionary = parseSfDictionary(fieldValue)
  } catch (error) {
    if (error instanceof Erc8128Error) throw error
    throw parseError("Delegation field is malformed.")
  }
  const entries = Object.entries(dictionary)
  if (entries.length === 0) throw parseError("Delegation field is empty.")
  if (entries.length > MAX_DELEGATION_ARRAY_ENTRIES) {
    throw tooLarge("Delegation field has too many links.")
  }
  const links = entries.map(([key, member], index) => {
    if (key !== `g${index}`) {
      throw parseError("Delegation links must be consecutive and ordered.")
    }
    if (
      !("value" in member) ||
      typeof member.value !== "object" ||
      member.value.type !== "binary" ||
      Object.keys(member.params ?? {}).length !== 0
    ) {
      throw parseError("Delegation links must be bare Byte Sequences.")
    }
    const link = decodeDelegationLink(member.value.value)
    validateDelegationAudiences(link.grant, policy)
    return link
  })
  const chain = { links }
  formatDelegationField(chain)
  return { chain, fieldValue }
}

export function parseDelegationComponent(value: string): ComponentIdentifier {
  assertString(value, "component")
  const separator = value.indexOf(";")
  const name = separator < 0 ? value : value.slice(0, separator)
  const parameters = separator < 0 ? "" : value.slice(separator)
  let item: ReturnType<typeof parseSfInnerList>["items"][number] | undefined
  try {
    const escaped = name.replace(/\\/g, "\\\\").replace(/"/g, '\\"')
    item = parseSfInnerList(`("${escaped}"${parameters})`).items[0]
  } catch {
    throw parseError("Delegation component is malformed.")
  }
  if (item === undefined || typeof item.value !== "string") {
    throw parseError("Delegation component is malformed.")
  }
  const component = normalizeComponentIdentifier({
    name: item.value,
    ...(Object.keys(item.params ?? {}).length === 0
      ? {}
      : {
          params: item.params as NonNullable<ComponentIdentifier["params"]>
        })
  })
  if (
    component.name === "@signature-params" ||
    component.name === DELEGATION_FIELD_NAME ||
    serializeDelegationComponent(component) !== value
  ) {
    throw parseError("Delegation component is forbidden or non-canonical.")
  }
  return component
}

export function serializeDelegationComponent(
  component: ComponentIdentifier
): string {
  const serialized = serializeComponentIdentifier(component)
  if (!serialized.startsWith('"')) throw invalid("Component is invalid.")
  const end = findClosingQuote(serialized)
  if (end < 1) throw invalid("Component is invalid.")
  return `${JSON.parse(serialized.slice(0, end + 1))}${serialized.slice(end + 1)}`
}

export function normalizeAudienceOrigin(
  input: string,
  policy: DelegationAudiencePolicy = {}
): string {
  const audience = parseCanonicalAudienceOrigin(input)
  if (audience.httpLoopback && policy.allowLoopbackAudiences !== true) {
    throw invalid(
      "HTTP loopback Audience requires explicit local-development policy."
    )
  }
  return audience.origin
}

export function isLoopbackAudienceOrigin(input: string): boolean {
  try {
    const audience = parseCanonicalAudienceOrigin(input)
    return isLoopback(new URL(audience.origin).hostname)
  } catch {
    return false
  }
}

function parseCanonicalAudienceOrigin(input: string): {
  httpLoopback: boolean
  origin: string
} {
  if (
    input.includes("*") ||
    /:\/\/[^/]*@/.test(input) ||
    /:\/\/[^/?#]*\.(?::\d+)?(?:[/?#]|$)/.test(input)
  ) {
    throw invalid("Audience must be an exact origin without a trailing dot.")
  }
  let url: URL
  try {
    url = new URL(input)
  } catch {
    throw invalid("Audience must be an absolute origin.")
  }
  if (
    url.origin === "null" ||
    url.username ||
    url.password ||
    (url.pathname !== "" && url.pathname !== "/") ||
    url.search ||
    url.hash ||
    url.hostname.endsWith(".")
  ) {
    throw invalid("Audience must contain only an RFC 6454 origin.")
  }
  const httpLoopback = url.protocol === "http:" && isLoopback(url.hostname)
  if (url.protocol !== "https:" && !httpLoopback) {
    throw invalid("Audience must use HTTPS except for loopback development.")
  }
  const normalized = url.origin.toLowerCase()
  if (normalized !== input) throw invalid("Audience must be canonical.")
  return { httpLoopback, origin: normalized }
}

export function validateDelegationAudiences(
  grant: Delegation,
  policy: DelegationAudiencePolicy = {}
): void {
  for (const audience of grant.audiences) {
    normalizeAudienceOrigin(audience, policy)
  }
}

export function validateDelegationStructure(grant: Delegation): void {
  if (
    typeof grant !== "object" ||
    grant === null ||
    Object.keys(grant).sort().join(",") !==
      "audiences,delegate,delegateIsEOA,epoch,id,issuer,maxRequestValiditySeconds,parentGrantHash,permissions,requireNonReplayable,requiredComponents,validAfter,validUntil"
  ) {
    throw parseError("Delegation has an invalid field set.")
  }
  requireCanonicalIdentity(grant.issuer, "issuer")
  requireCanonicalIdentity(grant.delegate, "delegate")
  assertArray(grant.audiences, "audiences", true)
  for (const audience of grant.audiences) parseCanonicalAudienceOrigin(audience)
  assertBytes32(grant.id, "id")
  assertInteger(grant.epoch, "epoch", 0, Number.MAX_SAFE_INTEGER)
  assertInteger(grant.validAfter, "validAfter", 0, Number.MAX_SAFE_INTEGER)
  assertInteger(grant.validUntil, "validUntil", 1, Number.MAX_SAFE_INTEGER)
  if (grant.validUntil <= grant.validAfter)
    throw parseError("Grant window is invalid.")
  assertInteger(
    grant.maxRequestValiditySeconds,
    "maxRequestValiditySeconds",
    1,
    0xffff_ffff
  )
  if (typeof grant.delegateIsEOA !== "boolean") {
    throw parseError("delegateIsEOA must be Boolean.")
  }
  if (typeof grant.requireNonReplayable !== "boolean") {
    throw parseError("requireNonReplayable must be Boolean.")
  }
  assertArray(grant.requiredComponents, "requiredComponents", false)
  for (const component of grant.requiredComponents)
    parseDelegationComponent(component)
  assertArray(grant.permissions, "permissions", false)
  assertBytes32(grant.parentGrantHash, "parentGrantHash")
}

function requireCanonicalIdentity(value: string, name: string) {
  assertString(value, name)
  const identity = parseKeyId(value)
  if (
    identity === null ||
    formatKeyId(identity.chainId, identity.address) !== value
  ) {
    throw parseError(`${name} must be a canonical CAIP-10 Account ID.`)
  }
  return identity
}

function assertArray(values: string[], name: string, nonEmpty: boolean): void {
  if (!Array.isArray(values) || (nonEmpty && values.length === 0)) {
    throw parseError(`${name} has an invalid entry count.`)
  }
  if (values.length > MAX_DELEGATION_ARRAY_ENTRIES) {
    throw tooLarge(`${name} has too many entries.`)
  }
  for (const value of values) assertString(value, name)
}

function assertString(value: string, name: string): void {
  if (typeof value !== "string") throw parseError(`${name} must be a String.`)
  if (!value.isWellFormed()) {
    throw parseError(`${name} must contain well-formed Unicode.`)
  }
  if (encoder.encode(value).length > MAX_DELEGATION_STRING_BYTES) {
    throw tooLarge(`${name} String is too large.`)
  }
}

function assertBytes32(value: string, name: string): void {
  if (!/^0x[0-9a-f]{64}$/.test(value)) {
    throw parseError(`${name} must be canonical bytes32.`)
  }
}

function assertInteger(
  value: number,
  name: string,
  minimum: number,
  maximum: number
): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw parseError(`${name} is outside its supported integer range.`)
  }
}

function isLoopback(hostname: string): boolean {
  const normalized = hostname.toLowerCase()
  if (
    normalized === "localhost" ||
    normalized === "[::1]" ||
    normalized === "::1"
  ) {
    return true
  }
  const match = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(normalized)
  return match?.slice(1).every((part) => Number(part) <= 255) ?? false
}

function findClosingQuote(value: string): number {
  let escaped = false
  for (let index = 1; index < value.length; index += 1) {
    const character = value[index]
    if (escaped) escaped = false
    else if (character === "\\") escaped = true
    else if (character === '"') return index
  }
  return -1
}

function invalid(message: string): Erc8128Error {
  return new Erc8128Error("INVALID_OPTIONS", message)
}

function parseError(message: string): Erc8128Error {
  return new Erc8128Error("PARSE_ERROR", message)
}

function tooLarge(message: string): Erc8128Error {
  return new Erc8128Error("DELEGATION_TOO_LARGE", message)
}
