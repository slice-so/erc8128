import {
  decodeAbiParameters,
  encodeAbiParameters,
  hashTypedData,
  type Hex as ViemHex
} from "viem"
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

export const DELEGATION_FIELD_NAME = "erc-8128-delegation"
export const DELEGATION_COMPONENT = {
  name: DELEGATION_FIELD_NAME,
  params: { sf: true }
} as const satisfies ComponentIdentifier
export const TAG_DIRECT = "erc8128"
export const TAG_DELEGATED = "erc8128-delegated"
export const ZERO_DELEGATION_PARENT =
  "0x0000000000000000000000000000000000000000000000000000000000000000"

export const DELEGATION_TYPE_STRING =
  "Delegation(string root,string delegate,string[] aud,bytes32 id,uint64 epoch,uint64 created,uint64 expires,uint32 maxAge,bool delegateIsEOA,bool allowReplayable,string[] components,string[] scope,bytes32 parent)"

export const DELEGATION_TYPES = {
  Delegation: [
    { name: "root", type: "string" },
    { name: "delegate", type: "string" },
    { name: "aud", type: "string[]" },
    { name: "id", type: "bytes32" },
    { name: "epoch", type: "uint64" },
    { name: "created", type: "uint64" },
    { name: "expires", type: "uint64" },
    { name: "maxAge", type: "uint32" },
    { name: "delegateIsEOA", type: "bool" },
    { name: "allowReplayable", type: "bool" },
    { name: "components", type: "string[]" },
    { name: "scope", type: "string[]" },
    { name: "parent", type: "bytes32" }
  ]
} as const

export const ERC8128_REVOCATION_ABI = [
  {
    type: "function",
    name: "status",
    stateMutability: "view",
    inputs: [
      { name: "root", type: "address" },
      { name: "id", type: "bytes32" }
    ],
    outputs: [
      { name: "isRevoked", type: "bool" },
      { name: "currentEpoch", type: "uint64" }
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
      { name: "root", type: "address" },
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
      { name: "root", type: "address", indexed: true },
      { name: "id", type: "bytes32", indexed: true }
    ]
  },
  {
    type: "event",
    name: "EpochAdvanced",
    inputs: [
      { name: "root", type: "address", indexed: true },
      { name: "newEpoch", type: "uint64", indexed: false }
    ]
  }
] as const

const DELEGATION_LINK_ABI = [
  {
    type: "tuple",
    components: DELEGATION_TYPES.Delegation
  },
  { type: "bytes" }
] as const
const MAX_FIELD_BYTES = 16_384
const MAX_LINK_BYTES = 8_192
const MAX_ARRAY_ENTRIES = 32
const MAX_STRING_BYTES = 256
const encoder = new TextEncoder()

export function getDelegationTypedData(grant: Delegation): DelegationTypedData {
  const root = requireCanonicalIdentity(grant.root, "root")
  return {
    domain: {
      name: "ERC-8128 Delegation",
      version: "1",
      chainId: root.chainId
    },
    types: DELEGATION_TYPES,
    primaryType: "Delegation",
    message: {
      ...grant,
      epoch: BigInt(grant.epoch),
      created: BigInt(grant.created),
      expires: BigInt(grant.expires)
    }
  }
}

export function hashDelegation(
  grant: Delegation,
  policy: DelegationAudiencePolicy = {}
): ViemHex {
  validateDelegation(grant, policy)
  return hashTypedData(getDelegationTypedData(grant))
}

export function encodeDelegationLink(
  link: DelegationLink,
  policy: DelegationAudiencePolicy = {}
): Uint8Array {
  validateDelegation(link.grant, policy)
  const signature = hexToBytes(link.signature)
  if (signature.length === 0) throw invalid("Delegation proof is empty.")
  return hexToBytes(
    encodeAbiParameters(DELEGATION_LINK_ABI, [
      {
        ...link.grant,
        epoch: BigInt(link.grant.epoch),
        created: BigInt(link.grant.created),
        expires: BigInt(link.grant.expires),
        maxAge: link.grant.maxAge
      },
      link.signature
    ])
  )
}

export function decodeDelegationLink(
  bytes: Uint8Array,
  policy: DelegationAudiencePolicy = {}
): DelegationLink {
  if (bytes.length > MAX_LINK_BYTES)
    throw tooLarge("Delegation Link is too large.")
  let decoded: ReturnType<
    typeof decodeAbiParameters<typeof DELEGATION_LINK_ABI>
  >
  try {
    decoded = decodeAbiParameters(DELEGATION_LINK_ABI, bytesToHex(bytes))
  } catch {
    throw parseError("Delegation Link ABI is invalid.")
  }
  const [value, signature] = decoded
  const grant: Delegation = {
    root: value.root,
    delegate: value.delegate,
    aud: [...value.aud],
    id: value.id,
    epoch: safeInteger(value.epoch, "epoch"),
    created: safeInteger(value.created, "created"),
    expires: safeInteger(value.expires, "expires"),
    maxAge: safeInteger(value.maxAge, "maxAge"),
    delegateIsEOA: value.delegateIsEOA,
    allowReplayable: value.allowReplayable,
    components: [...value.components],
    scope: [...value.scope],
    parent: value.parent
  }
  const link = { grant, signature }
  validateDelegation(grant, policy)
  if (hexToBytes(signature).length === 0) {
    throw parseError("Delegation proof is empty.")
  }
  const canonical = encodeDelegationLink(link, policy)
  if (bytesToHex(canonical) !== bytesToHex(bytes)) {
    throw parseError("Delegation Link ABI is not canonical.")
  }
  return link
}

export function formatDelegationField(
  chain: DelegationChain,
  policy: DelegationAudiencePolicy = {}
): string {
  if (chain.links.length === 0) throw invalid("Delegation Chain is empty.")
  const dictionary: SfDictionary = {}
  for (const [index, link] of chain.links.entries()) {
    dictionary[`g${index}`] = {
      value: sfBinary(encodeDelegationLink(link, policy))
    }
  }
  const fieldValue = serializeSfDictionary(dictionary)
  if (encoder.encode(fieldValue).length > MAX_FIELD_BYTES) {
    throw tooLarge("Delegation field is too large.")
  }
  return fieldValue
}

export function parseDelegationField(
  fieldValue: string,
  policy: DelegationAudiencePolicy = {}
): ParsedDelegationField {
  if (encoder.encode(fieldValue).length > MAX_FIELD_BYTES) {
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
    return decodeDelegationLink(member.value.value, policy)
  })
  const chain = { links }
  formatDelegationField(chain, policy)
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
  const loopback = isLoopback(url.hostname)
  if (
    url.protocol !== "https:" &&
    !(
      url.protocol === "http:" &&
      loopback &&
      policy.allowLoopbackAudiences === true
    )
  ) {
    throw invalid("Audience must use HTTPS except for loopback development.")
  }
  const normalized = url.origin.toLowerCase()
  if (normalized !== input) throw invalid("Audience must be canonical.")
  return normalized
}

export function validateDelegation(
  grant: Delegation,
  policy: DelegationAudiencePolicy = {}
): void {
  if (
    typeof grant !== "object" ||
    grant === null ||
    Object.keys(grant).sort().join(",") !==
      "allowReplayable,aud,components,created,delegate,delegateIsEOA,epoch,expires,id,maxAge,parent,root,scope"
  ) {
    throw parseError("Delegation has an invalid field set.")
  }
  requireCanonicalIdentity(grant.root, "root")
  requireCanonicalIdentity(grant.delegate, "delegate")
  assertArray(grant.aud, "aud", true)
  for (const audience of grant.aud) normalizeAudienceOrigin(audience, policy)
  assertBytes32(grant.id, "id")
  assertInteger(grant.epoch, "epoch", 0, Number.MAX_SAFE_INTEGER)
  assertInteger(grant.created, "created", 0, Number.MAX_SAFE_INTEGER)
  assertInteger(grant.expires, "expires", 1, Number.MAX_SAFE_INTEGER)
  if (grant.expires <= grant.created)
    throw parseError("Grant window is invalid.")
  assertInteger(grant.maxAge, "maxAge", 1, 0xffff_ffff)
  if (typeof grant.delegateIsEOA !== "boolean") {
    throw parseError("delegateIsEOA must be Boolean.")
  }
  if (typeof grant.allowReplayable !== "boolean") {
    throw parseError("allowReplayable must be Boolean.")
  }
  assertArray(grant.components, "components", false)
  for (const component of grant.components) parseDelegationComponent(component)
  assertArray(grant.scope, "scope", false)
  assertBytes32(grant.parent, "parent")
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
  if (values.length > MAX_ARRAY_ENTRIES) {
    throw tooLarge(`${name} has too many entries.`)
  }
  for (const value of values) assertString(value, name)
}

function assertString(value: string, name: string): void {
  if (typeof value !== "string") throw parseError(`${name} must be a String.`)
  if (encoder.encode(value).length > MAX_STRING_BYTES) {
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

function safeInteger(value: bigint | number, name: string): number {
  const converted = Number(value)
  assertInteger(converted, name, 0, Number.MAX_SAFE_INTEGER)
  return converted
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
