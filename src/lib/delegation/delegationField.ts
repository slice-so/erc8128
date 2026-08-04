import type {
  AccountIdentity,
  ComponentIdentifier,
  DelegationGrantBuildArgs,
  ParsedDelegationField,
  SfDictionary,
  SfItem,
  SfMember
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import {
  normalizeComponentIdentifier,
  serializeComponentIdentifier
} from "../engine/componentIdentifier"
import {
  canonicalizeSfDictionary,
  parseSfDictionary,
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
export const TAG_DELEGATION = "erc8128-delegation"

const BASE_MEMBERS = new Set([
  "root",
  "delegate",
  "aud",
  "id",
  "epoch",
  "max-age",
  "allow-replayable",
  "components",
  "scope"
])
const MAX_AUDIENCES = 16
const MAX_COMPONENTS = 16
const MAX_SCOPES = 16
const MAX_SCOPE_LENGTH = 64
const MAX_FIELD_BYTES = 16_384
const encoder = new TextEncoder()

export function formatDelegationField(args: DelegationGrantBuildArgs): string {
  const root = formatIdentity(args.root)
  const delegate = formatIdentity(args.delegate)
  const audiences = Array.from(
    new Set(args.audiences.map(normalizeAudienceOrigin))
  ).sort()
  if (audiences.length === 0 || audiences.length > MAX_AUDIENCES) {
    throw invalid("Delegation must have 1-16 exact audiences.")
  }
  const idBytes = args.id instanceof Uint8Array ? args.id : hexToBytes(args.id)
  if (idBytes.length !== 32) throw invalid("Delegation id must be 32 bytes.")
  if (!Number.isSafeInteger(args.epoch) || args.epoch < 0) {
    throw invalid("Delegation epoch must be a non-negative integer.")
  }
  if (
    args.maxAge !== undefined &&
    (!Number.isSafeInteger(args.maxAge) || args.maxAge <= 0)
  ) {
    throw invalid("Delegation max-age must be a positive integer.")
  }

  const scopes = normalizeScopes(args.scopes ?? [])

  const members: SfDictionary = {
    root: { value: root },
    delegate: {
      value: delegate,
      ...(args.delegateKeyType === undefined
        ? {}
        : { params: { "key-type": args.delegateKeyType } })
    },
    aud: { items: audiences.map((audience) => ({ value: audience })) },
    id: { value: sfBinary(idBytes) },
    epoch: { value: args.epoch },
    ...(args.maxAge === undefined ? {} : { "max-age": { value: args.maxAge } }),
    ...(args.allowReplayable === true
      ? { "allow-replayable": { value: true } }
      : {}),
    ...(args.components === undefined || args.components.length === 0
      ? {}
      : {
          components: {
            items: args.components.map((component) => {
              const normalized = normalizeComponentIdentifier(component)
              return { value: normalized.name, params: normalized.params }
            })
          }
        }),
    ...(scopes.length === 0
      ? {}
      : { scope: { items: scopes.map((scope) => ({ value: scope })) } })
  }
  const fieldValue = serializeSfDictionary(members)
  if (encoder.encode(fieldValue).length > MAX_FIELD_BYTES) {
    throw invalid("Delegation field exceeds the supported size.")
  }
  try {
    return parseDelegationField(fieldValue).fieldValue
  } catch (error) {
    if (error instanceof Erc8128Error) {
      throw invalid(error.message)
    }
    throw error
  }
}

export function parseDelegationField(
  fieldValue: string
): ParsedDelegationField {
  if (encoder.encode(fieldValue).length > MAX_FIELD_BYTES) {
    throw new Erc8128Error(
      "DELEGATION_TOO_LARGE",
      "Delegation field is too large."
    )
  }
  const members = parseSfDictionary(fieldValue)
  for (const name of Object.keys(members)) {
    if (!BASE_MEMBERS.has(name)) {
      throw parseError(`Unsupported delegation member: ${name}.`)
    }
  }
  const rootValue = requireStringItem(members.root, "root")
  const delegateMember = requireItem(members.delegate, "delegate")
  if (typeof delegateMember.value !== "string") {
    throw parseError("delegate must be a string.")
  }
  const root = parseCanonicalIdentity(rootValue, "root")
  const delegate = parseCanonicalIdentity(delegateMember.value, "delegate")
  const delegateParams = delegateMember.params ?? {}
  for (const key of Object.keys(delegateParams)) {
    if (key !== "key-type")
      throw parseError(`Unsupported delegate parameter: ${key}.`)
  }
  const keyType = delegateParams["key-type"]
  if (keyType !== undefined && keyType !== "eoa") {
    throw parseError("Unsupported delegate key-type.")
  }

  const audiences = requireStringList(members.aud, "aud").map((audience) => {
    const normalized = normalizeAudienceOrigin(audience)
    if (normalized !== audience) throw parseError("Audience is not canonical.")
    return normalized
  })
  if (
    audiences.length === 0 ||
    audiences.length > MAX_AUDIENCES ||
    new Set(audiences).size !== audiences.length
  ) {
    throw parseError(
      "Delegation audiences are empty, duplicated, or too numerous."
    )
  }

  const idMember = requireItem(members.id, "id")
  if (
    typeof idMember.value !== "object" ||
    idMember.value.type !== "binary" ||
    idMember.value.value.length !== 32 ||
    Object.keys(idMember.params ?? {}).length !== 0
  ) {
    throw parseError("Delegation id must be exactly 32 bytes.")
  }

  const maxAge = optionalPositiveInteger(members["max-age"], "max-age")
  const epoch = requireNonNegativeInteger(members.epoch, "epoch")
  const allowReplayable =
    optionalBoolean(members["allow-replayable"], "allow-replayable") ?? false
  if (members["allow-replayable"] !== undefined && !allowReplayable) {
    throw parseError("allow-replayable may only be present with ?1.")
  }
  const components = optionalComponentList(members.components)
  const scopes = members.scope
    ? normalizeScopes(requireStringList(members.scope, "scope"), parseError)
    : []

  return {
    fieldValue: canonicalizeSfDictionary(fieldValue),
    root,
    delegate,
    ...(keyType === "eoa" ? { delegateKeyType: "eoa" as const } : {}),
    audiences,
    id: bytesToHex(idMember.value.value),
    epoch,
    ...(maxAge === undefined ? {} : { maxAge }),
    allowReplayable,
    components,
    scopes,
    members
  }
}

export function normalizeAudienceOrigin(input: string): string {
  if (
    input.includes("*") ||
    /:\/\/[^/]*@/.test(input) ||
    /:\/\/[^/?#]*\.(?::\d+)?(?:[/?#]|$)/.test(input)
  ) {
    throw invalid(
      "Audience must be an exact origin without credentials or a trailing dot."
    )
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
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw invalid("Audience must use HTTPS except for loopback development.")
  }
  return url.origin.toLowerCase()
}

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
      { name: "currentEpoch", type: "uint256" }
    ]
  }
] as const

function formatIdentity(identity: AccountIdentity): string {
  return formatKeyId(identity.chainId, identity.address)
}

function parseCanonicalIdentity(value: string, name: string): AccountIdentity {
  const identity = parseKeyId(value)
  if (identity === null || formatIdentity(identity) !== value) {
    throw parseError(`${name} must be a canonical CAIP-10 identity.`)
  }
  return identity
}

function requireItem(member: SfMember | undefined, name: string): SfItem {
  if (member === undefined || !("value" in member)) {
    throw parseError(`${name} must be an Item.`)
  }
  return member
}

function requireStringItem(member: SfMember | undefined, name: string): string {
  const item = requireItem(member, name)
  if (typeof item.value !== "string" || Object.keys(item.params ?? {}).length) {
    throw parseError(`${name} must be a bare string Item.`)
  }
  return item.value
}

function requireStringList(
  member: SfMember | undefined,
  name: string
): string[] {
  if (member === undefined || !("items" in member)) {
    throw parseError(`${name} must be an Inner List.`)
  }
  if (Object.keys(member.params ?? {}).length) {
    throw parseError(`${name} must not have parameters.`)
  }
  return member.items.map((item) => {
    if (
      typeof item.value !== "string" ||
      Object.keys(item.params ?? {}).length
    ) {
      throw parseError(`${name} items must be bare strings.`)
    }
    return item.value
  })
}

function optionalPositiveInteger(
  member: SfMember | undefined,
  name: string
): number | undefined {
  if (member === undefined) return undefined
  const item = requireItem(member, name)
  if (
    !Number.isSafeInteger(item.value) ||
    (item.value as number) <= 0 ||
    Object.keys(item.params ?? {}).length
  ) {
    throw parseError(`${name} must be a positive integer.`)
  }
  return item.value as number
}

function requireNonNegativeInteger(
  member: SfMember | undefined,
  name: string
): number {
  const item = requireItem(member, name)
  if (
    !Number.isSafeInteger(item.value) ||
    (item.value as number) < 0 ||
    Object.keys(item.params ?? {}).length
  ) {
    throw parseError(`${name} must be a non-negative integer.`)
  }
  return item.value as number
}

function optionalBoolean(
  member: SfMember | undefined,
  name: string
): boolean | undefined {
  if (member === undefined) return undefined
  const item = requireItem(member, name)
  if (
    typeof item.value !== "boolean" ||
    Object.keys(item.params ?? {}).length
  ) {
    throw parseError(`${name} must be a Boolean.`)
  }
  return item.value
}

function optionalComponentList(
  member: SfMember | undefined
): ComponentIdentifier[] {
  if (member === undefined) return []
  if (!("items" in member) || Object.keys(member.params ?? {}).length) {
    throw parseError("components must be an Inner List.")
  }
  const components = member.items.map((item) => {
    if (typeof item.value !== "string") {
      throw parseError("components entries must be strings.")
    }
    const component = normalizeComponentIdentifier({
      name: item.value,
      ...(Object.keys(item.params ?? {}).length
        ? { params: item.params as NonNullable<ComponentIdentifier["params"]> }
        : {})
    })
    if (
      [
        "@scheme",
        "@authority",
        "@method",
        "@path",
        "@query",
        "@signature-params",
        "content-digest",
        "content-type",
        DELEGATION_FIELD_NAME
      ].includes(component.name)
    ) {
      throw parseError("components must not restate the delegated baseline.")
    }
    return component
  })
  if (components.length > MAX_COMPONENTS) {
    throw new Erc8128Error(
      "DELEGATION_TOO_LARGE",
      "Delegation has too many component requirements."
    )
  }
  if (
    new Set(components.map(serializeComponentIdentifier)).size !==
    components.length
  ) {
    throw parseError("components entries must be unique.")
  }
  return components
}

function normalizeScopes(
  values: readonly string[],
  error: (message: string) => Error = invalid
): string[] {
  const scopes = [...values]
  if (
    scopes.length > MAX_SCOPES ||
    scopes.some(
      (scope) =>
        scope.length === 0 ||
        scope.length > MAX_SCOPE_LENGTH ||
        !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope)
    ) ||
    new Set(scopes).size !== scopes.length
  ) {
    throw error("scope entries must be unique visible ASCII strings.")
  }
  const sorted = [...scopes].sort()
  if (
    error === parseError &&
    sorted.some((scope, index) => scope !== scopes[index])
  ) {
    throw error("scope entries must be sorted.")
  }
  return sorted
}

function isLoopback(hostname: string): boolean {
  const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase()
  if (normalized === "localhost" || normalized === "::1") return true
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(normalized)
  return match !== null && Number(match[1]) === 127
}

function invalid(message: string): Erc8128Error {
  return new Erc8128Error("INVALID_OPTIONS", message)
}

function parseError(message: string): Erc8128Error {
  return new Erc8128Error("PARSE_ERROR", message)
}
