import type {
  DiscoveryDocument,
  DiscoveryDocumentConfig,
  RoutePolicy,
  RoutePolicyConfig
} from "../types"
import {
  isContentDigestMode,
  isCoveredComponent,
  isHttpFieldName
} from "./policyValues"
import { DEFAULT_MAX_VALIDITY_SEC } from "./verifyUtils"

const MAX_DISCOVERY_DOCUMENT_BYTES = 65_536
const MAX_ROUTE_POLICIES = 128
const MAX_POLICIES_PER_ROUTE = 16
const MAX_COMPONENTS_PER_POLICY = 32
const MAX_METHODS_PER_POLICY = 16

type JsonValue =
  | boolean
  | null
  | number
  | string
  | JsonValue[]
  | { readonly [key: string]: JsonValue }

const isRecord = (
  value: JsonValue
): value is { readonly [key: string]: JsonValue } =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const hasOnlyKeys = (
  record: { readonly [key: string]: JsonValue },
  keys: readonly string[]
) => Object.keys(record).every((key) => keys.includes(key))

const isStringArray = (
  value: JsonValue | undefined,
  maximum = MAX_COMPONENTS_PER_POLICY
): value is string[] =>
  Array.isArray(value) &&
  value.length <= maximum &&
  value.every((entry) => typeof entry === "string" && entry.length <= 2_048)

const isComponentArray = (value: JsonValue | undefined): value is string[] =>
  isStringArray(value) && value.every(isCoveredComponent)

const isHeaderArray = (value: JsonValue | undefined): value is string[] =>
  isStringArray(value) && value.every(isHttpFieldName)

const isClassBoundPolicies = (
  value: JsonValue | undefined
): value is string[] | string[][] =>
  isComponentArray(value) ||
  (Array.isArray(value) &&
    value.length <= MAX_POLICIES_PER_ROUTE &&
    value.every(isComponentArray))

const isRoutePolicy = (value: JsonValue): value is RoutePolicy => {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      "additionalRequestBoundComponents",
      "classBoundPolicies",
      "contentDigest",
      "methods",
      "replayable",
      "requiredCoveredHeadersWhenPresent"
    ])
  ) {
    return false
  }
  return (
    (value.methods === undefined ||
      isStringArray(value.methods, MAX_METHODS_PER_POLICY)) &&
    (value.replayable === undefined || typeof value.replayable === "boolean") &&
    (value.additionalRequestBoundComponents === undefined ||
      isComponentArray(value.additionalRequestBoundComponents)) &&
    (value.requiredCoveredHeadersWhenPresent === undefined ||
      isHeaderArray(value.requiredCoveredHeadersWhenPresent)) &&
    (value.classBoundPolicies === undefined ||
      isClassBoundPolicies(value.classBoundPolicies)) &&
    (value.contentDigest === undefined ||
      (typeof value.contentDigest === "string" &&
        isContentDigestMode(value.contentDigest)))
  )
}

const isRoutePolicyCandidate = (
  value: JsonValue
): value is RoutePolicy | RoutePolicy[] =>
  isRoutePolicy(value) ||
  (Array.isArray(value) &&
    value.length > 0 &&
    value.length <= MAX_POLICIES_PER_ROUTE &&
    value.every(isRoutePolicy))

type ParsedRoutePolicyConfig = Record<string, RoutePolicy | RoutePolicy[]>

const isRoutePolicyConfig = (
  value: JsonValue
): value is ParsedRoutePolicyConfig =>
  isRecord(value) &&
  Object.keys(value).length <= MAX_ROUTE_POLICIES &&
  Object.entries(value).every(
    ([route, candidate]) =>
      route.length <= 2_048 && isRoutePolicyCandidate(candidate)
  )

const isSecureEndpoint = (value: string | undefined) => {
  if (value === undefined || value.length > 2_048) return false
  try {
    const url = new URL(value)
    const local =
      url.protocol === "http:" &&
      (url.hostname === "localhost" ||
        url.hostname === "127.0.0.1" ||
        url.hostname === "[::1]")
    return (
      url.href === value &&
      (url.protocol === "https:" || local) &&
      url.username === "" &&
      url.password === "" &&
      url.hash === ""
    )
  } catch {
    return false
  }
}

export function formatDiscoveryDocument(
  config: DiscoveryDocumentConfig
): DiscoveryDocument {
  const replayableEnabled =
    config.routePolicy != null &&
    Object.values(config.routePolicy).some(
      (candidate) =>
        candidate !== false &&
        candidate !== undefined &&
        hasReplayableRoutePolicy(candidate)
    )

  if (replayableEnabled && !isSecureEndpoint(config.invalidationEndpoint)) {
    throw new Error(
      "Replayable route policies require a secure invalidation endpoint."
    )
  }

  const routePolicies = config.routePolicy
    ? (Object.fromEntries(
        Object.entries(config.routePolicy).filter(
          (entry): entry is [string, RoutePolicy | RoutePolicy[]] =>
            entry[1] !== false && entry[1] !== undefined
        )
      ) as RoutePolicyConfig)
    : undefined

  const document: DiscoveryDocument = {
    ...(config.verificationEndpoint
      ? { verification_endpoint: config.verificationEndpoint }
      : {}),
    ...(replayableEnabled
      ? { invalidation_endpoint: config.invalidationEndpoint as string }
      : {}),
    max_validity_sec: config.maxValiditySec ?? DEFAULT_MAX_VALIDITY_SEC,
    ...(routePolicies && Object.keys(routePolicies).length > 0
      ? { route_policies: routePolicies }
      : {})
  }
  if (parseDiscoveryDocument(JSON.stringify(document)) === null) {
    throw new Error("ERC-8128 discovery configuration is invalid.")
  }
  return document
}

function hasReplayableRoutePolicy(
  candidate: RoutePolicy | RoutePolicy[]
): boolean {
  const policies = Array.isArray(candidate) ? candidate : [candidate]
  return policies.some((policy) => policy.replayable === true)
}

export const parseDiscoveryDocument = (
  value: string
): DiscoveryDocument | null => {
  if (new TextEncoder().encode(value).length > MAX_DISCOVERY_DOCUMENT_BYTES) {
    return null
  }
  let parsed: JsonValue
  try {
    parsed = JSON.parse(value) as JsonValue
  } catch {
    return null
  }
  if (
    !isRecord(parsed) ||
    !hasOnlyKeys(parsed, [
      "invalidation_endpoint",
      "max_validity_sec",
      "route_policies",
      "verification_endpoint"
    ]) ||
    typeof parsed.max_validity_sec !== "number" ||
    !Number.isSafeInteger(parsed.max_validity_sec) ||
    parsed.max_validity_sec <= 0 ||
    (parsed.verification_endpoint !== undefined &&
      (typeof parsed.verification_endpoint !== "string" ||
        !isSecureEndpoint(parsed.verification_endpoint))) ||
    (parsed.invalidation_endpoint !== undefined &&
      (typeof parsed.invalidation_endpoint !== "string" ||
        !isSecureEndpoint(parsed.invalidation_endpoint))) ||
    (parsed.route_policies !== undefined &&
      !isRoutePolicyConfig(parsed.route_policies))
  ) {
    return null
  }

  const document: DiscoveryDocument = {
    max_validity_sec: parsed.max_validity_sec,
    ...(typeof parsed.verification_endpoint === "string"
      ? { verification_endpoint: parsed.verification_endpoint }
      : {}),
    ...(typeof parsed.invalidation_endpoint === "string"
      ? { invalidation_endpoint: parsed.invalidation_endpoint }
      : {}),
    ...(parsed.route_policies === undefined
      ? {}
      : { route_policies: parsed.route_policies })
  }
  const replayable =
    document.route_policies !== undefined &&
    Object.values(document.route_policies).some(
      (candidate) =>
        candidate !== undefined && hasReplayableRoutePolicy(candidate)
    )
  return replayable && document.invalidation_endpoint === undefined
    ? null
    : document
}
