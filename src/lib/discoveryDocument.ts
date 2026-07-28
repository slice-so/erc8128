import type {
  DiscoveryDocument,
  DiscoveryDocumentConfig,
  RoutePolicy,
  RoutePolicyConfig
} from "../types"
import { isContentDigestMode, isCoveredComponent } from "./policyValues"
import { DEFAULT_MAX_VALIDITY_SEC } from "./verifyUtils"

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

const isStringArray = (value: JsonValue | undefined): value is string[] =>
  Array.isArray(value) && value.every((entry) => typeof entry === "string")

const isComponentArray = (value: JsonValue | undefined): value is string[] =>
  isStringArray(value) && value.every(isCoveredComponent)

const isClassBoundPolicies = (
  value: JsonValue | undefined
): value is string[] | string[][] =>
  isComponentArray(value) ||
  (Array.isArray(value) && value.every(isComponentArray))

const isRoutePolicy = (value: JsonValue): value is RoutePolicy => {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      "additionalRequestBoundComponents",
      "classBoundPolicies",
      "contentDigest",
      "methods",
      "replayable"
    ])
  ) {
    return false
  }
  return (
    (value.methods === undefined || isStringArray(value.methods)) &&
    (value.replayable === undefined || typeof value.replayable === "boolean") &&
    (value.additionalRequestBoundComponents === undefined ||
      isComponentArray(value.additionalRequestBoundComponents)) &&
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
  (Array.isArray(value) && value.length > 0 && value.every(isRoutePolicy))

const isRoutePolicyConfig = (value: JsonValue): value is RoutePolicyConfig =>
  isRecord(value) && Object.values(value).every(isRoutePolicyCandidate)

const isSecureEndpoint = (value: string | undefined) => {
  if (value === undefined) return false
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
      (candidate) => candidate !== false && hasReplayableRoutePolicy(candidate)
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
            entry[1] !== false
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
    Object.values(document.route_policies).some(hasReplayableRoutePolicy)
  return replayable && document.invalidation_endpoint === undefined
    ? null
    : document
}
