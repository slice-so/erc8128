import type { RoutePolicy, RoutePolicyConfig } from "./types"
import { DEFAULT_MAX_VALIDITY_SEC } from "./verifyUtils"

export type DiscoveryDocumentConfig = {
  verificationEndpoint?: string
  invalidationEndpoint?: string
  maxValiditySec?: number
  routePolicy?: Record<string, RoutePolicy | RoutePolicy[] | false> & {
    default?: RoutePolicy
  }
}

export type DiscoveryDocument = {
  max_validity_sec: number
  verification_endpoint?: string
  invalidation_endpoint?: string
  route_policies?: RoutePolicyConfig
}

export function formatDiscoveryDocument(
  config: DiscoveryDocumentConfig
): DiscoveryDocument {
  const replayableEnabled =
    config.routePolicy != null &&
    Object.values(config.routePolicy).some(
      (candidate) => candidate !== false && hasReplayableRoutePolicy(candidate)
    )

  const routePolicies = config.routePolicy
    ? (Object.fromEntries(
        Object.entries(config.routePolicy).filter(
          (entry): entry is [string, RoutePolicy | RoutePolicy[]] =>
            entry[1] !== false
        )
      ) as RoutePolicyConfig)
    : undefined

  return {
    ...(config.verificationEndpoint
      ? { verification_endpoint: config.verificationEndpoint }
      : {}),
    ...(replayableEnabled
      ? { invalidation_endpoint: config.invalidationEndpoint }
      : {}),
    max_validity_sec: config.maxValiditySec ?? DEFAULT_MAX_VALIDITY_SEC,
    ...(routePolicies && Object.keys(routePolicies).length > 0
      ? { route_policies: routePolicies }
      : {})
  }
}

function hasReplayableRoutePolicy(
  candidate: RoutePolicy | RoutePolicy[]
): boolean {
  const policies = Array.isArray(candidate) ? candidate : [candidate]
  return policies.some((policy) => policy.replayable === true)
}
