import type { RoutePolicy } from "./types"
import { DEFAULT_MAX_VALIDITY_SEC } from "./verifyUtils"

export type DiscoveryDocumentConfig = {
  verificationEndpoint?: string
  invalidationEndpoint?: string
  maxValiditySec?: number
  routePolicy?: Record<string, RoutePolicy | false>
}

export type DiscoveryDocument = {
  max_validity_sec: number
  verification_endpoint?: string
  invalidation_endpoint?: string
  route_policies?: Record<string, RoutePolicy>
}

export function formatDiscoveryDocument(
  config: DiscoveryDocumentConfig
): DiscoveryDocument {
  const replayableEnabled =
    config.routePolicy != null &&
    Object.values(config.routePolicy).some(
      (p) => typeof p === "object" && p !== null && p.replayable === true
    )

  const routePolicies = config.routePolicy
    ? (Object.fromEntries(
        Object.entries(config.routePolicy).filter(
          (entry): entry is [string, RoutePolicy] =>
            entry[0] !== "default" && entry[1] !== false
        )
      ) as Record<string, RoutePolicy>)
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
