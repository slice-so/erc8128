import type { RoutePolicy, RoutePolicyConfig } from "./policy"

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
