import type { ComponentIdentifier, RoutePolicy } from "../../types"
import { normalizeComponentsList } from "./normalizePolicies"
import { requiredCoveredHeadersForRequest } from "./requiredCoveredHeaders"

export function routeRequiredComponentsForRequest(
  request: Request,
  routePolicy: RoutePolicy | null | undefined
): ComponentIdentifier[] {
  return normalizeComponentsList([
    ...requiredCoveredHeadersForRequest(
      request,
      routePolicy?.requiredCoveredHeadersWhenPresent
    ),
    ...(routePolicy?.contentDigest === "require"
      ? (["content-digest"] as const)
      : [])
  ])
}
