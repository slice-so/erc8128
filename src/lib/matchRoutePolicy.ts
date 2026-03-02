import type { ServerConfig } from "./types"

type RoutePolicy = NonNullable<ServerConfig["route_policies"]>[string]

/**
 * Match a request's method + pathname against the server's route_policies.
 *
 * Resolution order:
 * 1. Exact match: `"METHOD /path"`
 * 2. Wildcard method: `"* /path"`
 * 3. `undefined` (no match — caller falls back to server-level defaults)
 */
export function matchRoutePolicy(
  method: string,
  pathname: string,
  policies: Record<string, RoutePolicy> | undefined
): RoutePolicy | undefined {
  if (!policies) return undefined
  return (
    policies[`${method.toUpperCase()} ${pathname}`] ??
    policies[`* ${pathname}`] ??
    undefined
  )
}
