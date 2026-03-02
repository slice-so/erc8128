import { matchRoutePolicy } from "./matchRoutePolicy"
import type { BindingMode, ReplayMode, ServerConfig } from "./types"

export type ResolvedPosture = {
  binding: BindingMode
  replay: ReplayMode
  components: string[] | undefined
}

/**
 * Resolve the signing posture for a given request based on client preferences
 * and the server's per-route policy.
 *
 * @param method        HTTP method (e.g. "GET", "POST")
 * @param pathname      URL pathname (e.g. "/api/auth/session")
 * @param preferReplayable  Client preference for replayable signatures (default false)
 * @param minComponents     Minimum class-bound components the client is willing to sign
 * @param serverConfig      Server configuration from `/.well-known/erc8128`
 *
 * When `serverConfig` is `null`/`undefined`, preferences are used as-is:
 * - `preferReplayable: true` → replayable; with `minComponents` → class-bound
 * - `preferReplayable: false` → non-replayable + request-bound
 *
 * When `serverConfig` is set, the posture is route-aware:
 * - Replayable only if the server's route policy allows it
 * - Class-bound components are the union of `minComponents` + route's `classBoundPolicies`
 */
export function resolvePosture(
  method: string,
  pathname: string,
  preferReplayable: boolean,
  minComponents: string[] | undefined,
  serverConfig: ServerConfig | null | undefined
): ResolvedPosture {
  if (!serverConfig) {
    // Without server config, derive posture from client preferences directly
    if (!preferReplayable) {
      return {
        binding: "request-bound",
        replay: "non-replayable",
        components: undefined
      }
    }
    if (minComponents) {
      return {
        binding: "class-bound",
        replay: "replayable",
        components: minComponents
      }
    }
    return {
      binding: "request-bound",
      replay: "replayable",
      components: undefined
    }
  }

  // Route-aware resolution
  const routePolicy = matchRoutePolicy(
    method,
    pathname,
    serverConfig.route_policies
  )
  const serverAllowsReplay =
    routePolicy?.replayable ?? serverConfig.replay_protection.replayable
  const replayable = preferReplayable && serverAllowsReplay

  // Class-bound when replayable AND client declared minimum components
  const useClassBound = replayable && minComponents !== undefined

  if (useClassBound) {
    const merged = mergeComponents(
      minComponents ?? [],
      routePolicy?.classBoundPolicies
    )
    return { binding: "class-bound", replay: "replayable", components: merged }
  }

  if (replayable) {
    return {
      binding: "request-bound",
      replay: "replayable",
      components: undefined
    }
  }

  // Non-replayable: safest posture (nonce-based)
  return {
    binding: "request-bound",
    replay: "non-replayable",
    components: undefined
  }
}

/**
 * Merge the client's minimum components with the route's classBoundPolicies.
 *
 * classBoundPolicies can be:
 * - `string[]`: a single policy — merge with client components
 * - `string[][]`: multiple policies — merge client components into the first one
 * - `undefined`: use client components as-is
 */
function mergeComponents(
  clientComponents: string[],
  classBoundPolicies: string[] | string[][] | undefined
): string[] {
  if (!classBoundPolicies || classBoundPolicies.length === 0) {
    return clientComponents
  }

  // Normalize to a single flat policy list
  const routeComponents: string[] = Array.isArray(classBoundPolicies[0])
    ? (classBoundPolicies[0] as string[])
    : (classBoundPolicies as string[])

  // Union: route components + any client components not already present
  const set = new Set(routeComponents)
  for (const c of clientComponents) set.add(c)
  return [...set]
}
