import { matchRoutePolicy } from "./matchRoutePolicy"
import type {
  BindingMode,
  ReplayMode,
  ServerConfig,
  SignOptions
} from "./types"

export type ResolvedPosture = {
  binding: BindingMode | undefined
  replay: ReplayMode
  components: string[] | undefined
}

/**
 * Resolve the signing posture for a given request based on client preferences
 * and the server's per-route policy.
 *
 * @param method        HTTP method (e.g. "GET", "POST")
 * @param pathname      URL pathname (e.g. "/api/auth/session")
 * @param serverConfig  Server configuration from `/.well-known/erc8128`
 * @param mergedOptions Merged options from the signer client, priority to the per request options
 */
export function resolvePosture(
  method: string,
  pathname: string,
  serverConfig: ServerConfig | null | undefined,
  mergedOptions: SignOptions & { replay: ReplayMode }
): ResolvedPosture {
  if (!serverConfig) {
    return {
      binding: mergedOptions.binding,
      replay: mergedOptions.replay,
      components: mergedOptions.components
    }
  }

  // Route-aware resolution. The matcher already handles path keys,
  // method-specific entries, glob paths, and default fallback.
  const routePolicy = matchRoutePolicy(
    method,
    pathname,
    serverConfig.route_policies
  )

  // Route can restrict replay even if client wants it
  const replayable =
    mergedOptions.replay === "replayable" && routePolicy?.replayable !== false

  const useClassBound =
    mergedOptions.binding === "class-bound" &&
    routePolicy != null &&
    routePolicy.classBoundPolicies !== undefined

  // Class-bound is independent of replayability — it means only selected components are signed
  if (useClassBound) {
    const merged = mergeComponents(
      mergedOptions.components ?? [],
      routePolicy?.classBoundPolicies
    )

    return {
      binding: "class-bound",
      replay: replayable ? "replayable" : "non-replayable",
      components: merged
    }
  }

  // For request-bound, merge additionalRequestBoundComponents from route
  const additionalComponents = routePolicy?.additionalRequestBoundComponents
  const components = additionalComponents
    ? [
        ...new Set([
          ...(mergedOptions.components ?? []),
          ...additionalComponents
        ])
      ]
    : mergedOptions.components

  return {
    binding: "request-bound",
    replay: replayable ? "replayable" : "non-replayable",
    components: components?.length ? components : undefined
  }
}

/**
 * Merge the client's minimum components with the route's classBoundPolicies.
 *
 * classBoundPolicies can be:
 * - `string[]`: a single policy — merge with client components
 * - `string[][]`: multiple policies — pick the one requiring the fewest
 *   extra components beyond what the client already provides, then merge
 * - `["@authority"]`: explicit minimal class-bound policy
 * - `[]`: supported shorthand for `["@authority"]`
 * - `undefined`: route does not allow class-bound
 */
function mergeComponents(
  clientComponents: string[],
  classBoundPolicies: string[] | string[][] | undefined
): string[] {
  if (classBoundPolicies === undefined) {
    return clientComponents
  }

  if (classBoundPolicies.length === 0) {
    return clientComponents
  }

  // Normalize to list of policies
  const policies: string[][] = Array.isArray(classBoundPolicies[0])
    ? (classBoundPolicies as string[][])
    : [classBoundPolicies as string[]]

  // Pick the policy requiring the fewest extra components beyond clientComponents
  const clientSet = new Set(clientComponents)
  let bestPolicy = policies[0]
  let bestExtra = Infinity

  for (const policy of policies) {
    const extra = policy.filter((c) => !clientSet.has(c)).length
    if (extra < bestExtra) {
      bestExtra = extra
      bestPolicy = policy
    }
  }

  // Union: best policy + client components
  const set = new Set(bestPolicy)
  for (const c of clientComponents) set.add(c)
  return [...set]
}
