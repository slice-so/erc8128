import type {
  CoveredComponent,
  ReplayMode,
  ResolvedPosture,
  ServerConfig,
  SignOptions
} from "../types"
import {
  componentIdentifierEquals,
  normalizeComponentIdentifier
} from "./engine/componentIdentifier"
import { matchRoutePolicy } from "./matchRoutePolicy"
import { resolveContentDigestMode } from "./resolveContentDigest"

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
  mergedOptions: SignOptions,
  requestedReplay: ReplayMode
): ResolvedPosture {
  const defaultTtlSeconds = positiveInteger(mergedOptions.ttlSeconds) ?? 60
  const maximumTtlSeconds =
    positiveInteger(serverConfig?.max_validity_sec) ?? Number.POSITIVE_INFINITY
  if (!serverConfig) {
    return {
      binding: mergedOptions.binding,
      replay: requestedReplay,
      components: mergedOptions.components,
      contentDigest: mergedOptions.contentDigest,
      defaultTtlSeconds,
      maximumTtlSeconds
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
    requestedReplay === "replayable" && routePolicy?.replayable !== false

  const useClassBound =
    mergedOptions.binding === "class-bound" &&
    routePolicy != null &&
    routePolicy.classBoundPolicies !== undefined &&
    routePolicy.classBoundPolicies.length > 0

  // Class-bound is independent of replayability — it means only selected components are signed
  if (useClassBound) {
    const merged = mergeComponentGroups(
      mergeComponents(
        mergedOptions.components ?? [],
        routePolicy?.classBoundPolicies
      ),
      routePolicy?.additionalRequestBoundComponents ?? []
    )

    return {
      binding: "class-bound",
      replay: replayable ? "replayable" : "non-replayable",
      components: merged,
      contentDigest: resolveContentDigestMode(
        mergedOptions.contentDigest,
        routePolicy?.contentDigest
      ),
      defaultTtlSeconds,
      maximumTtlSeconds
    }
  }

  // For request-bound, merge additionalRequestBoundComponents from route
  const additionalComponents = routePolicy?.additionalRequestBoundComponents
  const components = additionalComponents
    ? mergeComponentGroups(mergedOptions.components ?? [], additionalComponents)
    : mergedOptions.components

  return {
    binding: "request-bound",
    replay: replayable ? "replayable" : "non-replayable",
    components: components?.length ? components : undefined,
    contentDigest: resolveContentDigestMode(
      mergedOptions.contentDigest,
      routePolicy?.contentDigest
    ),
    defaultTtlSeconds,
    maximumTtlSeconds
  }
}

function positiveInteger(value: number | undefined): number | undefined {
  return Number.isSafeInteger(value) && (value ?? 0) > 0 ? value : undefined
}

/**
 * Merge the client's minimum components with the route's classBoundPolicies.
 *
 * classBoundPolicies can be:
 * - `string[]`: a single policy — merge with client components
 * - `string[][]`: multiple policies — pick the one requiring the fewest
 *   extra components beyond what the client already provides, then merge
 * - `["@authority"]`: explicit minimal class-bound policy
 * - `[]`: class-bound signing is disabled
 * - `undefined`: route does not allow class-bound
 */
function mergeComponents(
  clientComponents: CoveredComponent[],
  classBoundPolicies: CoveredComponent[] | CoveredComponent[][] | undefined
): CoveredComponent[] {
  if (classBoundPolicies === undefined) {
    return clientComponents
  }

  if (classBoundPolicies.length === 0) {
    return clientComponents
  }

  // Normalize to list of policies
  const policies: CoveredComponent[][] = Array.isArray(classBoundPolicies[0])
    ? (classBoundPolicies as CoveredComponent[][])
    : [classBoundPolicies as CoveredComponent[]]

  // Pick the policy requiring the fewest extra components beyond clientComponents
  let bestPolicy = policies[0]
  let bestExtra = Infinity

  for (const policy of policies) {
    const extra = policy.filter(
      (component) =>
        !clientComponents.some((candidate) =>
          componentIdentifierEquals(candidate, component)
        )
    ).length
    if (extra < bestExtra) {
      bestExtra = extra
      bestPolicy = policy
    }
  }

  // Union: best policy + client components
  return mergeComponentGroups(bestPolicy ?? [], clientComponents)
}

function mergeComponentGroups(
  ...groups: readonly CoveredComponent[][]
): CoveredComponent[] {
  const result: CoveredComponent[] = []
  for (const group of groups) {
    for (const component of group) {
      const normalized = normalizeComponentIdentifier(component)
      if (
        !result.some((candidate) =>
          componentIdentifierEquals(candidate, normalized)
        )
      )
        result.push(normalized)
    }
  }
  return result
}
