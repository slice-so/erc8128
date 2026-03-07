import type { RoutePolicy, RoutePolicyConfig } from "./types"

/**
 * Match a request's method + pathname against path-keyed route policies.
 *
 * Resolution order:
 * 1. Exact path match: `"/path"`
 * 2. Glob path match: `"/prefix/*"` — longest prefix wins
 * 3. Default key: `"default"` — catch-all fallback
 * 4. `undefined` (no match)
 *
 * For a matched path entry, method-specific policies are preferred over
 * methodless policies. Method names are compared case-insensitively.
 * If a path matches but none of that path's method-specific entries match and
 * there is no methodless fallback on that same path, lower-precedence routes
 * and `default` are not consulted.
 */
export function matchRoutePolicy(
  method: string,
  pathname: string,
  policies: RoutePolicyConfig | undefined
): RoutePolicy | undefined {
  if (!policies) return undefined

  const upperMethod = method.toUpperCase()

  // 1. Exact path match
  if (pathname in policies) {
    return selectRoutePolicy(upperMethod, policies[pathname])
  }

  // 2. Glob: keys ending with "/*" — longest matching prefix wins
  let best:
    | {
        candidate: RoutePolicy | RoutePolicy[]
        prefixLen: number
      }
    | undefined

  for (const [key, candidate] of Object.entries(policies)) {
    if (key === "default" || !key.endsWith("/*")) continue

    const prefix = key.slice(0, -1) // "/prefix/*" -> "/prefix/"
    if (!pathname.startsWith(prefix)) continue

    if (!best || prefix.length > best.prefixLen) {
      best = {
        candidate,
        prefixLen: prefix.length
      }
    }
  }

  if (best) {
    return selectRoutePolicy(upperMethod, best.candidate)
  }

  // 3. Default fallback
  return selectRoutePolicy(upperMethod, policies.default)
}

function selectRoutePolicy(
  method: string,
  candidate: RoutePolicy | RoutePolicy[] | undefined
): RoutePolicy | undefined {
  if (!candidate) return undefined

  const policies = Array.isArray(candidate) ? candidate : [candidate]
  let fallback: RoutePolicy | undefined

  for (const policy of policies) {
    const methods = policy.methods
    if (!methods || methods.length === 0) {
      fallback ??= policy
      continue
    }

    if (methods.some((entry) => entry.toUpperCase() === method)) {
      return policy
    }
  }

  return fallback
}
