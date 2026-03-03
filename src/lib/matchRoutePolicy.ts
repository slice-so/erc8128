import type { ServerConfig } from "./types"

type RoutePolicy = NonNullable<ServerConfig["route_policies"]>[string]

/**
 * Match a request's method + pathname against the server's route_policies.
 *
 * Resolution order:
 * 1. Exact match: `"METHOD /path"`
 * 2. Wildcard method + exact path: `"* /path"`
 * 3. Glob match: `"METHOD /prefix/*"` or `"* /prefix/*"` — longest prefix wins,
 *    exact method takes priority over wildcard method at equal prefix length.
 * 4. `undefined` (no match — caller falls back to server-level defaults)
 */
export function matchRoutePolicy(
  method: string,
  pathname: string,
  policies: Record<string, RoutePolicy> | undefined
): RoutePolicy | undefined {
  if (!policies) return undefined

  const upperMethod = method.toUpperCase()

  // 1. Exact: "METHOD /path"
  const exact = policies[`${upperMethod} ${pathname}`]
  if (exact) return exact

  // 2. Wildcard method + exact path: "* /path"
  const wildcardExact = policies[`* ${pathname}`]
  if (wildcardExact) return wildcardExact

  // 3. Glob: keys ending with "/*" — iterate and pick best match
  let best:
    | { policy: RoutePolicy; prefixLen: number; exactMethod: boolean }
    | undefined

  for (const key in policies) {
    if (!key.endsWith("/*")) continue

    const spaceIdx = key.indexOf(" ")
    const keyMethod = key.slice(0, spaceIdx)
    const prefix = key.slice(spaceIdx + 1, -1) // "/prefix/*" → "/prefix/"

    const isExactMethod = keyMethod === upperMethod
    if (!isExactMethod && keyMethod !== "*") continue
    if (!pathname.startsWith(prefix)) continue

    if (
      !best ||
      (isExactMethod && !best.exactMethod) ||
      (isExactMethod === best.exactMethod && prefix.length > best.prefixLen)
    ) {
      best = {
        policy: policies[key],
        prefixLen: prefix.length,
        exactMethod: isExactMethod
      }
    }
  }

  return best?.policy
}
