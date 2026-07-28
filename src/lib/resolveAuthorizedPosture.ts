import type {
  ContentDigestMode,
  ResolveAuthorizedPostureParameters,
  ResolvedAuthorizedPosture
} from "../types"

const positiveInteger = (value: number | undefined) =>
  value !== undefined && Number.isSafeInteger(value) && value > 0
    ? value
    : undefined

const unionComponents = (
  ...groups: readonly (readonly string[] | undefined)[]
) => {
  const components: string[] = []
  const seen = new Set<string>()
  for (const group of groups) {
    for (const component of group ?? []) {
      const normalized = component.trim().toLowerCase()
      if (!normalized || seen.has(normalized)) continue
      seen.add(normalized)
      components.push(normalized)
    }
  }
  return components
}

const selectClassBoundPolicy = (
  minimum: readonly string[],
  policies: string[] | string[][] | undefined
) => {
  if (policies === undefined) return undefined
  if (policies.length === 0) return []
  const candidates =
    typeof policies[0] === "string"
      ? [policies as string[]]
      : (policies as string[][])
  const minimumSet = new Set(minimum)
  return candidates.reduce((best, candidate) => {
    const candidateExtra = candidate.filter(
      (component) => !minimumSet.has(component)
    ).length
    const bestExtra = best.filter(
      (component) => !minimumSet.has(component)
    ).length
    return candidateExtra < bestExtra ? candidate : best
  })
}

const resolveContentDigest = (
  requested: ContentDigestMode | undefined,
  required: ContentDigestMode | undefined
): ContentDigestMode => {
  if (required === undefined || required === "off") {
    return requested ?? required ?? "auto"
  }
  if (requested === undefined || requested === "off") return required
  return requested
}

/**
 * Resolve the intersection of immutable authorization constraints, one
 * request's tightening options, and a destination route policy.
 */
export const resolveAuthorizedPosture = ({
  authorizationPolicy,
  invalidationAvailable = false,
  remainingAuthorizationSeconds,
  requestOptions = {},
  routeMaxValiditySeconds,
  routePolicy
}: ResolveAuthorizedPostureParameters): ResolvedAuthorizedPosture => {
  if (
    remainingAuthorizationSeconds !== undefined &&
    remainingAuthorizationSeconds <= 0
  ) {
    throw new Error("The authorization has expired.")
  }
  const requestWantsReplayable = requestOptions.replay === "replayable"
  const requestRequiresNonReplayable =
    requestOptions.replay === "non-replayable"
  const replayable =
    authorizationPolicy.preferReplayable &&
    !requestRequiresNonReplayable &&
    (requestWantsReplayable || requestOptions.replay === undefined) &&
    routePolicy?.replayable === true &&
    invalidationAvailable

  const authorizationAllowsClassBound =
    authorizationPolicy.binding === "class-bound"
  const requestAllowsClassBound =
    requestOptions.binding === undefined ||
    requestOptions.binding === "class-bound"
  const classBoundPolicy =
    authorizationAllowsClassBound && requestAllowsClassBound
      ? selectClassBoundPolicy(
          authorizationPolicy.components,
          routePolicy?.classBoundPolicies
        )
      : undefined
  const binding =
    classBoundPolicy === undefined ? "request-bound" : "class-bound"

  const components =
    binding === "class-bound"
      ? unionComponents(
          ["@authority"],
          classBoundPolicy,
          authorizationPolicy.components,
          requestOptions.components
        )
      : unionComponents(
          authorizationPolicy.components,
          requestOptions.components,
          routePolicy?.additionalRequestBoundComponents
        )

  const validityCaps = [
    positiveInteger(authorizationPolicy.ttlSeconds),
    positiveInteger(requestOptions.ttlSeconds),
    positiveInteger(routeMaxValiditySeconds),
    positiveInteger(remainingAuthorizationSeconds)
  ].filter((value): value is number => value !== undefined)
  if (validityCaps.length === 0) {
    throw new Error("Authorized posture requires a positive validity cap.")
  }

  return {
    binding,
    components,
    contentDigest: resolveContentDigest(
      requestOptions.contentDigest,
      routePolicy?.contentDigest
    ),
    replay: replayable ? "replayable" : "non-replayable",
    ttlSeconds: Math.min(...validityCaps)
  }
}
