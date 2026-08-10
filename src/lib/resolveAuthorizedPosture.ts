import type {
  CoveredComponent,
  ResolveAuthorizedPostureParameters,
  ResolvedAuthorizedPosture
} from "../types"
import {
  componentIdentifierEquals,
  normalizeComponentIdentifier
} from "./engine/componentIdentifier"
import { resolveContentDigestMode } from "./resolveContentDigest"

const positiveInteger = (value: number | undefined) =>
  value !== undefined && Number.isSafeInteger(value) && value > 0
    ? value
    : undefined

const unionComponents = (
  ...groups: readonly (readonly CoveredComponent[] | undefined)[]
) => {
  const components: CoveredComponent[] = []
  for (const group of groups) {
    for (const component of group ?? []) {
      const normalized = normalizeComponentIdentifier(component)
      if (
        components.some((candidate) =>
          componentIdentifierEquals(candidate, normalized)
        )
      )
        continue
      components.push(normalized)
    }
  }
  return components
}

const selectClassBoundPolicy = (
  minimum: readonly CoveredComponent[],
  policies: CoveredComponent[] | CoveredComponent[][] | undefined
) => {
  if (policies === undefined) return undefined
  if (policies.length === 0) return undefined
  const candidates = Array.isArray(policies[0])
    ? (policies as CoveredComponent[][])
    : [policies as CoveredComponent[]]
  return candidates.reduce((best, candidate) => {
    const candidateExtra = candidate.filter(
      (component) =>
        !minimum.some((required) =>
          componentIdentifierEquals(required, component)
        )
    ).length
    const bestExtra = best.filter(
      (component) =>
        !minimum.some((required) =>
          componentIdentifierEquals(required, component)
        )
    ).length
    return candidateExtra < bestExtra ? candidate : best
  })
}

/**
 * Resolve the intersection of immutable authorization constraints, one
 * request's tightening options, and a destination route policy.
 */
export const resolveAuthorizedPosture = ({
  authorizationPolicy,
  invalidationAvailable = false,
  preferReplayable = authorizationPolicy.preferReplayable,
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
  const requestWantsReplayable = requestOptions.nonce === null
  const requestRequiresNonReplayable =
    requestOptions.nonce !== undefined && requestOptions.nonce !== null
  const replayable =
    authorizationPolicy.preferReplayable &&
    !requestRequiresNonReplayable &&
    (requestWantsReplayable || preferReplayable) &&
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
          requestOptions.components,
          routePolicy?.additionalRequestBoundComponents
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
    contentDigest:
      resolveContentDigestMode(
        requestOptions.contentDigest,
        routePolicy?.contentDigest
      ) ?? "auto",
    replay: replayable ? "replayable" : "non-replayable",
    ttlSeconds: Math.min(...validityCaps)
  }
}
