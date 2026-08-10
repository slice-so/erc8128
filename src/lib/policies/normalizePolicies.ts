import type { ComponentIdentifier, CoveredComponent } from "../../types"
import {
  componentIdentifierEquals,
  normalizeComponentIdentifier
} from "../engine/componentIdentifier"

export type ClassBoundPolicy = ComponentIdentifier[]

export function normalizeComponentsList(
  components?: readonly CoveredComponent[]
): ComponentIdentifier[] {
  if (!components) return []
  const result: ComponentIdentifier[] = []
  for (const component of components) {
    const normalized = normalizeComponentIdentifier(component)
    if (
      !result.some((candidate) =>
        componentIdentifierEquals(candidate, normalized)
      )
    ) {
      result.push(normalized)
    }
  }
  return result
}

export function normalizeClassBoundPolicies(
  policies?: CoveredComponent[] | CoveredComponent[][]
): ClassBoundPolicy[] {
  if (policies === undefined) return []
  if (policies.length === 0) return []
  if (Array.isArray(policies[0])) {
    return (policies as CoveredComponent[][]).map((policy) =>
      normalizeComponentsList(policy)
    )
  }
  return [normalizeComponentsList(policies as CoveredComponent[])]
}

export function ensureAuthority(policy: ClassBoundPolicy): ClassBoundPolicy {
  if (policy.some((component) => component.name === "@authority")) return policy
  return [{ name: "@authority" }, ...policy]
}
