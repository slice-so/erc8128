import type { ComponentIdentifier, CoveredComponent } from "../../types"
import {
  includesComponent,
  normalizeComponentIdentifiers
} from "../engine/componentIdentifier"

export function isRequestBoundForThisRequest(
  components: ComponentIdentifier[],
  reqShape: { hasQuery: boolean; hasBody: boolean; hasContentType?: boolean },
  extraComponents?: CoveredComponent[]
): boolean {
  const needed = requiredRequestBoundComponents(reqShape, extraComponents)
  return includesAllComponents(needed, components)
}

export function requiredRequestBoundComponents(
  reqShape: { hasQuery: boolean; hasBody: boolean; hasContentType?: boolean },
  extraComponents?: CoveredComponent[]
): ComponentIdentifier[] {
  const needed = normalizeComponentIdentifiers([
    "@scheme",
    "@authority",
    "@method",
    "@path",
    "@query"
  ])
  // If body present, must include content-digest
  if (reqShape.hasBody) needed.push({ name: "content-digest" })
  if (reqShape.hasContentType) needed.push({ name: "content-type" })

  if (extraComponents) {
    for (const raw of extraComponents) {
      const component = normalizeComponentIdentifiers([raw])[0]
      if (
        component &&
        !needed.some((candidate) => includesComponent([candidate], component))
      ) {
        needed.push(component)
      }
    }
  }

  return needed
}

export function includesAllComponents(
  required: CoveredComponent[],
  components: ComponentIdentifier[]
): boolean {
  for (const req of required) {
    if (!includesComponent(components, req)) return false
  }
  return true
}
