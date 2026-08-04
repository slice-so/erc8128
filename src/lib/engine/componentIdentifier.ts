import type {
  ComponentIdentifier,
  CoveredComponent,
  SfParameters
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { serializeSfMember } from "./structuredFields"

const parameterNameSet = new Set(["sf", "bs", "tr", "req", "key", "name"])

export function normalizeComponentIdentifier(
  component: CoveredComponent
): ComponentIdentifier {
  const name = (typeof component === "string" ? component : component.name)
    .trim()
    .toLowerCase()
  if (!/^@[a-z][a-z0-9-]*$|^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) {
    throw new Erc8128Error("INVALID_OPTIONS", "Invalid component name.")
  }
  if (typeof component === "string" || component.params === undefined) {
    return { name }
  }
  if (Object.keys(component.params).some((key) => !parameterNameSet.has(key))) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Unsupported component parameter."
    )
  }
  const params: NonNullable<ComponentIdentifier["params"]> = {}
  for (const [parameter, value] of Object.entries(component.params)) {
    if (
      (parameter === "key" || parameter === "name") &&
      typeof value !== "string"
    ) {
      throw new Erc8128Error(
        "INVALID_OPTIONS",
        `Invalid ${parameter} component parameter.`
      )
    }
    if (parameter !== "key" && parameter !== "name" && value !== true) {
      throw new Erc8128Error(
        "INVALID_OPTIONS",
        `Invalid ${parameter} component parameter.`
      )
    }
    Object.assign(params, { [parameter]: value })
  }
  return Object.keys(params).length === 0 ? { name } : { name, params }
}

export function normalizeComponentIdentifiers(
  components: readonly CoveredComponent[]
): ComponentIdentifier[] {
  return components.map(normalizeComponentIdentifier)
}

export function serializeComponentIdentifier(
  component: ComponentIdentifier
): string {
  const normalized = normalizeComponentIdentifier(component)
  const params: SfParameters = {}
  for (const [parameter, value] of Object.entries(normalized.params ?? {})) {
    params[parameter] = value
  }
  return serializeSfMember({ value: normalized.name, params })
}

export function componentIdentifierEquals(
  left: CoveredComponent,
  right: CoveredComponent
): boolean {
  const normalizedLeft = normalizeComponentIdentifier(left)
  const normalizedRight = normalizeComponentIdentifier(right)
  if (normalizedLeft.name !== normalizedRight.name) return false
  const leftParams = normalizedLeft.params ?? {}
  const rightParams = normalizedRight.params ?? {}
  const keys = new Set([
    ...Object.keys(leftParams),
    ...Object.keys(rightParams)
  ])
  return [...keys].every(
    (key) =>
      leftParams[key as keyof typeof leftParams] ===
      rightParams[key as keyof typeof rightParams]
  )
}

export function includesComponent(
  components: readonly ComponentIdentifier[],
  required: CoveredComponent
): boolean {
  return components.some((component) =>
    componentIdentifierEquals(component, required)
  )
}

export function componentName(component: CoveredComponent): string {
  return normalizeComponentIdentifier(component).name
}
