import type {
  ComponentIdentifier,
  CoveredComponent,
  SfParameters
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { serializeSfMember } from "./structuredFields"

const PARAMETER_NAMES = ["sf", "bs", "tr", "req", "key", "name"] as const
const parameterNameSet = new Set<string>(PARAMETER_NAMES)

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
  for (const parameter of PARAMETER_NAMES) {
    const value = component.params[parameter]
    if (value === undefined) continue
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
  for (const parameter of PARAMETER_NAMES) {
    const value = normalized.params?.[parameter]
    if (value !== undefined) params[parameter] = value
  }
  return serializeSfMember({ value: normalized.name, params })
}

export function componentIdentifierEquals(
  left: CoveredComponent,
  right: CoveredComponent
): boolean {
  return (
    serializeComponentIdentifier(normalizeComponentIdentifier(left)) ===
    serializeComponentIdentifier(normalizeComponentIdentifier(right))
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
