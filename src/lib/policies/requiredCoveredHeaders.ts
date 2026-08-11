import type { ComponentIdentifier, CoveredComponent } from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { isHttpFieldName } from "../policyValues"
import { normalizeComponentsList } from "./normalizePolicies"

export function requiredCoveredHeadersForRequest(
  request: Request,
  components: readonly CoveredComponent[] | undefined
): ComponentIdentifier[] {
  const normalized = normalizeComponentsList(components)
  for (const component of normalized) {
    const params = component.params
    if (
      !isHttpFieldName(component.name) ||
      params?.req ||
      params?.tr ||
      params?.name !== undefined ||
      (params?.bs && params?.sf) ||
      (params?.key && !params.sf)
    ) {
      throw new Erc8128Error(
        "INVALID_OPTIONS",
        "requiredCoveredHeadersWhenPresent must contain request-header components."
      )
    }
  }
  return normalized.filter((component) => request.headers.has(component.name))
}
