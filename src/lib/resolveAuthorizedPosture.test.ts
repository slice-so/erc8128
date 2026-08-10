import { describe, expect, test } from "bun:test"
import type { ComponentIdentifier, RoutePolicy } from "../types"
import { resolveAuthorizedPosture } from "./resolveAuthorizedPosture"

const structuredComponent: ComponentIdentifier = {
  name: "x-dictionary",
  params: { key: "tenant", sf: true }
}

const resolve = (routePolicy: RoutePolicy) =>
  resolveAuthorizedPosture({
    authorizationPolicy: {
      binding: "class-bound",
      components: [structuredComponent],
      preferReplayable: false,
      ttlSeconds: 60
    },
    routePolicy
  })

describe("resolveAuthorizedPosture structural component policies", () => {
  test("accepts a flat object-form class-bound policy", () => {
    expect(
      resolve({ classBoundPolicies: [structuredComponent] })
    ).toMatchObject({
      binding: "class-bound",
      components: [{ name: "@authority" }, structuredComponent]
    })
  })

  test("selects the nested policy with the matching sf and key parameters", () => {
    const result = resolve({
      classBoundPolicies: [
        [{ name: "x-dictionary", params: { sf: true } }, "x-extra"],
        [structuredComponent]
      ]
    })

    expect(result.binding).toBe("class-bound")
    expect(result.components).toEqual([
      { name: "@authority" },
      structuredComponent
    ])
  })

  test("includes unconditional route components in class-bound posture", () => {
    const result = resolve({
      classBoundPolicies: [structuredComponent],
      additionalRequestBoundComponents: ["x-tenant"]
    })

    expect(result.components).toEqual([
      { name: "@authority" },
      structuredComponent,
      { name: "x-tenant" }
    ])
  })
})
