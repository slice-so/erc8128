import { describe, expect, test } from "bun:test"
import type { ComponentIdentifier, RoutePolicy } from "../types"
import { resolvePosture } from "./resolvePosture"

const structuredComponent: ComponentIdentifier = {
  name: "x-dictionary",
  params: { key: "tenant", sf: true }
}

const serverConfig = (
  classBoundPolicies: RoutePolicy["classBoundPolicies"]
) => ({
  max_validity_sec: 60,
  route_policies: {
    "/resource": { classBoundPolicies }
  }
})

describe("resolvePosture structural component policies", () => {
  test("treats a flat object-form component list as one policy", () => {
    const result = resolvePosture(
      "GET",
      "/resource",
      serverConfig([structuredComponent]),
      {
        binding: "class-bound",
        components: [structuredComponent]
      },
      "non-replayable"
    )

    expect(result).toEqual({
      binding: "class-bound",
      components: [structuredComponent],
      replay: "non-replayable",
      contentDigest: undefined,
      ttlSeconds: 60
    })
  })

  test("selects from nested policies using structural parameters", () => {
    const result = resolvePosture(
      "GET",
      "/resource",
      serverConfig([
        [{ name: "x-dictionary", params: { sf: true } }, "x-extra"],
        [structuredComponent]
      ]),
      {
        binding: "class-bound",
        components: [structuredComponent]
      },
      "non-replayable"
    )

    expect(result.components).toEqual([structuredComponent])
  })

  test("includes unconditional route components in class-bound posture", () => {
    const result = resolvePosture(
      "GET",
      "/resource",
      {
        max_validity_sec: 60,
        route_policies: {
          "/resource": {
            classBoundPolicies: ["@authority"],
            additionalRequestBoundComponents: ["x-tenant"]
          }
        }
      },
      { binding: "class-bound" },
      "non-replayable"
    )

    expect(result.components).toEqual([
      { name: "@authority" },
      { name: "x-tenant" }
    ])
  })
})
