import { describe, expect, test } from "bun:test"
import type { AuthorizationPolicy } from "../types"
import { resolveAuthorizedPosture } from "./resolveAuthorizedPosture"

const strictPolicy: AuthorizationPolicy = {
  binding: "request-bound",
  components: ["x-session-policy"],
  preferReplayable: false,
  ttlSeconds: 120
}

describe("resolveAuthorizedPosture", () => {
  test("request options cannot enable replayability", () => {
    expect(
      resolveAuthorizedPosture({
        authorizationPolicy: strictPolicy,
        invalidationAvailable: true,
        requestOptions: { replay: "replayable" },
        routePolicy: { replayable: true }
      }).replay
    ).toBe("non-replayable")
  })

  test("request options cannot weaken request binding", () => {
    expect(
      resolveAuthorizedPosture({
        authorizationPolicy: strictPolicy,
        requestOptions: { binding: "class-bound" },
        routePolicy: { classBoundPolicies: [] }
      }).binding
    ).toBe("request-bound")
  })

  test("authorization, request, and route components are unioned", () => {
    expect(
      resolveAuthorizedPosture({
        authorizationPolicy: strictPolicy,
        requestOptions: { components: ["x-request"] },
        routePolicy: {
          additionalRequestBoundComponents: ["x-route", "x-session-policy"]
        }
      }).components
    ).toEqual(["x-session-policy", "x-request", "x-route"])
  })

  test("validity is capped by authorization, route, request, and lifetime", () => {
    expect(
      resolveAuthorizedPosture({
        authorizationPolicy: strictPolicy,
        remainingAuthorizationSeconds: 30,
        requestOptions: { ttlSeconds: 90 },
        routeMaxValiditySeconds: 60
      }).ttlSeconds
    ).toBe(30)
  })

  test("request options cannot disable a route digest requirement", () => {
    expect(
      resolveAuthorizedPosture({
        authorizationPolicy: strictPolicy,
        requestOptions: { contentDigest: "off" },
        routePolicy: { contentDigest: "require" }
      }).contentDigest
    ).toBe("require")
  })

  test("class-bound preference uses the compatible route policy", () => {
    expect(
      resolveAuthorizedPosture({
        authorizationPolicy: {
          ...strictPolicy,
          binding: "class-bound",
          components: ["x-tenant"]
        },
        requestOptions: { components: ["authorization"] },
        routePolicy: {
          classBoundPolicies: [
            ["@authority", "x-region"],
            ["@authority", "x-tenant"]
          ]
        }
      })
    ).toMatchObject({
      binding: "class-bound",
      components: ["@authority", "x-tenant", "authorization"]
    })
  })
})
