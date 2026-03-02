import { describe, expect, test } from "bun:test"
import { matchRoutePolicy } from "./matchRoutePolicy"

describe("matchRoutePolicy", () => {
  const policies = {
    "POST /api/auth/session": {
      replayable: true,
      classBoundPolicies: ["@authority"]
    },
    "GET /api/auth/session": { replayable: true },
    "* /api/public": { replayable: false },
    "DELETE /api/admin": { replayable: false }
  }

  test("exact match: METHOD + pathname", () => {
    expect(matchRoutePolicy("POST", "/api/auth/session", policies)).toEqual({
      replayable: true,
      classBoundPolicies: ["@authority"]
    })
  })

  test("exact match is case-insensitive for method", () => {
    expect(matchRoutePolicy("post", "/api/auth/session", policies)).toEqual({
      replayable: true,
      classBoundPolicies: ["@authority"]
    })
  })

  test("different method on same path returns that method's policy", () => {
    expect(matchRoutePolicy("GET", "/api/auth/session", policies)).toEqual({
      replayable: true
    })
  })

  test("wildcard match when no exact method match", () => {
    expect(matchRoutePolicy("GET", "/api/public", policies)).toEqual({
      replayable: false
    })
  })

  test("exact match takes priority over wildcard", () => {
    // Add a wildcard for a path that also has an exact match
    const withBoth = {
      ...policies,
      "* /api/auth/session": { replayable: false }
    }
    expect(matchRoutePolicy("POST", "/api/auth/session", withBoth)).toEqual({
      replayable: true,
      classBoundPolicies: ["@authority"]
    })
  })

  test("returns undefined when no match found", () => {
    expect(matchRoutePolicy("GET", "/unknown", policies)).toBeUndefined()
  })

  test("returns undefined when policies is undefined", () => {
    expect(matchRoutePolicy("GET", "/anything", undefined)).toBeUndefined()
  })

  test("returns undefined for empty policies", () => {
    expect(matchRoutePolicy("GET", "/anything", {})).toBeUndefined()
  })
})
