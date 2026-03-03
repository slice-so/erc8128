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

  // ─── Glob path patterns ─────────────────────────────────────

  describe("glob path patterns", () => {
    const globPolicies = {
      "GET /api/admin/*": { replayable: false },
      "POST /api/admin/users": { replayable: true },
      "GET /api/admin/users/*": {
        replayable: true,
        classBoundPolicies: ["@authority"]
      },
      "* /api/public/*": { replayable: true }
    }

    test("glob matches sub-path", () => {
      expect(matchRoutePolicy("GET", "/api/admin/roles", globPolicies)).toEqual(
        {
          replayable: false
        }
      )
    })

    test("glob matches deeply nested paths", () => {
      expect(
        matchRoutePolicy("GET", "/api/admin/roles/123/edit", globPolicies)
      ).toEqual({
        replayable: false
      })
    })

    test("exact path takes priority over glob", () => {
      expect(
        matchRoutePolicy("POST", "/api/admin/users", globPolicies)
      ).toEqual({
        replayable: true
      })
    })

    test("longer glob prefix wins over shorter", () => {
      expect(
        matchRoutePolicy("GET", "/api/admin/users/123", globPolicies)
      ).toEqual({
        replayable: true,
        classBoundPolicies: ["@authority"]
      })
    })

    test("exact method glob wins over wildcard method glob", () => {
      // "GET /api/admin/*" (exact method) beats "* /api/public/*" for GET
      // but for /api/public/* only wildcard exists, so it should match
      expect(
        matchRoutePolicy("DELETE", "/api/public/data", globPolicies)
      ).toEqual({
        replayable: true
      })
    })

    test("wildcard method glob works for any method", () => {
      expect(
        matchRoutePolicy("PUT", "/api/public/resource", globPolicies)
      ).toEqual({
        replayable: true
      })
    })

    test("glob does not match the prefix itself (no trailing slash)", () => {
      // "/api/admin" does not start with "/api/admin/"
      expect(
        matchRoutePolicy("GET", "/api/admin", globPolicies)
      ).toBeUndefined()
    })

    test("exact method glob preferred over wildcard method glob at same prefix", () => {
      const mixed = {
        "GET /api/data/*": { replayable: true },
        "* /api/data/*": { replayable: false }
      }
      expect(matchRoutePolicy("GET", "/api/data/item", mixed)).toEqual({
        replayable: true
      })
      // Non-GET falls to wildcard
      expect(matchRoutePolicy("POST", "/api/data/item", mixed)).toEqual({
        replayable: false
      })
    })
  })
})
