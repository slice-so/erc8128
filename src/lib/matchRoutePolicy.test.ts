import { describe, expect, test } from "bun:test"
import { matchRoutePolicy } from "./matchRoutePolicy"
import type { RoutePolicyConfig } from "./types"

describe("matchRoutePolicy", () => {
  const policies: RoutePolicyConfig = {
    "/api/auth/session": [
      {
        methods: ["POST"],
        replayable: true,
        classBoundPolicies: ["@authority"]
      },
      { methods: ["GET"], replayable: true }
    ],
    "/api/public": { replayable: false },
    "/api/admin": { methods: ["DELETE"], replayable: false }
  }

  test("exact path match selects the method-specific policy", () => {
    expect(matchRoutePolicy("POST", "/api/auth/session", policies)).toEqual({
      methods: ["POST"],
      replayable: true,
      classBoundPolicies: ["@authority"]
    })
  })

  test("exact match is case-insensitive for method", () => {
    expect(matchRoutePolicy("post", "/api/auth/session", policies)).toEqual({
      methods: ["POST"],
      replayable: true,
      classBoundPolicies: ["@authority"]
    })
  })

  test("different method on the same path returns that method's policy", () => {
    expect(matchRoutePolicy("GET", "/api/auth/session", policies)).toEqual({
      methods: ["GET"],
      replayable: true
    })
  })

  test("methodless path policy applies to any method", () => {
    expect(matchRoutePolicy("GET", "/api/public", policies)).toEqual({
      replayable: false
    })
  })

  test("method-specific entry beats a methodless fallback on the same path", () => {
    const withBoth = {
      ...policies,
      "/api/profile": [
        { replayable: false },
        { methods: ["POST"], replayable: true }
      ]
    }
    expect(matchRoutePolicy("POST", "/api/profile", withBoth)).toEqual({
      methods: ["POST"],
      replayable: true
    })
    expect(matchRoutePolicy("GET", "/api/profile", withBoth)).toEqual({
      replayable: false
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
    const globPolicies: RoutePolicyConfig = {
      "/api/admin/*": { methods: ["GET"], replayable: false },
      "/api/admin/users": { methods: ["POST"], replayable: true },
      "/api/admin/users/*": {
        methods: ["GET"],
        replayable: true,
        classBoundPolicies: ["@authority"]
      },
      "/api/public/*": { replayable: true }
    }

    test("glob matches sub-path", () => {
      expect(matchRoutePolicy("GET", "/api/admin/roles", globPolicies)).toEqual(
        {
          methods: ["GET"],
          replayable: false
        }
      )
    })

    test("glob matches deeply nested paths", () => {
      expect(
        matchRoutePolicy("GET", "/api/admin/roles/123/edit", globPolicies)
      ).toEqual({
        methods: ["GET"],
        replayable: false
      })
    })

    test("exact path takes priority over glob", () => {
      expect(
        matchRoutePolicy("POST", "/api/admin/users", globPolicies)
      ).toEqual({
        methods: ["POST"],
        replayable: true
      })
    })

    test("longer glob prefix wins over shorter", () => {
      expect(
        matchRoutePolicy("GET", "/api/admin/users/123", globPolicies)
      ).toEqual({
        methods: ["GET"],
        replayable: true,
        classBoundPolicies: ["@authority"]
      })
    })

    test("methodless glob works for any method", () => {
      expect(
        matchRoutePolicy("DELETE", "/api/public/data", globPolicies)
      ).toEqual({
        replayable: true
      })
    })

    test("glob does not match the prefix itself (no trailing slash)", () => {
      expect(
        matchRoutePolicy("GET", "/api/admin", globPolicies)
      ).toBeUndefined()
    })

    test("longer glob prefix wins over shorter", () => {
      const mixed = {
        "/api/data/*": { replayable: false },
        "/api/data/items/*": { replayable: true }
      }
      expect(matchRoutePolicy("GET", "/api/data/item", mixed)).toEqual({
        replayable: false
      })
      expect(matchRoutePolicy("POST", "/api/data/items/1", mixed)).toEqual({
        replayable: true
      })
    })

    test("default policy is used when no exact or glob match is found", () => {
      const withDefault: RoutePolicyConfig = {
        ...globPolicies,
        default: { replayable: false }
      }

      expect(matchRoutePolicy("PATCH", "/unmatched", withDefault)).toEqual({
        replayable: false
      })
    })

    test("default is not used when an exact path exists but its methods do not match", () => {
      const withDefault: RoutePolicyConfig = {
        "/verify": [
          { methods: ["DELETE"], replayable: false },
          { methods: ["POST", "PUT"], classBoundPolicies: [["@authority"]] }
        ],
        default: { replayable: true, classBoundPolicies: [["@authority"]] }
      }

      expect(matchRoutePolicy("GET", "/verify", withDefault)).toBeUndefined()
    })

    test("a more specific glob blocks fallback to a shorter glob when methods do not match", () => {
      const policies: RoutePolicyConfig = {
        "/api/*": { replayable: true },
        "/api/orders/*": { methods: ["POST"], replayable: false }
      }

      expect(matchRoutePolicy("GET", "/api/orders/1", policies)).toBeUndefined()
    })
  })
})
