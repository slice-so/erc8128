import { describe, expect, test } from "bun:test"
import { resolvePosture } from "./resolvePosture"
import type { ServerConfig } from "./types"

const baseConfig: ServerConfig = {
  max_validity_sec: 300,
  route_policies: {
    default: { replayable: true }
  }
}

describe("resolvePosture", () => {
  // ─── Without serverConfig ───────────────────────────────────

  describe("without serverConfig", () => {
    test("passes through mergedOptions as-is", () => {
      expect(
        resolvePosture("GET", "/any", null, {
          replay: "non-replayable",
          binding: "request-bound"
        })
      ).toEqual({
        binding: "request-bound",
        replay: "non-replayable",
        components: undefined
      })
    })

    test("passes through replayable + request-bound", () => {
      expect(
        resolvePosture("GET", "/any", null, {
          replay: "replayable"
        })
      ).toEqual({
        binding: undefined,
        replay: "replayable",
        components: undefined
      })
    })

    test("passes through class-bound with components", () => {
      expect(
        resolvePosture("GET", "/any", null, {
          replay: "replayable",
          binding: "class-bound",
          components: ["@authority", "authorization"]
        })
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "authorization"]
      })
    })
  })

  // ─── With serverConfig ──────────────────────────────────────

  describe("with serverConfig (server allows replay via default)", () => {
    test("replayable request stays replayable", () => {
      expect(
        resolvePosture("GET", "/any", baseConfig, {
          replay: "replayable"
        })
      ).toEqual({
        binding: "request-bound",
        replay: "replayable",
        components: undefined
      })
    })

    test("non-replayable request stays non-replayable", () => {
      expect(
        resolvePosture("GET", "/any", baseConfig, {
          replay: "non-replayable"
        })
      ).toEqual({
        binding: "request-bound",
        replay: "non-replayable",
        components: undefined
      })
    })

    test("class-bound + replayable merges with route classBoundPolicies", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/api/session": [
            {
              methods: ["POST"],
              replayable: true,
              classBoundPolicies: ["@authority", "x-session-id"]
            }
          ]
        }
      }
      expect(
        resolvePosture("POST", "/api/session", config, {
          replay: "replayable",
          binding: "class-bound",
          components: ["@authority", "authorization"]
        })
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "x-session-id", "authorization"]
      })
    })
  })

  describe("route-level overrides", () => {
    test("route disables replay even when client wants it", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/api/sensitive": [
            {
              methods: ["POST"],
              replayable: false,
              classBoundPolicies: ["@authority"]
            }
          ]
        }
      }
      // Class-bound is preserved (independent of replay), but replay is denied
      expect(
        resolvePosture("POST", "/api/sensitive", config, {
          replay: "replayable",
          binding: "class-bound",
          components: ["@authority"]
        })
      ).toEqual({
        binding: "class-bound",
        replay: "non-replayable",
        components: ["@authority"]
      })
    })

    test("no classBoundPolicies on route → falls back to request-bound", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/api/sensitive": [{ methods: ["POST"], replayable: false }]
        }
      }
      expect(
        resolvePosture("POST", "/api/sensitive", config, {
          replay: "replayable",
          binding: "class-bound",
          components: ["@authority"]
        })
      ).toEqual({
        binding: "request-bound",
        replay: "non-replayable",
        components: ["@authority"]
      })
    })

    test("empty classBoundPolicies shorthand keeps class-bound with authority-only minimum", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/api/sensitive": [
            {
              methods: ["POST"],
              replayable: true,
              classBoundPolicies: []
            }
          ]
        }
      }
      expect(
        resolvePosture("POST", "/api/sensitive", config, {
          replay: "replayable",
          binding: "class-bound",
          components: ["authorization"]
        })
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["authorization"]
      })
    })

    test("route enables replay even when default disables it", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          default: { replayable: false },
          "/api/cache-friendly": { methods: ["GET"], replayable: true }
        }
      }
      expect(
        resolvePosture("GET", "/api/cache-friendly", config, {
          replay: "replayable"
        })
      ).toEqual({
        binding: "request-bound",
        replay: "replayable",
        components: undefined
      })
    })

    test("path policy with method restriction is used for matching methods", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/api/auth": {
            methods: ["PUT"],
            replayable: true,
            classBoundPolicies: ["@authority"]
          }
        }
      }
      expect(
        resolvePosture("PUT", "/api/auth", config, {
          replay: "replayable",
          binding: "class-bound",
          components: ["authorization"]
        })
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "authorization"]
      })
    })

    test("unmatched route falls back to default policy", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          default: { replayable: false },
          "/api/session": { methods: ["POST"], replayable: true }
        }
      }
      // GET /other doesn't match any route → falls back to default (replayable: false)
      expect(
        resolvePosture("GET", "/other", config, {
          replay: "replayable"
        })
      ).toEqual({
        binding: "request-bound",
        replay: "non-replayable",
        components: undefined
      })
    })

    test("route with additionalRequestBoundComponents merges them", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/api/orders": [
            {
              methods: ["POST"],
              replayable: false,
              additionalRequestBoundComponents: ["x-idempotency-key"]
            }
          ]
        }
      }
      expect(
        resolvePosture("POST", "/api/orders", config, {
          replay: "non-replayable"
        })
      ).toEqual({
        binding: "request-bound",
        replay: "non-replayable",
        components: ["x-idempotency-key"]
      })
    })

    test("additionalRequestBoundComponents deduplicates with existing components", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/api/orders": [
            {
              methods: ["POST"],
              additionalRequestBoundComponents: [
                "x-idempotency-key",
                "x-custom"
              ]
            }
          ]
        }
      }
      expect(
        resolvePosture("POST", "/api/orders", config, {
          replay: "non-replayable",
          components: ["x-idempotency-key", "authorization"]
        })
      ).toEqual({
        binding: "request-bound",
        replay: "non-replayable",
        components: ["x-idempotency-key", "authorization", "x-custom"]
      })
    })
  })

  // ─── Component merging ──────────────────────────────────────

  describe("component merging", () => {
    test("no route classBoundPolicies → falls back to request-bound with components as extras", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/api/plain": { methods: ["GET"], replayable: true }
        }
      }
      expect(
        resolvePosture("GET", "/api/plain", config, {
          replay: "replayable",
          binding: "class-bound",
          components: ["@authority", "custom"]
        })
      ).toEqual({
        binding: "request-bound",
        replay: "replayable",
        components: ["@authority", "custom"]
      })
    })

    test("empty route classBoundPolicies shorthand keeps class-bound even with no extra components", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/api/plain": {
            methods: ["GET"],
            replayable: true,
            classBoundPolicies: []
          }
        }
      }
      expect(
        resolvePosture("GET", "/api/plain", config, {
          replay: "replayable",
          binding: "class-bound",
          components: []
        })
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: []
      })
    })

    test("deduplicates overlapping components", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/dup": {
            methods: ["GET"],
            replayable: true,
            classBoundPolicies: ["@authority", "shared"]
          }
        }
      }
      expect(
        resolvePosture("GET", "/dup", config, {
          replay: "replayable",
          binding: "class-bound",
          components: ["@authority", "shared", "extra"]
        })
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "shared", "extra"]
      })
    })

    test("handles nested classBoundPolicies (string[][]) with single policy", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/nested": {
            methods: ["GET"],
            replayable: true,
            classBoundPolicies: [["@authority", "x-tenant"]]
          }
        }
      }
      expect(
        resolvePosture("GET", "/nested", config, {
          replay: "replayable",
          binding: "class-bound",
          components: ["authorization"]
        })
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "x-tenant", "authorization"]
      })
    })

    test("picks policy requiring fewest extra components", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/multi": {
            methods: ["GET"],
            replayable: true,
            classBoundPolicies: [
              ["@authority", "x-tenant", "x-region"],
              ["@authority", "authorization"]
            ]
          }
        }
      }
      // Client has ["@authority", "authorization"] → second policy needs 0 extras,
      // first needs 2 extras → picks second
      expect(
        resolvePosture("GET", "/multi", config, {
          replay: "replayable",
          binding: "class-bound",
          components: ["@authority", "authorization"]
        })
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "authorization"]
      })
    })

    test("methodless fallback on a path applies when no method-specific policy matches", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/multi-method": [
            { methods: ["POST"], replayable: false },
            { replayable: true }
          ]
        }
      }

      expect(
        resolvePosture("GET", "/multi-method", config, {
          replay: "replayable"
        })
      ).toEqual({
        binding: "request-bound",
        replay: "replayable",
        components: undefined
      })
    })

    test("default classBoundPolicies do not leak into an explicitly routed path", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/verify": [
            { methods: ["DELETE"], replayable: false },
            { methods: ["POST", "PUT"], classBoundPolicies: [["@authority"]] }
          ],
          default: {
            replayable: true,
            classBoundPolicies: [["@authority", "@path"]]
          }
        }
      }

      expect(
        resolvePosture("GET", "/verify", config, {
          replay: "replayable",
          binding: "class-bound",
          components: ["authorization"]
        })
      ).toEqual({
        binding: "request-bound",
        replay: "replayable",
        components: ["authorization"]
      })
    })

    test("default additionalRequestBoundComponents do not leak into an explicitly routed path", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "/verify": [{ methods: ["DELETE"], replayable: false }],
          default: {
            replayable: true,
            additionalRequestBoundComponents: ["x-request-id"]
          }
        }
      }

      expect(
        resolvePosture("GET", "/verify", config, {
          replay: "replayable"
        })
      ).toEqual({
        binding: "request-bound",
        replay: "replayable",
        components: undefined
      })
    })
  })
})
