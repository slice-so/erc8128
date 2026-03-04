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
          "POST /api/session": {
            replayable: true,
            classBoundPolicies: ["@authority", "x-session-id"]
          }
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
          "POST /api/sensitive": {
            replayable: false,
            classBoundPolicies: ["@authority"]
          }
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
          "POST /api/sensitive": { replayable: false }
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

    test("route enables replay even when default disables it", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          default: { replayable: false },
          "GET /api/cache-friendly": { replayable: true }
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

    test("wildcard route policy is used when no exact match", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "* /api/auth": {
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
          "POST /api/session": { replayable: true }
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
          "POST /api/orders": {
            replayable: false,
            additionalRequestBoundComponents: ["x-idempotency-key"]
          }
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
          "POST /api/orders": {
            additionalRequestBoundComponents: ["x-idempotency-key", "x-custom"]
          }
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
          "GET /api/plain": { replayable: true }
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

    test("deduplicates overlapping components", () => {
      const config: ServerConfig = {
        max_validity_sec: 300,
        route_policies: {
          "GET /dup": {
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
          "GET /nested": {
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
          "GET /multi": {
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
  })
})
