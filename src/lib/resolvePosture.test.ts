import { describe, expect, test } from "bun:test"
import { resolvePosture } from "./resolvePosture"
import type { ServerConfig } from "./types"

const baseConfig: ServerConfig = {
  replay_protection: { replayable: true },
  max_validity_sec: 300
}

describe("resolvePosture", () => {
  // ─── Without serverConfig ───────────────────────────────────

  describe("without serverConfig", () => {
    test("preferReplayable=false → non-replayable + request-bound", () => {
      expect(resolvePosture("GET", "/any", false, undefined, null)).toEqual({
        binding: "request-bound",
        replay: "non-replayable",
        components: undefined
      })
    })

    test("preferReplayable=false ignores minComponents", () => {
      expect(
        resolvePosture("GET", "/any", false, ["@authority"], null)
      ).toEqual({
        binding: "request-bound",
        replay: "non-replayable",
        components: undefined
      })
    })

    test("preferReplayable=true without minComponents → replayable + request-bound", () => {
      expect(resolvePosture("GET", "/any", true, undefined, null)).toEqual({
        binding: "request-bound",
        replay: "replayable",
        components: undefined
      })
    })

    test("preferReplayable=true with minComponents → replayable + class-bound", () => {
      expect(
        resolvePosture(
          "GET",
          "/any",
          true,
          ["@authority", "authorization"],
          null
        )
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "authorization"]
      })
    })
  })

  // ─── With serverConfig ──────────────────────────────────────

  describe("with serverConfig (server allows replay globally)", () => {
    test("client prefers replayable + server allows → replayable", () => {
      expect(
        resolvePosture("GET", "/any", true, undefined, baseConfig)
      ).toEqual({
        binding: "request-bound",
        replay: "replayable",
        components: undefined
      })
    })

    test("client does not prefer replayable → non-replayable regardless of server", () => {
      expect(
        resolvePosture("GET", "/any", false, undefined, baseConfig)
      ).toEqual({
        binding: "request-bound",
        replay: "non-replayable",
        components: undefined
      })
    })

    test("replayable + minComponents → class-bound with merged components", () => {
      const config: ServerConfig = {
        ...baseConfig,
        route_policies: {
          "POST /api/session": {
            replayable: true,
            classBoundPolicies: ["@authority", "x-session-id"]
          }
        }
      }
      expect(
        resolvePosture(
          "POST",
          "/api/session",
          true,
          ["@authority", "authorization"],
          config
        )
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "x-session-id", "authorization"]
      })
    })
  })

  describe("route-level overrides", () => {
    test("route disables replay even when server allows it globally", () => {
      const config: ServerConfig = {
        ...baseConfig,
        route_policies: {
          "POST /api/sensitive": { replayable: false }
        }
      }
      expect(
        resolvePosture("POST", "/api/sensitive", true, ["@authority"], config)
      ).toEqual({
        binding: "request-bound",
        replay: "non-replayable",
        components: undefined
      })
    })

    test("route enables replay even when server disables it globally", () => {
      const config: ServerConfig = {
        replay_protection: { replayable: false },
        max_validity_sec: 300,
        route_policies: {
          "GET /api/cache-friendly": { replayable: true }
        }
      }
      expect(
        resolvePosture("GET", "/api/cache-friendly", true, undefined, config)
      ).toEqual({
        binding: "request-bound",
        replay: "replayable",
        components: undefined
      })
    })

    test("wildcard route policy is used when no exact match", () => {
      const config: ServerConfig = {
        ...baseConfig,
        route_policies: {
          "* /api/auth": {
            replayable: true,
            classBoundPolicies: ["@authority"]
          }
        }
      }
      expect(
        resolvePosture("PUT", "/api/auth", true, ["authorization"], config)
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "authorization"]
      })
    })

    test("unmatched route falls back to server global policy", () => {
      const config: ServerConfig = {
        replay_protection: { replayable: false },
        max_validity_sec: 300,
        route_policies: {
          "POST /api/session": { replayable: true }
        }
      }
      // GET /other doesn't match any route → falls back to global (replayable: false)
      expect(resolvePosture("GET", "/other", true, undefined, config)).toEqual({
        binding: "request-bound",
        replay: "non-replayable",
        components: undefined
      })
    })
  })

  // ─── Component merging ──────────────────────────────────────

  describe("component merging", () => {
    test("no route classBoundPolicies → uses minComponents as-is", () => {
      const config: ServerConfig = {
        ...baseConfig,
        route_policies: {
          "GET /api/plain": { replayable: true }
        }
      }
      expect(
        resolvePosture(
          "GET",
          "/api/plain",
          true,
          ["@authority", "custom"],
          config
        )
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "custom"]
      })
    })

    test("deduplicates overlapping components", () => {
      const config: ServerConfig = {
        ...baseConfig,
        route_policies: {
          "GET /dup": {
            replayable: true,
            classBoundPolicies: ["@authority", "shared"]
          }
        }
      }
      expect(
        resolvePosture(
          "GET",
          "/dup",
          true,
          ["@authority", "shared", "extra"],
          config
        )
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "shared", "extra"]
      })
    })

    test("handles nested classBoundPolicies (string[][])", () => {
      const config: ServerConfig = {
        ...baseConfig,
        route_policies: {
          "GET /nested": {
            replayable: true,
            classBoundPolicies: [["@authority", "x-tenant"]]
          }
        }
      }
      expect(
        resolvePosture("GET", "/nested", true, ["authorization"], config)
      ).toEqual({
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority", "x-tenant", "authorization"]
      })
    })
  })
})
