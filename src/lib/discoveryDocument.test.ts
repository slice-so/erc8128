import { describe, expect, test } from "bun:test"
import {
  formatDiscoveryDocument,
  parseDiscoveryDocument
} from "./discoveryDocument"

describe("formatDiscoveryDocument", () => {
  test("returns minimal document with defaults", () => {
    const doc = formatDiscoveryDocument({})
    expect(doc).toEqual({
      max_validity_sec: 300
    })
  })

  test("includes max_validity_sec when provided", () => {
    const doc = formatDiscoveryDocument({ maxValiditySec: 600 })
    expect(doc.max_validity_sec).toBe(600)
  })

  test("includes verification_endpoint when provided", () => {
    const doc = formatDiscoveryDocument({
      verificationEndpoint: "https://api.example.com/erc8128/verify"
    })
    expect(doc.verification_endpoint).toBe(
      "https://api.example.com/erc8128/verify"
    )
  })

  test("omits verification_endpoint when not provided", () => {
    const doc = formatDiscoveryDocument({})
    expect(doc.verification_endpoint).toBeUndefined()
  })

  test("includes invalidation_endpoint when any routePolicy has replayable true", () => {
    const doc = formatDiscoveryDocument({
      invalidationEndpoint: "https://api.example.com/erc8128/invalidate",
      routePolicy: {
        "/api/public": [{ methods: ["GET"], replayable: true }],
        "/api/private": { replayable: false }
      }
    })
    expect(doc.invalidation_endpoint).toBe(
      "https://api.example.com/erc8128/invalidate"
    )
  })

  test("omits invalidation_endpoint when no replayable policy", () => {
    const doc = formatDiscoveryDocument({
      invalidationEndpoint: "https://api.example.com/erc8128/invalidate",
      routePolicy: {
        "/api/data": { replayable: false }
      }
    })
    expect(doc.invalidation_endpoint).toBeUndefined()
  })

  test("omits invalidation_endpoint when no routePolicy", () => {
    const doc = formatDiscoveryDocument({
      invalidationEndpoint: "https://api.example.com/erc8128/invalidate"
    })
    expect(doc.invalidation_endpoint).toBeUndefined()
  })

  test("preserves the default key in route_policies", () => {
    const doc = formatDiscoveryDocument({
      invalidationEndpoint: "https://api.example.com/erc8128/invalidate",
      routePolicy: {
        default: { replayable: true },
        "/api/public": { replayable: true }
      }
    })
    expect(doc.route_policies).toEqual({
      default: { replayable: true },
      "/api/public": { replayable: true }
    })
  })

  test("filters out false values from route_policies", () => {
    const doc = formatDiscoveryDocument({
      invalidationEndpoint: "https://api.example.com/erc8128/invalidate",
      routePolicy: {
        "/api/public": { replayable: true },
        "/api/disabled": false
      }
    })
    expect(doc.route_policies).toEqual({
      "/api/public": { replayable: true }
    })
  })

  test("rejects replayable policy without a valid invalidation endpoint", () => {
    expect(() =>
      formatDiscoveryDocument({
        routePolicy: { "/api/public": { replayable: true } }
      })
    ).toThrow("invalidation endpoint")
    expect(() =>
      formatDiscoveryDocument({
        invalidationEndpoint: "http://api.example.com/invalidate",
        routePolicy: { "/api/public": { replayable: true } }
      })
    ).toThrow("invalidation endpoint")
  })

  test("rejects invalid verification endpoints and validity windows", () => {
    expect(() =>
      formatDiscoveryDocument({
        verificationEndpoint: "http://api.example.com/verify"
      })
    ).toThrow("configuration")
    expect(() => formatDiscoveryDocument({ maxValiditySec: 0 })).toThrow(
      "configuration"
    )
  })

  test("omits route_policies when all entries are filtered out", () => {
    const doc = formatDiscoveryDocument({
      routePolicy: {
        "/api/disabled": false
      }
    })
    expect(doc.route_policies).toBeUndefined()
  })

  test("omits route_policies when routePolicy is not provided", () => {
    const doc = formatDiscoveryDocument({})
    expect(doc.route_policies).toBeUndefined()
  })

  test("preserves route policy details", () => {
    const doc = formatDiscoveryDocument({
      routePolicy: {
        "/api/orders": {
          methods: ["POST"],
          replayable: false,
          additionalRequestBoundComponents: ["content-type"]
        }
      }
    })
    expect(doc.route_policies).toEqual({
      "/api/orders": {
        methods: ["POST"],
        replayable: false,
        additionalRequestBoundComponents: ["content-type"]
      }
    })
  })

  test("preserves route policy arrays", () => {
    const doc = formatDiscoveryDocument({
      routePolicy: {
        "/verify": [
          { methods: ["DELETE"], replayable: false },
          {
            methods: ["POST", "PUT"],
            classBoundPolicies: [["@authority", "@path"]]
          }
        ]
      }
    })

    expect(doc.route_policies).toEqual({
      "/verify": [
        { methods: ["DELETE"], replayable: false },
        {
          methods: ["POST", "PUT"],
          classBoundPolicies: [["@authority", "@path"]]
        }
      ]
    })
  })
})

describe("parseDiscoveryDocument", () => {
  test("validates the complete discovery document", () => {
    expect(
      parseDiscoveryDocument(
        JSON.stringify({
          invalidation_endpoint: "https://api.example.com/invalidate",
          max_validity_sec: 120,
          route_policies: {
            "/orders": {
              methods: ["POST"],
              replayable: true
            }
          }
        })
      )
    ).toEqual({
      invalidation_endpoint: "https://api.example.com/invalidate",
      max_validity_sec: 120,
      route_policies: {
        "/orders": {
          methods: ["POST"],
          replayable: true
        }
      }
    })
  })

  test("rejects replayable routes without invalidation and unknown fields", () => {
    expect(
      parseDiscoveryDocument(
        JSON.stringify({
          max_validity_sec: 120,
          route_policies: { default: { replayable: true } }
        })
      )
    ).toBeNull()
    expect(
      parseDiscoveryDocument(
        JSON.stringify({ max_validity_sec: 120, permissive: true })
      )
    ).toBeNull()
  })

  test("rejects oversized documents and route maps", () => {
    expect(parseDiscoveryDocument(" ".repeat(65_537))).toBeNull()
    expect(
      parseDiscoveryDocument(
        JSON.stringify({
          max_validity_sec: 120,
          route_policies: Object.fromEntries(
            Array.from({ length: 129 }, (_, index) => [
              `/route-${index}`,
              { replayable: false }
            ])
          )
        })
      )
    ).toBeNull()
  })
})
