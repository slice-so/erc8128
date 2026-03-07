import { describe, expect, test } from "bun:test"
import { formatDiscoveryDocument } from "./discoveryDocument"

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
      routePolicy: {
        "/api/public": { replayable: true },
        "/api/disabled": false
      }
    })
    expect(doc.route_policies).toEqual({
      "/api/public": { replayable: true }
    })
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
