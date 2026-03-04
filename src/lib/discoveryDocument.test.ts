import { describe, expect, test } from "bun:test"
import { formatDiscoveryDocument } from "./discoveryDocument"

describe("formatDiscoveryDocument", () => {
  test("returns minimal document with just baseURL", () => {
    const doc = formatDiscoveryDocument({
      baseURL: "https://api.example.com"
    })
    expect(doc).toEqual({
      verification_endpoint: "https://api.example.com/erc8128/verify",
      max_validity_sec: undefined
    })
  })

  test("includes max_validity_sec when provided", () => {
    const doc = formatDiscoveryDocument({
      baseURL: "https://api.example.com",
      maxValiditySec: 300
    })
    expect(doc.max_validity_sec).toBe(300)
  })

  test("includes invalidation_endpoint when any routePolicy has replayable true", () => {
    const doc = formatDiscoveryDocument({
      baseURL: "https://api.example.com",
      routePolicy: {
        "/api/public": { replayable: true },
        "/api/private": { replayable: false }
      }
    })
    expect(doc.invalidation_endpoint).toBe(
      "https://api.example.com/erc8128/invalidate"
    )
  })

  test("omits invalidation_endpoint when no replayable policy", () => {
    const doc = formatDiscoveryDocument({
      baseURL: "https://api.example.com",
      routePolicy: {
        "/api/data": { replayable: false }
      }
    })
    expect(doc.invalidation_endpoint).toBeUndefined()
  })

  test("filters out 'default' key from route_policies", () => {
    const doc = formatDiscoveryDocument({
      baseURL: "https://api.example.com",
      routePolicy: {
        default: { replayable: true },
        "/api/public": { replayable: true }
      }
    })
    expect(doc.route_policies).toEqual({
      "/api/public": { replayable: true }
    })
  })

  test("filters out false values from route_policies", () => {
    const doc = formatDiscoveryDocument({
      baseURL: "https://api.example.com",
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
      baseURL: "https://api.example.com",
      routePolicy: {
        default: { replayable: false }
      }
    })
    expect(doc.route_policies).toBeUndefined()
  })

  test("omits route_policies when routePolicy is not provided", () => {
    const doc = formatDiscoveryDocument({
      baseURL: "https://api.example.com"
    })
    expect(doc.route_policies).toBeUndefined()
  })

  test("preserves route policy details", () => {
    const doc = formatDiscoveryDocument({
      baseURL: "https://api.example.com",
      routePolicy: {
        "/api/orders": {
          replayable: false,
          additionalRequestBoundComponents: ["content-type"]
        }
      }
    })
    expect(doc.route_policies).toEqual({
      "/api/orders": {
        replayable: false,
        additionalRequestBoundComponents: ["content-type"]
      }
    })
  })
})
