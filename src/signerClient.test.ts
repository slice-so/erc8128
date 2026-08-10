import { describe, expect, test } from "bun:test"
import { parseSignatureInputHeader } from "./lib/engine/createSignatureInput"
import { createSignerClient } from "./signerClient"

const signer = {
  address: "0x1111111111111111111111111111111111111111" as const,
  chainId: 8453,
  signMessage: async () => `0x${"11".repeat(65)}` as `0x${string}`
}

describe("createSignerClient authorization constraints", () => {
  const signatureParams = (request: Request) =>
    parseSignatureInputHeader(request.headers.get("signature-input") ?? "")[0]
      ?.params
  test("clamps an explicit expiry to the resolved validity cap", async () => {
    const created = 1_700_000_000
    const client = createSignerClient(signer, {
      authorizationPolicy: {
        binding: "request-bound",
        components: [],
        preferReplayable: false,
        ttlSeconds: 120
      },
      serverConfigs: {
        "https://api.example": {
          max_validity_sec: 40
        }
      }
    })
    const request = await client.signRequest("https://api.example/accounts", {
      created,
      expires: created + 3_600,
      ttlSeconds: 90
    })

    expect(request.headers.get("signature-input")).toContain(
      `;created=${created};expires=${created + 40};`
    )
  })

  test("preserves an explicit expiry that is shorter than every cap", async () => {
    const created = 1_700_000_000
    const client = createSignerClient(signer, {
      authorizationPolicy: {
        binding: "request-bound",
        components: [],
        preferReplayable: false,
        ttlSeconds: 120
      }
    })
    const request = await client.signRequest("https://api.example/accounts", {
      created,
      expires: created + 15
    })

    expect(request.headers.get("signature-input")).toContain(
      `;created=${created};expires=${created + 15};`
    )
  })

  test("normalizes configured origins before applying route policy", async () => {
    const client = createSignerClient(signer, {
      preferReplayable: true,
      serverConfigs: {
        "https://API.example:443/": {
          max_validity_sec: 60,
          route_policies: { default: { replayable: false } }
        }
      }
    })

    const request = await client.signRequest("https://api.example/resource")
    expect(signatureParams(request)?.nonce).toBeDefined()
  })

  test("clamps default signing to route and authorization expiry", async () => {
    const created = 1_700_000_000
    const client = createSignerClient(signer, {
      authorizationExpiresAt: created + 30,
      ttlSeconds: 120,
      serverConfigs: {
        "https://api.example": { max_validity_sec: 40 }
      }
    })

    const request = await client.signRequest("https://api.example/resource", {
      created,
      expires: created + 300
    })
    expect(signatureParams(request)?.expires).toBe(created + 30)
  })

  test("re-resolves route policy after each redirect", async () => {
    const observed: Request[] = []
    const fetchImpl: typeof fetch = Object.assign(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const request =
          input instanceof Request ? input : new Request(input, init)
        observed.push(request.clone())
        return observed.length === 1
          ? new Response(null, {
              status: 303,
              headers: { location: "/admin/transfer" }
            })
          : new Response(null, { status: 204 })
      },
      { preconnect: () => {} }
    )
    const client = createSignerClient(signer, {
      preferReplayable: true,
      fetch: fetchImpl,
      serverConfigs: {
        "https://api.example": {
          max_validity_sec: 60,
          route_policies: {
            "/login": { replayable: true },
            "/admin/*": { replayable: false }
          }
        }
      }
    })

    await client.fetch("https://api.example/login", { method: "POST" })

    expect(signatureParams(observed[0] as Request)?.nonce).toBeUndefined()
    expect(signatureParams(observed[1] as Request)?.nonce).toBeDefined()
    expect(observed[1]?.method).toBe("GET")
  })
})
