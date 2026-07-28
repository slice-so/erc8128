import { describe, expect, test } from "bun:test"
import { createSignerClient } from "./signerClient"

const signer = {
  address: "0x1111111111111111111111111111111111111111" as const,
  chainId: 8453,
  signMessage: async () => `0x${"11".repeat(65)}` as `0x${string}`
}

describe("createSignerClient authorization constraints", () => {
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
})
