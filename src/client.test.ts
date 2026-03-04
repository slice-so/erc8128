import { describe, expect, test } from "bun:test"
import { createSignerClient } from "."
import type { Address, Hex, ServerConfig } from "./lib/types"

function makeSigner() {
  return {
    chainId: 1,
    address: "0x0000000000000000000000000000000000000001" as Address,
    signMessage: async () => "0x11" as Hex
  }
}

describe("ERC-8128 client", () => {
  test("signRequest merges defaults with per-call options", async () => {
    const signer = makeSigner()
    const client = createSignerClient(signer, {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      nonce: "nonce-default"
    })

    const signed = await client.signRequest("https://example.com", {
      nonce: "nonce-override"
    })

    const sigInput = signed.headers.get("Signature-Input")
    expect(sigInput).toBeTruthy()
    if (!sigInput) throw new Error("unreachable")
    expect(sigInput).toContain('nonce="nonce-override"')
    expect(sigInput).toContain("created=1700000000")
    expect(sigInput).toContain("expires=1700000060")
  })

  test("fetch uses defaults.fetch and supports init/opts overloads", async () => {
    const signer = makeSigner()
    type RecordedRequest = { headers: Headers }
    const makeRecorder = () => {
      let resolve!: (request: RecordedRequest) => void
      const promise = new Promise<RecordedRequest>((res) => {
        resolve = res
      })
      return { promise, resolve }
    }

    let recorder = makeRecorder()
    const fetchStub = Object.assign(
      (async (input: RequestInfo | URL, init?: RequestInit) => {
        const req = input instanceof Request ? input : new Request(input, init)
        recorder.resolve({ headers: req.headers })
        return new Response("ok")
      }) as typeof fetch,
      { preconnect: () => undefined }
    )

    const client = createSignerClient(signer, {
      fetch: fetchStub,
      created: 1_700_000_000,
      expires: 1_700_000_060,
      nonce: "nonce-default"
    })

    await client.fetch(
      "https://example.com",
      { method: "GET" },
      {
        nonce: "nonce-call"
      }
    )

    const firstRequest = await recorder.promise
    expect(firstRequest.headers.get("Signature-Input")).toContain(
      'nonce="nonce-call"'
    )

    recorder = makeRecorder()
    await client.fetch("https://example.com/opts-only", { nonce: "nonce-only" })
    const secondRequest = await recorder.promise
    expect(secondRequest.headers.get("Signature-Input")).toContain(
      'nonce="nonce-only"'
    )
  })
})

// ─── Posture system ───────────────────────────────────────────

const ORIGIN = "https://example.com"

const exampleConfig: ServerConfig = {
  max_validity_sec: 300,
  route_policies: {
    default: { replayable: true },
    "POST /api/auth/session": {
      replayable: true,
      classBoundPolicies: ["@authority", "x-session-id"]
    },
    "POST /api/sensitive": { replayable: false }
  }
}

// Helper: parse Signature-Input to check binding/replay/nonce/components
function parseSignatureInput(req: Request) {
  const raw = req.headers.get("Signature-Input")
  if (!raw) throw new Error("missing Signature-Input")
  const hasNonce = raw.includes("nonce=")
  // Components are the inner list items before the `;params`
  // e.g. eth=("@authority" "@method" "@path");created=...
  const innerMatch = raw.match(/=\(([^)]*)\)/)
  const components = innerMatch
    ? innerMatch[1]
        .split(" ")
        .map((s) => s.replace(/"/g, ""))
        .filter(Boolean)
    : []
  return { raw, hasNonce, components }
}

describe("ERC-8128 client posture", () => {
  test("default posture: non-replayable + request-bound (has nonce)", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      serverConfigs: { [ORIGIN]: exampleConfig }
    })

    const req = await client.signRequest(`${ORIGIN}/any`)
    const { hasNonce, components } = parseSignatureInput(req)
    expect(hasNonce).toBe(true)
    // Request-bound always includes @authority, @method, @path
    expect(components).toContain("@authority")
    expect(components).toContain("@method")
    expect(components).toContain("@path")
  })

  test("preferReplayable on a replayable route → no nonce", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      serverConfigs: { [ORIGIN]: exampleConfig }
    })

    const req = await client.signRequest(`${ORIGIN}/api/auth/session`, {
      method: "POST"
    })
    const { hasNonce } = parseSignatureInput(req)
    expect(hasNonce).toBe(false) // replayable → no nonce
  })

  test("preferReplayable on a non-replayable route → falls back to nonce", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      serverConfigs: { [ORIGIN]: exampleConfig }
    })

    const req = await client.signRequest(`${ORIGIN}/api/sensitive`, {
      method: "POST"
    })
    const { hasNonce } = parseSignatureInput(req)
    expect(hasNonce).toBe(true) // route disables replay → nonce required
  })

  test("preferReplayable + class-bound with components → merged with route classBoundPolicies", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      binding: "class-bound",
      components: ["@authority", "authorization"],
      serverConfigs: { [ORIGIN]: exampleConfig }
    })

    const req = await client.signRequest(
      new Request(`${ORIGIN}/api/auth/session`, {
        method: "POST",
        headers: {
          authorization: "Bearer tok",
          "x-session-id": "sess-123"
        }
      })
    )
    const { hasNonce, components } = parseSignatureInput(req)

    expect(hasNonce).toBe(false) // replayable
    // Class-bound: should have union of components + route's classBoundPolicies
    expect(components).toContain("@authority")
    expect(components).toContain("x-session-id")
    expect(components).toContain("authorization")
    // Class-bound should NOT have @method/@path
    expect(components).not.toContain("@method")
    expect(components).not.toContain("@path")
  })

  test("per-call explicit overrides bypass defaults", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      binding: "class-bound",
      components: ["@authority"],
      serverConfigs: { [ORIGIN]: exampleConfig }
    })

    // Per-call: override replay + binding to request-bound non-replayable
    const req = await client.signRequest(
      `${ORIGIN}/api/auth/session`,
      {
        method: "POST"
      },
      {
        replay: "non-replayable",
        binding: "request-bound",
        nonce: "explicit-nonce"
      }
    )
    const { hasNonce } = parseSignatureInput(req)
    expect(hasNonce).toBe(true)
  })

  test("optimization: no posture fields → request-bound + non-replayable even with serverConfigs", async () => {
    // Neither preferReplayable nor class-bound set → posture resolution uses defaults
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      serverConfigs: { [ORIGIN]: exampleConfig }
    })

    const req = await client.signRequest(`${ORIGIN}/api/auth/session`, {
      method: "POST"
    })
    const { hasNonce, components } = parseSignatureInput(req)
    // Even though the route allows replay, the client didn't opt in
    expect(hasNonce).toBe(true)
    expect(components).toContain("@method")
  })
})

// ─── setServerConfig ──────────────────────────────────────────

describe("ERC-8128 client setServerConfig", () => {
  test("setServerConfig adds config for an origin", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true
    })

    // No config → preferReplayable used as-is → replayable
    const req1 = await client.signRequest(`${ORIGIN}/any`)
    expect(parseSignatureInput(req1).hasNonce).toBe(false)

    // Set config that disables replay globally
    client.setServerConfig(ORIGIN, {
      max_validity_sec: 300,
      route_policies: { default: { replayable: false } }
    })

    const req2 = await client.signRequest(`${ORIGIN}/any`)
    expect(parseSignatureInput(req2).hasNonce).toBe(true) // now non-replayable
  })

  test("setServerConfig(origin, null) removes config", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      serverConfigs: {
        [ORIGIN]: {
          max_validity_sec: 300,
          route_policies: { default: { replayable: false } }
        }
      }
    })

    // Config disables replay
    const req1 = await client.signRequest(`${ORIGIN}/any`)
    expect(parseSignatureInput(req1).hasNonce).toBe(true)

    // Remove config → back to preference-only
    client.setServerConfig(ORIGIN, null)
    const req2 = await client.signRequest(`${ORIGIN}/any`)
    expect(parseSignatureInput(req2).hasNonce).toBe(false)
  })
})

// ─── Multi-origin ─────────────────────────────────────────────

describe("ERC-8128 client multi-origin", () => {
  const ORIGIN_A = "https://api-a.example.com"
  const ORIGIN_B = "https://api-b.example.com"

  const configA: ServerConfig = {
    max_validity_sec: 300,
    route_policies: {
      default: { replayable: true },
      "GET /session": { replayable: true }
    }
  }

  const configB: ServerConfig = {
    max_validity_sec: 120,
    route_policies: {
      default: { replayable: false }
    }
  }

  test("different origins use different server configs", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      serverConfigs: { [ORIGIN_A]: configA, [ORIGIN_B]: configB }
    })

    // Origin A allows replay on GET /session
    const reqA = await client.signRequest(`${ORIGIN_A}/session`)
    expect(parseSignatureInput(reqA).hasNonce).toBe(false)

    // Origin B disables replay globally
    const reqB = await client.signRequest(`${ORIGIN_B}/session`)
    expect(parseSignatureInput(reqB).hasNonce).toBe(true)
  })

  test("unknown origin has no server config → uses preferences as-is", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      serverConfigs: { [ORIGIN_A]: configA }
    })

    // ORIGIN_B has no config → preferReplayable applies unconditionally
    const req = await client.signRequest(`${ORIGIN_B}/anything`)
    expect(parseSignatureInput(req).hasNonce).toBe(false)
  })

  test("setServerConfig on one origin does not affect another", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      serverConfigs: { [ORIGIN_A]: configA }
    })

    // Add restrictive config for ORIGIN_B
    client.setServerConfig(ORIGIN_B, configB)

    // ORIGIN_A still uses its config (replayable)
    const reqA = await client.signRequest(`${ORIGIN_A}/session`)
    expect(parseSignatureInput(reqA).hasNonce).toBe(false)

    // ORIGIN_B now uses its config (non-replayable)
    const reqB = await client.signRequest(`${ORIGIN_B}/session`)
    expect(parseSignatureInput(reqB).hasNonce).toBe(true)
  })

  test("replacing a config updates posture for that origin", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      serverConfigs: { [ORIGIN_A]: configA }
    })

    // configA allows replay → replayable
    const req1 = await client.signRequest(`${ORIGIN_A}/session`)
    expect(parseSignatureInput(req1).hasNonce).toBe(false)

    // Replace with restrictive config
    client.setServerConfig(ORIGIN_A, configB)

    // Now non-replayable
    const req2 = await client.signRequest(`${ORIGIN_A}/session`)
    expect(parseSignatureInput(req2).hasNonce).toBe(true)
  })

  test("replacing a config with new route_policies applies the new policies", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      serverConfigs: {
        [ORIGIN_A]: {
          max_validity_sec: 300,
          route_policies: { "GET /data": { replayable: true } }
        }
      }
    })

    // GET /data is replayable
    const req1 = await client.signRequest(`${ORIGIN_A}/data`)
    expect(parseSignatureInput(req1).hasNonce).toBe(false)

    // Replace with config that disables replay on GET /data
    client.setServerConfig(ORIGIN_A, {
      max_validity_sec: 300,
      route_policies: { "GET /data": { replayable: false } }
    })

    const req2 = await client.signRequest(`${ORIGIN_A}/data`)
    expect(parseSignatureInput(req2).hasNonce).toBe(true)
  })

  test("incrementally adding configs from empty", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true
    })

    // No configs → preferences used as-is → replayable for both
    const reqA1 = await client.signRequest(`${ORIGIN_A}/session`)
    expect(parseSignatureInput(reqA1).hasNonce).toBe(false)
    const reqB1 = await client.signRequest(`${ORIGIN_B}/session`)
    expect(parseSignatureInput(reqB1).hasNonce).toBe(false)

    // Add config for A (allows replay)
    client.setServerConfig(ORIGIN_A, configA)

    // A still replayable (config agrees with preference)
    const reqA2 = await client.signRequest(`${ORIGIN_A}/session`)
    expect(parseSignatureInput(reqA2).hasNonce).toBe(false)
    // B unchanged (still no config)
    const reqB2 = await client.signRequest(`${ORIGIN_B}/session`)
    expect(parseSignatureInput(reqB2).hasNonce).toBe(false)

    // Add restrictive config for B
    client.setServerConfig(ORIGIN_B, configB)

    // A still replayable
    const reqA3 = await client.signRequest(`${ORIGIN_A}/session`)
    expect(parseSignatureInput(reqA3).hasNonce).toBe(false)
    // B now non-replayable
    const reqB3 = await client.signRequest(`${ORIGIN_B}/session`)
    expect(parseSignatureInput(reqB3).hasNonce).toBe(true)
  })

  test("deleting one origin preserves the other", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      serverConfigs: { [ORIGIN_A]: configA, [ORIGIN_B]: configB }
    })

    // Both configs active
    expect(
      parseSignatureInput(await client.signRequest(`${ORIGIN_A}/session`))
        .hasNonce
    ).toBe(false)
    expect(
      parseSignatureInput(await client.signRequest(`${ORIGIN_B}/session`))
        .hasNonce
    ).toBe(true)

    // Remove A
    client.setServerConfig(ORIGIN_A, null)

    // A falls back to preference-only (replayable)
    expect(
      parseSignatureInput(await client.signRequest(`${ORIGIN_A}/session`))
        .hasNonce
    ).toBe(false)
    // B still governed by its config (non-replayable)
    expect(
      parseSignatureInput(await client.signRequest(`${ORIGIN_B}/session`))
        .hasNonce
    ).toBe(true)
  })

  test("deleting all configs reverts to empty state", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      serverConfigs: { [ORIGIN_A]: configA, [ORIGIN_B]: configB }
    })

    client.setServerConfig(ORIGIN_A, null)
    client.setServerConfig(ORIGIN_B, null)

    // Both origins now use preference-only → replayable
    expect(
      parseSignatureInput(await client.signRequest(`${ORIGIN_A}/session`))
        .hasNonce
    ).toBe(false)
    expect(
      parseSignatureInput(await client.signRequest(`${ORIGIN_B}/session`))
        .hasNonce
    ).toBe(false)
  })

  test("re-adding a config after deletion works", async () => {
    const client = createSignerClient(makeSigner(), {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      preferReplayable: true,
      serverConfigs: { [ORIGIN_A]: configB } // restrictive
    })

    // Non-replayable
    expect(
      parseSignatureInput(await client.signRequest(`${ORIGIN_A}/session`))
        .hasNonce
    ).toBe(true)

    // Remove
    client.setServerConfig(ORIGIN_A, null)
    expect(
      parseSignatureInput(await client.signRequest(`${ORIGIN_A}/session`))
        .hasNonce
    ).toBe(false)

    // Re-add with permissive config
    client.setServerConfig(ORIGIN_A, configA)
    expect(
      parseSignatureInput(await client.signRequest(`${ORIGIN_A}/session`))
        .hasNonce
    ).toBe(false)

    // Re-add with restrictive config again
    client.setServerConfig(ORIGIN_A, configB)
    expect(
      parseSignatureInput(await client.signRequest(`${ORIGIN_A}/session`))
        .hasNonce
    ).toBe(true)
  })
})
