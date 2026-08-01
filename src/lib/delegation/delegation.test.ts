import { describe, expect, test } from "bun:test"
import { type Hex, recoverMessageAddress } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { BoundedMemoryNonceStore } from "../../stores"
import { verifyRequest } from "../../verify"
import {
  parseSignatureHeader,
  parseSignatureInputHeader
} from "../engine/createSignatureInput"
import { bytesToHex } from "../utilities"
import {
  buildDelegationGrant,
  completeDelegationGrant,
  getDelegationGrantSignatureBase
} from "./createDelegationGrant"
import { createDelegatedSignerClient } from "./delegatedSignerClient"
import { parseDelegationField } from "./delegationField"

const root = privateKeyToAccount(`0x${"11".repeat(32)}`)
const delegate = privateKeyToAccount(`0x${"22".repeat(32)}`)
const now = Math.floor(Date.now() / 1_000)

const signer = (account: typeof root) => ({
  address: account.address,
  chainId: 8453,
  signMessage: (message: Uint8Array) =>
    account.signMessage({ message: { raw: bytesToHex(message) } })
})

const createGrant = async (
  audiences: readonly string[] = ["https://api.example"],
  extension?: { critical: string; member: { value: boolean } }
) => {
  const prepared = buildDelegationGrant({
    root: { address: root.address, chainId: 8453 },
    delegate: { address: delegate.address, chainId: 8453 },
    delegateKeyType: "eoa",
    audiences,
    id: `0x${"33".repeat(32)}`,
    created: now,
    expires: now + 600,
    maxAge: 60,
    components: ["x-tenant"],
    ...(extension
      ? {
          critical: [extension.critical],
          extensions: { [extension.critical]: extension.member }
        }
      : {})
  })
  return completeDelegationGrant(
    prepared,
    await root.signMessage({
      message: { raw: bytesToHex(prepared.signatureBase) }
    })
  )
}

describe("ERC-8128 delegation", () => {
  test("builds one canonical grant artifact", async () => {
    const grant = await createGrant()
    const field = parseDelegationField(grant.fieldValue)
    expect(field.root).toEqual({
      address: root.address.toLowerCase() as typeof root.address,
      chainId: 8453
    })
    expect(field.delegateKeyType).toBe("eoa")
    expect(field.audiences).toEqual(["https://api.example"])
    expect(field.components).toEqual([{ name: "x-tenant" }])
    expect(getDelegationGrantSignatureBase(grant)).toBeInstanceOf(Uint8Array)
  })

  test("authenticates the root with a zero-RPC delegate request check", async () => {
    const grant = await createGrant()
    const request = await createDelegatedSignerClient(
      signer(delegate),
      grant
    ).signRequest(
      new Request("https://api.example/orders", {
        headers: { "x-tenant": "store-1" }
      }),
      { created: now, expires: now + 45, nonce: "0123456789abcdef" }
    )
    let universalChecks = 0
    const result = await verifyRequest({
      request,
      nonceStore: new BoundedMemoryNonceStore(),
      policy: {
        now: () => now,
        principal: "delegated",
        delegation: { audience: "https://api.example" }
      },
      verifyMessage: async ({ address, message, signature }) => {
        universalChecks += 1
        return (
          (
            await recoverMessageAddress({
              message,
              signature: signature as Hex
            })
          ).toLowerCase() === address.toLowerCase()
        )
      }
    })
    if (!result.ok) throw new Error(result.reason)
    expect(result.ok).toBe(true)
    expect(result.principal.address.toLowerCase()).toBe(
      root.address.toLowerCase()
    )
    expect(result.signer.address.toLowerCase()).toBe(
      delegate.address.toLowerCase()
    )
    expect(result.delegated).toBe(true)
    expect(universalChecks).toBe(1)
  })

  test("canonicalizes cosmetic grant whitespace for verification caching", async () => {
    const grant = await createGrant()
    const cosmeticGrant = {
      ...grant,
      grantSignatureInput: grant.grantSignatureInput
        .replace("(", "(  ")
        .replace(");created", "  );created")
    }
    const cache = new Map<string, boolean>()
    let rootChecks = 0

    for (const [index, candidateGrant] of [grant, cosmeticGrant].entries()) {
      const request = await createDelegatedSignerClient(
        signer(delegate),
        candidateGrant
      ).signRequest(
        new Request("https://api.example/orders", {
          headers: { "x-tenant": "store-1" }
        }),
        {
          created: now,
          expires: now + 45,
          nonce: `cache-nonce-000${index}`
        }
      )
      const result = await verifyRequest({
        request,
        nonceStore: new BoundedMemoryNonceStore(),
        policy: {
          now: () => now,
          principal: "delegated",
          delegation: {
            audience: "https://api.example",
            grantCache: {
              get: (key) => cache.get(key),
              set: (key) => {
                cache.set(key, true)
              }
            }
          }
        },
        verifyMessage: async ({ address, message, signature }) => {
          rootChecks += 1
          return (
            (
              await recoverMessageAddress({
                message,
                signature: signature as Hex
              })
            ).toLowerCase() === address.toLowerCase()
          )
        }
      })
      expect(result.ok).toBe(true)
    }

    expect(cache.size).toBe(1)
    expect(rootChecks).toBe(1)
  })

  test("verifies one grant at most once across mixed request candidates", async () => {
    const grant = await createGrant(["https://api.example"], {
      critical: "test-extension",
      member: { value: true }
    })
    const signed = await createDelegatedSignerClient(
      signer(delegate),
      grant
    ).signRequest(
      new Request("https://api.example/orders", {
        headers: { "x-tenant": "store-1" }
      }),
      { created: now, expires: now + 45, nonce: "mixed-candidate-1" }
    )
    const headers = new Headers(signed.headers)
    const requestCandidate = parseSignatureInputHeader(
      headers.get("signature-input") ?? ""
    ).find(({ params }) => params.tag === "erc8128-delegated")
    const requestSignature = parseSignatureHeader(
      headers.get("signature") ?? ""
    ).get(requestCandidate?.label ?? "")
    if (!requestCandidate || !requestSignature) {
      throw new Error("Expected delegated request signature.")
    }
    headers.set(
      "signature-input",
      `${headers.get("signature-input")}, alt=${requestCandidate.signatureParamsValue}`
    )
    headers.set(
      "signature",
      `${headers.get("signature")}, alt=:${requestSignature}:`
    )

    let rootChecks = 0
    let nonceConsumes = 0
    const result = await verifyRequest({
      request: new Request(signed, { headers }),
      nonceStore: {
        consume: async () => {
          nonceConsumes += 1
          return true
        }
      },
      policy: {
        now: () => now,
        principal: "delegated",
        delegation: {
          audience: "https://api.example",
          extensions: { "test-extension": () => false }
        }
      },
      verifyMessage: async ({ address, message, signature }) => {
        rootChecks += 1
        return (
          (
            await recoverMessageAddress({
              message,
              signature: signature as Hex
            })
          ).toLowerCase() === address.toLowerCase()
        )
      }
    })

    expect(result).toMatchObject({
      ok: false,
      reason: "delegation_extension_rejected"
    })
    expect(rootChecks).toBe(1)
    expect(nonceConsumes).toBe(0)
  })

  test("refuses a destination outside the exact audience", async () => {
    const grant = await createGrant()
    await expect(
      createDelegatedSignerClient(signer(delegate), grant).signRequest(
        "https://other.example/orders"
      )
    ).rejects.toThrow("outside the delegation audience")
  })

  test("rebuilds and re-signs an allowed redirect without losing its body", async () => {
    const grant = await createGrant([
      "https://api.example",
      "https://next.example"
    ])
    const observed: Request[] = []
    const fetchImpl: typeof fetch = Object.assign(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const request =
          input instanceof Request ? input : new Request(input, init)
        observed.push(request.clone())
        return observed.length === 1
          ? new Response(null, {
              headers: { location: "https://next.example/continued" },
              status: 307
            })
          : new Response(null, { status: 204 })
      },
      { preconnect: () => {} }
    )
    const client = createDelegatedSignerClient(signer(delegate), grant, {
      fetch: fetchImpl
    })
    const response = await client.fetch(
      new Request("https://api.example/start", {
        body: "redirected body",
        headers: { "content-type": "text/plain", "x-tenant": "store-1" },
        method: "POST"
      }),
      { created: now, expires: now + 45, nonce: "redirect-nonce-1" }
    )
    expect(response.status).toBe(204)
    expect(observed.map(({ url }) => url)).toEqual([
      "https://api.example/start",
      "https://next.example/continued"
    ])
    expect(await observed[1]?.text()).toBe("redirected body")
    expect(observed[0]?.headers.get("signature-input")).not.toBe(
      observed[1]?.headers.get("signature-input")
    )
    const requestNonce = (request: Request) =>
      parseSignatureInputHeader(
        request.headers.get("signature-input") ?? ""
      ).find(({ params }) => params.tag === "erc8128-delegated")?.params.nonce
    expect(requestNonce(observed[0] as Request)).not.toBe(
      requestNonce(observed[1] as Request)
    )
  })
})
