import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test"
import { signedFetch, signRequest, verifyRequest } from "@slicekit/erc8128"
import type { Address, Hex } from "viem"
import { createPublicClient, http } from "viem"
import { createSigner } from "./wallet.js"

// Test private key (well-known test key, DO NOT USE IN PRODUCTION)
const TEST_PRIVATE_KEY =
  "0x0123456789012345678901234567890123456789012345678901234567890123"

// Mock fetch for testing (doesn't make actual network requests)
const originalFetch = globalThis.fetch

describe("integration tests", () => {
  let consoleSpy: ReturnType<typeof spyOn>

  beforeAll(() => {
    consoleSpy = spyOn(console, "error").mockImplementation(() => {})
  })

  afterAll(() => {
    consoleSpy.mockRestore()
  })

  describe("full request signing flow", () => {
    test("signs request with Signature and Signature-Input headers", async () => {
      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      const request = new Request("https://api.example.com/resource", {
        method: "GET"
      })

      const signedReq = await signRequest(request, signer)

      // Verify signature headers are present
      const signatureInput = signedReq.headers.get("Signature-Input")
      const signature = signedReq.headers.get("Signature")

      expect(signatureInput).toBeTruthy()
      expect(signature).toBeTruthy()

      // Verify Signature-Input format
      expect(signatureInput).toMatch(/^eth=\(.+\);/)
      expect(signatureInput).toContain("created=")
      expect(signatureInput).toContain("expires=")
      expect(signatureInput).toContain('keyid="erc8128:')

      // Verify Signature format (base64 in colons)
      expect(signature).toMatch(/^eth=:[A-Za-z0-9+/]+={0,2}:$/)
    })

    test("signs POST request with body and adds Content-Digest", async () => {
      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      const request = new Request("https://api.example.com/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data: "test" })
      })

      const signedReq = await signRequest(request, signer)

      // Should have Content-Digest header for POST with body
      const contentDigest = signedReq.headers.get("Content-Digest")
      expect(contentDigest).toBeTruthy()
      expect(contentDigest).toMatch(/^sha-256=:.+:$/)

      // Signature-Input should include content-digest component
      const signatureInput = signedReq.headers.get("Signature-Input")
      expect(signatureInput).toContain('"content-digest"')
    })

    test("signed request can be verified", async () => {
      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      const created = Math.floor(Date.now() / 1000)
      const expires = created + 60

      const request = new Request("https://api.example.com/verify-me", {
        method: "GET"
      })

      const signedReq = await signRequest(request, signer, {
        created,
        expires,
        nonce: "test-nonce-1"
      })

      // Create verification dependencies
      const publicClient = createPublicClient({
        transport: http("http://localhost:8787")
      })

      const verifyMessage = async (args: {
        address: Address
        message: { raw: Hex }
        signature: Hex
      }) => {
        return publicClient.verifyMessage(args)
      }

      const nonceStore = {
        seen: new Set<string>(),
        consume: async (key: string) => {
          if (nonceStore.seen.has(key)) return false
          nonceStore.seen.add(key)
          return true
        }
      }

      const result = await verifyRequest({
        request: signedReq,
        verifyMessage,
        nonceStore,
        policy: {
          now: () => created
        }
      })

      expect(result.ok).toBe(true)
      if (!result.ok) throw new Error("unreachable")
      expect(result.address.toLowerCase()).toBe(signer.address.toLowerCase())
      expect(result.chainId).toBe(1)
    })

    test("includes nonce for non-replayable requests", async () => {
      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      const request = new Request("https://api.example.com/resource", {
        method: "GET"
      })

      const signedReq = await signRequest(request, signer, {
        replay: "non-replayable"
      })

      const signatureInput = signedReq.headers.get("Signature-Input")
      expect(signatureInput).toContain('nonce="')
    })

    test("excludes nonce for replayable requests", async () => {
      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      const request = new Request("https://api.example.com/resource", {
        method: "GET"
      })

      const signedReq = await signRequest(request, signer, {
        replay: "replayable"
      })

      const signatureInput = signedReq.headers.get("Signature-Input")
      expect(signatureInput).not.toContain("nonce=")
    })
  })

  describe("chain ID handling", () => {
    test("keyid includes correct chain ID", async () => {
      const signer137 = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 137 // Polygon
      })

      const request = new Request("https://api.example.com/polygon", {
        method: "GET"
      })

      const signedReq = await signRequest(request, signer137)

      const signatureInput = signedReq.headers.get("Signature-Input")
      expect(signatureInput).toContain('keyid="erc8128:137:')
    })

    test("different chain IDs produce different keyids", async () => {
      const signerMainnet = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      const signerArbitrum = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 42161
      })

      const request = new Request("https://api.example.com/test", {
        method: "GET"
      })

      const signed1 = await signRequest(request.clone(), signerMainnet)
      const signed42161 = await signRequest(request.clone(), signerArbitrum)

      const input1 = signed1.headers.get("Signature-Input")
      const input42161 = signed42161.headers.get("Signature-Input")

      expect(input1).toContain('keyid="erc8128:1:')
      expect(input42161).toContain('keyid="erc8128:42161:')
    })
  })

  describe("binding modes", () => {
    test("request-bound includes all required components", async () => {
      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      const request = new Request("https://api.example.com/path?q=1", {
        method: "POST",
        body: "test"
      })

      const signedReq = await signRequest(request, signer, {
        binding: "request-bound"
      })

      const signatureInput = signedReq.headers.get("Signature-Input")

      // Request-bound should include these components
      expect(signatureInput).toContain('"@authority"')
      expect(signatureInput).toContain('"@method"')
      expect(signatureInput).toContain('"@path"')
      expect(signatureInput).toContain('"@query"')
      expect(signatureInput).toContain('"content-digest"')
    })

    test("class-bound with explicit components", async () => {
      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      const request = new Request("https://api.example.com/class", {
        method: "GET"
      })

      const signedReq = await signRequest(request, signer, {
        binding: "class-bound",
        components: ["@authority"],
        replay: "replayable" // class-bound typically uses replayable
      })

      const signatureInput = signedReq.headers.get("Signature-Input")
      expect(signatureInput).toContain('"@authority"')
    })
  })

  describe("TTL handling", () => {
    test("respects custom TTL in signature", async () => {
      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      const created = 1700000000
      const ttlSeconds = 300 // 5 minutes
      const expires = created + ttlSeconds

      const request = new Request("https://api.example.com/ttl", {
        method: "GET"
      })

      const signedReq = await signRequest(request, signer, {
        created,
        expires
      })

      const signatureInput = signedReq.headers.get("Signature-Input")
      expect(signatureInput).toContain(`created=${created}`)
      expect(signatureInput).toContain(`expires=${expires}`)
    })
  })

  describe("header handling", () => {
    test("preserves original request headers", async () => {
      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      const request = new Request("https://api.example.com/headers", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer token123",
          "X-Custom-Header": "custom-value"
        },
        body: '{"test": true}'
      })

      const signedReq = await signRequest(request, signer)

      expect(signedReq.headers.get("Content-Type")).toBe("application/json")
      expect(signedReq.headers.get("Authorization")).toBe("Bearer token123")
      expect(signedReq.headers.get("X-Custom-Header")).toBe("custom-value")
    })

    test("can sign extra header components", async () => {
      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      const request = new Request("https://api.example.com/custom", {
        method: "GET",
        headers: {
          "X-Api-Key": "key123"
        }
      })

      const signedReq = await signRequest(request, signer, {
        components: ["x-api-key"]
      })

      const signatureInput = signedReq.headers.get("Signature-Input")
      expect(signatureInput).toContain('"x-api-key"')
    })
  })

  describe("signedFetch integration", () => {
    test("signedFetch adds signature headers (mocked)", async () => {
      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        chainId: 1
      })

      let capturedRequest: Request | null = null

      // Mock fetch to capture the request
      const mockFetch = (async (
        input: RequestInfo | URL,
        init?: RequestInit
      ) => {
        if (input instanceof Request) {
          capturedRequest = input
        } else {
          capturedRequest = new Request(input, init)
        }
        return new Response('{"success": true}', {
          status: 200,
          headers: { "Content-Type": "application/json" }
        })
      }) as typeof fetch

      globalThis.fetch = mockFetch

      try {
        const response = await signedFetch(
          "https://api.example.com/fetch-test",
          { method: "GET" },
          signer
        )

        const request = capturedRequest as Request | null
        expect(request).toBeTruthy()
        if (!request) {
          throw new Error("Expected captured request to be set by fetch mock")
        }
        expect(request.headers.get("Signature-Input")).toBeTruthy()
        expect(request.headers.get("Signature")).toBeTruthy()

        const body = await response.json()
        expect(body.success).toBe(true)
      } finally {
        globalThis.fetch = originalFetch
      }
    })
  })
})
