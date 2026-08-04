import { describe, expect, test } from "bun:test"
import { recoverMessageAddress } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { VerificationUnavailableError } from "./lib/Erc8128Error"
import { parseSignatureInputHeader } from "./lib/engine/createSignatureInput"
import { formatErc8128ProblemDetails } from "./lib/problemDetails"
import { bytesToHex } from "./lib/utilities"
import { signedFetch, signRequest } from "./sign"
import { BoundedMemoryNonceStore } from "./stores"
import { verifyRequest } from "./verify"

const account = privateKeyToAccount(`0x${"11".repeat(32)}`)
const secondAccount = privateKeyToAccount(`0x${"22".repeat(32)}`)
const now = Math.floor(Date.now() / 1_000)
const signer = {
  address: account.address,
  chainId: 1,
  signMessage: (message: Uint8Array) =>
    account.signMessage({ message: { raw: bytesToHex(message) } })
}
const secondSigner = {
  address: secondAccount.address,
  chainId: 1,
  signMessage: (message: Uint8Array) =>
    secondAccount.signMessage({ message: { raw: bytesToHex(message) } })
}

const universalVerify = async ({
  address,
  message,
  signature
}: Parameters<import("./types").VerifyMessageFn>[0]) =>
  (await recoverMessageAddress({ message, signature })).toLowerCase() ===
  address.toLowerCase()

describe("ERC-8128 direct signing and verification", () => {
  test("rejects missing signature fields before buffering request content", async () => {
    const request = new Request("https://api.example/orders", {
      body: "untrusted body",
      method: "POST"
    })
    let bodyRead = false
    Object.defineProperty(request, "clone", {
      value: () => {
        bodyRead = true
        throw new Error("Body must not be read.")
      }
    })
    expect(
      await verifyRequest({
        request,
        nonceStore: new BoundedMemoryNonceStore(),
        verifyMessage: universalVerify
      })
    ).toEqual({ ok: false, reason: "signature_missing" })
    expect(bodyRead).toBe(false)
  })

  test("round trips the mandatory tag, CAIP-10 key, and request floor", async () => {
    const signed = await signRequest(
      "https://api.example/orders?cursor=1",
      signer,
      {
        created: now,
        expires: now + 60,
        nonce: "0123456789abcdef"
      }
    )
    expect(signed.headers.get("signature-input")).toContain('tag="erc8128"')
    expect(signed.headers.get("signature-input")).toContain(
      `keyid="eip155:1:${account.address.toLowerCase()}"`
    )
    const result = await verifyRequest({
      request: signed,
      nonceStore: new BoundedMemoryNonceStore(),
      policy: { now: () => now, principal: "direct" },
      verifyMessage: universalVerify
    })
    expect(result.ok).toBe(true)
    if (!result.ok || result.delegated) throw new Error("unreachable")
    expect(result.principal).toEqual({
      address: account.address.toLowerCase() as typeof account.address,
      chainId: 1
    })
    expect(result.signer).toEqual(result.principal)
    expect(result.components.map(({ name }) => name)).toEqual([
      "@scheme",
      "@authority",
      "@method",
      "@path",
      "@query"
    ])
  })

  test("allocates collision-free transport labels when composing signatures", async () => {
    const first = await signRequest("https://api.example/composed", signer, {
      created: now,
      expires: now + 60,
      nonce: "composed-first-1"
    })
    const second = await signRequest(first, signer, {
      created: now,
      expires: now + 60,
      nonce: "composed-second-1"
    })
    expect(
      parseSignatureInputHeader(
        second.headers.get("signature-input") ?? ""
      ).map(({ label }) => label)
    ).toEqual(["request", "request1"])
  })

  test("recomputes the digest over exact received bytes", async () => {
    const signed = await signRequest(
      new Request("https://api.example/orders", {
        body: "one",
        headers: { "content-type": "text/plain" },
        method: "POST"
      }),
      signer,
      { created: now, expires: now + 60, nonce: "fedcba9876543210" }
    )
    const tampered = new Request(signed.url, {
      body: "two",
      headers: signed.headers,
      method: "POST"
    })
    await expect(
      verifyRequest({
        request: tampered,
        nonceStore: new BoundedMemoryNonceStore(),
        policy: { now: () => now },
        verifyMessage: universalVerify
      })
    ).resolves.toEqual({ ok: false, reason: "bad_content_digest" })
  })

  test("covers content type without requiring a digest for empty content", async () => {
    const signed = await signRequest(
      new Request("https://api.example/empty", {
        body: "",
        headers: { "content-type": "text/plain" },
        method: "POST"
      }),
      signer,
      { created: now, expires: now + 60, nonce: "empty-content-123" }
    )
    const signatureInput = signed.headers.get("signature-input")
    expect(signatureInput).not.toContain('"content-digest"')
    expect(signatureInput).toContain('"content-type"')
    expect(signed.headers.get("content-digest")).toBeNull()
  })

  test("rejects unsigned received fields under explicit class-bound policy", async () => {
    const classBoundOptions = {
      binding: "class-bound" as const,
      components: ["@authority"],
      created: now,
      expires: now + 60,
      nonce: "class-bound-test"
    }
    const signedWithoutType = await signRequest(
      "https://api.example/read",
      signer,
      classBoundOptions
    )
    const injectedType = new Request(signedWithoutType, {
      headers: new Headers([
        ...signedWithoutType.headers.entries(),
        ["content-type", "text/plain"]
      ])
    })
    const signedWithoutDigest = await signRequest(
      "https://api.example/write",
      signer,
      { ...classBoundOptions, nonce: "class-bound-body" }
    )
    const injectedBody = new Request(signedWithoutDigest, {
      body: "received",
      method: "POST"
    })

    for (const request of [injectedType, injectedBody]) {
      const result = await verifyRequest({
        request,
        nonceStore: new BoundedMemoryNonceStore(),
        policy: {
          classBoundPolicies: ["@authority"],
          now: () => now
        },
        verifyMessage: universalVerify
      })
      expect(result.ok).toBe(false)
    }
  })

  test("supports explicit EOA-only verification without RPC", async () => {
    const signed = await signRequest("https://api.example/me", signer, {
      created: now,
      expires: now + 60,
      nonce: "aaaaaaaaaaaaaaaa"
    })
    let calls = 0
    const result = await verifyRequest({
      request: signed,
      nonceStore: new BoundedMemoryNonceStore(),
      policy: { accountVerification: "eoa-only", now: () => now },
      verifyMessage: async () => {
        calls += 1
        return false
      }
    })
    expect(result.ok).toBe(true)
    expect(calls).toBe(0)
  })

  test("distinguishes unavailable universal verification", async () => {
    const signed = await signRequest("https://api.example/me", signer, {
      created: now,
      expires: now + 60,
      nonce: "bbbbbbbbbbbbbbbb"
    })
    await expect(
      verifyRequest({
        request: signed,
        nonceStore: new BoundedMemoryNonceStore(),
        policy: { now: () => now },
        verifyMessage: async () => {
          throw new VerificationUnavailableError()
        }
      })
    ).resolves.toEqual({
      ok: false,
      reason: "signature_verification_unavailable"
    })
  })

  test("rejects an otherwise signed candidate without the mandatory tag", async () => {
    const signed = await signRequest("https://api.example/me", signer, {
      created: now,
      expires: now + 60,
      nonce: "mandatory-tag-test"
    })
    const headers = new Headers(signed.headers)
    headers.set(
      "signature-input",
      (headers.get("signature-input") ?? "").replace(';tag="erc8128"', "")
    )

    expect(
      await verifyRequest({
        request: new Request(signed, { headers }),
        nonceStore: new BoundedMemoryNonceStore(),
        policy: { now: () => now },
        verifyMessage: universalVerify
      })
    ).toEqual({ ok: false, reason: "no_acceptable_signature" })
  })

  test("rejects the unsupported alg parameter before cryptography", async () => {
    const signed = await signRequest("https://api.example/me", signer, {
      created: now,
      expires: now + 60,
      nonce: "unsupported-alg-1"
    })
    const headers = new Headers(signed.headers)
    headers.set(
      "signature-input",
      (headers.get("signature-input") ?? "").replace(
        ';tag="erc8128"',
        ';tag="erc8128";alg="eip191"'
      )
    )
    let cryptoChecks = 0
    expect(
      await verifyRequest({
        request: new Request(signed, { headers }),
        nonceStore: new BoundedMemoryNonceStore(),
        policy: { now: () => now },
        verifyMessage: async () => {
          cryptoChecks += 1
          return true
        }
      })
    ).toEqual({ ok: false, reason: "unsupported_algorithm" })
    expect(cryptoChecks).toBe(0)
  })

  test("rejects requests that exceed the shared candidate budget", async () => {
    const requests = await Promise.all(
      Array.from({ length: 9 }, (_, index) =>
        signRequest("https://api.example/many", signer, {
          created: now,
          expires: now + 60,
          label: `candidate${index}`,
          nonce: `candidate-nonce-${index}`
        })
      )
    )
    const headers = new Headers(requests[0]?.headers)
    headers.set(
      "signature-input",
      requests
        .map((request) => request.headers.get("signature-input"))
        .join(", ")
    )
    headers.set(
      "signature",
      requests.map((request) => request.headers.get("signature")).join(", ")
    )
    let cryptoChecks = 0
    expect(
      await verifyRequest({
        request: new Request(requests[0], { headers }),
        nonceStore: new BoundedMemoryNonceStore(),
        policy: { now: () => now },
        verifyMessage: async () => {
          cryptoChecks += 1
          return true
        }
      })
    ).toEqual({ ok: false, reason: "signature_too_large" })
    expect(cryptoChecks).toBe(0)
  })

  test("maps covered-component and signature-parameter overflows to signature_too_large", async () => {
    const componentOverflow = Array.from(
      { length: 33 },
      (_, index) => `"x-component-${index}"`
    ).join(" ")
    const parameterOverflow = Array.from(
      { length: 17 },
      (_, index) => `;vendor${index}`
    ).join("")

    for (const signatureInput of [
      `request=(${componentOverflow});created=${now};expires=${now + 60};keyid="eip155:1:${account.address.toLowerCase()}";tag="erc8128"`,
      `request=("@method");created=${now};expires=${now + 60};keyid="eip155:1:${account.address.toLowerCase()}";tag="erc8128"${parameterOverflow}`
    ]) {
      const request = new Request("https://api.example/limits", {
        headers: {
          signature: "request=:AA==:",
          "signature-input": signatureInput
        }
      })
      const result = await verifyRequest({
        request,
        nonceStore: new BoundedMemoryNonceStore(),
        policy: { now: () => now },
        verifyMessage: universalVerify
      })
      expect(result).toMatchObject({
        ok: false,
        reason: "signature_too_large"
      })
      if (result.ok) throw new Error("Expected an oversized signature.")
      expect(formatErc8128ProblemDetails(result).status).toBe(400)
    }
  })

  test("ignores a foreign well-formed member with an unknown parameter", async () => {
    const signed = await signRequest("https://api.example/coexist", signer, {
      created: now,
      expires: now + 60,
      nonce: "coexisting-signature"
    })
    const headers = new Headers(signed.headers)
    headers.set(
      "signature-input",
      `cdn=("@method");vendor="edge", ${headers.get("signature-input")}`
    )
    headers.set("signature", `cdn=:AA==:, ${headers.get("signature")}`)

    const result = await verifyRequest({
      request: new Request(signed, { headers }),
      nonceStore: new BoundedMemoryNonceStore(),
      policy: { now: () => now },
      verifyMessage: universalVerify
    })
    expect(result.ok).toBe(true)
  })

  test("classifies invalid nonce and request-window failures before nonce use", async () => {
    const nonceStore = {
      consumes: 0,
      async consume() {
        this.consumes += 1
        return true
      }
    }
    const valid = await signRequest("https://api.example/timing", signer, {
      created: now,
      expires: now + 60,
      nonce: "valid-direct-nonce"
    })
    const invalidNonceHeaders = new Headers(valid.headers)
    invalidNonceHeaders.set(
      "signature-input",
      (invalidNonceHeaders.get("signature-input") ?? "").replace(
        'nonce="valid-direct-nonce"',
        'nonce=""'
      )
    )
    const future = await signRequest("https://api.example/timing", signer, {
      created: now + 100,
      expires: now + 160,
      nonce: "future-direct-nonce"
    })
    const expired = await signRequest("https://api.example/timing", signer, {
      created: now - 100,
      expires: now - 40,
      nonce: "expired-direct-nonce"
    })

    for (const [request, reason] of [
      [new Request(valid, { headers: invalidNonceHeaders }), "invalid_nonce"],
      [future, "request_not_yet_valid"],
      [expired, "request_expired"]
    ] as const) {
      const result = await verifyRequest({
        request,
        nonceStore,
        policy: { now: () => now },
        verifyMessage: universalVerify
      })
      expect(result).toMatchObject({ ok: false, reason })
      if (result.ok) throw new Error("Expected request validation failure.")
      expect(formatErc8128ProblemDetails(result).status).toBe(401)
    }
    expect(nonceStore.consumes).toBe(0)
  })

  test("prefers the first unavailable outcome when no candidate succeeds", async () => {
    const first = await signRequest("https://api.example/unavailable", signer, {
      created: now,
      expires: now + 60,
      label: "first",
      nonce: "first-failure-01"
    })
    const second = await signRequest(
      "https://api.example/unavailable",
      secondSigner,
      {
        created: now,
        expires: now + 60,
        label: "second",
        nonce: "second-unavailable"
      }
    )
    const headers = new Headers(first.headers)
    headers.set(
      "signature-input",
      `${first.headers.get("signature-input")}, ${second.headers.get("signature-input")}`
    )
    headers.set(
      "signature",
      `${first.headers.get("signature")}, ${second.headers.get("signature")}`
    )
    expect(
      await verifyRequest({
        request: new Request(first, { headers }),
        nonceStore: new BoundedMemoryNonceStore(),
        policy: { now: () => now },
        verifyMessage: async ({ address }) => {
          if (address.toLowerCase() === secondAccount.address.toLowerCase()) {
            throw new VerificationUnavailableError()
          }
          return false
        }
      })
    ).toEqual({
      ok: false,
      reason: "signature_verification_unavailable"
    })
  })

  test("reconstructs and re-signs direct requests across redirects", async () => {
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

    const response = await signedFetch(
      new Request("https://api.example/start", {
        body: "redirected body",
        headers: { "content-type": "text/plain" },
        method: "POST"
      }),
      signer,
      {
        created: now,
        expires: now + 60,
        fetch: fetchImpl,
        nonce: "direct-redirect-1"
      }
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
    const nonce = (request: Request) =>
      parseSignatureInputHeader(request.headers.get("signature-input") ?? "")[0]
        ?.params.nonce
    expect(nonce(observed[0] as Request)).toBe("direct-redirect-1")
    expect(nonce(observed[1] as Request)).not.toBe("direct-redirect-1")
  })

  test("skips a failing candidate and consumes only the valid candidate nonce", async () => {
    const bad = await signRequest("https://api.example/mixed", signer, {
      created: now,
      expires: now + 60,
      label: "bad",
      nonce: "mixed-bad-nonce-1"
    })
    const good = await signRequest("https://api.example/mixed", signer, {
      created: now,
      expires: now + 60,
      label: "good",
      nonce: "mixed-good-nonce"
    })
    const badSignature = bad.headers.get("signature") ?? ""
    const corruptedBadSignature = badSignature.replace(
      /:([A-Za-z0-9+/])/,
      (_match, first: string) => `:${first === "A" ? "B" : "A"}`
    )
    const headers = new Headers(good.headers)
    headers.set(
      "signature-input",
      `${bad.headers.get("signature-input")}, ${good.headers.get("signature-input")}`
    )
    headers.set(
      "signature",
      `${corruptedBadSignature}, ${good.headers.get("signature")}`
    )
    let nonceConsumes = 0

    const result = await verifyRequest({
      request: new Request(good, { headers }),
      nonceStore: {
        consume: async () => {
          nonceConsumes += 1
          return true
        }
      },
      policy: { now: () => now, principal: "direct" },
      verifyMessage: universalVerify
    })

    expect(result.ok).toBe(true)
    if (!result.ok || result.delegated) throw new Error("unexpected result")
    expect(result.label).toBe("good")
    expect(nonceConsumes).toBe(1)
  })
})
