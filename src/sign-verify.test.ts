import { describe, expect, test } from "bun:test"
import { recoverMessageAddress } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { parseAcceptSignatureHeader } from "./lib/acceptSignature"
import { VerificationUnavailableError } from "./lib/Erc8128Error"
import { createSignatureBaseMinimal } from "./lib/engine/createSignatureBase"
import { parseSignatureInputHeader } from "./lib/engine/createSignatureInput"
import { serializeSignatureHeader } from "./lib/engine/serializations"
import { formatErc8128ProblemDetails } from "./lib/problemDetails"
import { base64Encode, bytesToHex, hexToBytes } from "./lib/utilities"
import { runNonceChecks } from "./lib/verifyUtils"
import { signedFetch, signRequest } from "./sign"
import { BoundedMemoryNonceStore } from "./stores"
import type { VerifyMessageFn, VerifyPolicy } from "./types"
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
}: Parameters<VerifyMessageFn>[0]) =>
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

  test("preserves received legal component-parameter order", async () => {
    const signed = await signRequest(
      new Request("https://api.example/ordered", {
        headers: { "x-dictionary": "a=1" }
      }),
      signer,
      {
        components: [{ name: "x-dictionary", params: { key: "a", sf: true } }],
        created: now,
        expires: now + 60,
        nonce: "ordered-component-params"
      }
    )
    expect(signed.headers.get("signature-input")).toContain(
      '"x-dictionary";key="a";sf'
    )

    const result = await verifyRequest({
      request: signed,
      nonceStore: new BoundedMemoryNonceStore(),
      policy: { now: () => now },
      verifyMessage: universalVerify
    })
    expect(result.ok).toBe(true)
  })

  test("binds significant internal field whitespace", async () => {
    const signed = await signRequest(
      new Request("https://api.example/whitespace", {
        headers: { "x-note": "alpha   beta" }
      }),
      signer,
      {
        components: ["x-note"],
        created: now,
        expires: now + 60,
        nonce: "internal-whitespace"
      }
    )
    const headers = new Headers(signed.headers)
    headers.set("x-note", "alpha beta")
    let nonceConsumes = 0

    expect(
      await verifyRequest({
        request: new Request(signed, { headers }),
        nonceStore: {
          consume: async () => {
            nonceConsumes += 1
            return true
          }
        },
        policy: { now: () => now },
        verifyMessage: universalVerify
      })
    ).toEqual({ ok: false, reason: "bad_signature" })
    expect(nonceConsumes).toBe(0)
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

  test("rebuilds stream bodies from buffered bytes", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("stream payload"))
        controller.close()
      }
    })
    const signed = await signRequest(
      new Request("https://api.example/stream", {
        body,
        method: "POST"
      }),
      signer,
      { created: now, expires: now + 60, nonce: "stream-body-test" }
    )

    expect(await signed.text()).toBe("stream payload")
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

  test("enforces request-bound extras even when class-bound policies exist", async () => {
    const signed = await signRequest("https://api.example/read", signer, {
      binding: "class-bound",
      components: ["@authority"],
      created: now,
      expires: now + 60,
      nonce: "class-bound-extra"
    })

    const missingExtra = await verifyRequest({
      request: signed.clone(),
      nonceStore: new BoundedMemoryNonceStore(),
      policy: {
        additionalRequestBoundComponents: ["x-tenant"],
        classBoundPolicies: ["@authority"],
        now: () => now
      },
      verifyMessage: universalVerify
    })
    const emptyClassPolicy = await verifyRequest({
      request: signed,
      nonceStore: new BoundedMemoryNonceStore(),
      policy: { classBoundPolicies: [], now: () => now },
      verifyMessage: universalVerify
    })

    expect(missingExtra).toEqual({
      ok: false,
      reason: "insufficient_coverage"
    })
    expect(emptyClassPolicy).toEqual({
      ok: false,
      reason: "insufficient_coverage"
    })
  })

  test("advertises unconditional components in class-bound policies", async () => {
    const signed = await signRequest("https://api.example/read", signer, {
      binding: "class-bound",
      components: ["@authority"],
      created: now,
      expires: now + 60,
      nonce: "class-bound-advertisement"
    })
    let acceptSignature = ""

    await verifyRequest({
      request: signed,
      nonceStore: new BoundedMemoryNonceStore(),
      policy: {
        additionalRequestBoundComponents: ["x-tenant"],
        classBoundPolicies: ["@authority"],
        now: () => now
      },
      setHeaders(name, value) {
        if (name.toLowerCase() === "accept-signature") acceptSignature = value
      },
      verifyMessage: universalVerify
    })

    const advertised = parseAcceptSignatureHeader(acceptSignature)
    expect(advertised).toHaveLength(2)
    expect(advertised[1]?.components.map(({ name }) => name)).toEqual([
      "@authority",
      "x-tenant"
    ])
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

  test("classifies unavailable replay storage", async () => {
    const signed = await signRequest(
      "https://api.example/replay-store",
      signer,
      {
        created: now,
        expires: now + 60,
        nonce: "unavailable-replay-store"
      }
    )
    const candidate = parseSignatureInputHeader(
      signed.headers.get("signature-input") ?? ""
    )[0]
    if (candidate === undefined) throw new Error("Signed candidate is missing.")
    expect(
      runNonceChecks({
        allowReplayable: false,
        clockSkewSec: 30,
        maxNonceWindowSec: undefined,
        nonceKey: undefined,
        nonceStore: undefined,
        now,
        params: candidate.params
      }).failure
    ).toMatchObject({
      ok: false,
      reason: "signature_verification_unavailable"
    })

    const fullStore = new BoundedMemoryNonceStore(1)
    await fullStore.consume("occupied", 60)
    expect(
      await verifyRequest({
        request: signed,
        nonceStore: fullStore,
        policy: { now: () => now },
        verifyMessage: universalVerify
      })
    ).toEqual({
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

  test("accepts covered extension signature metadata", async () => {
    const signed = await signRequest("https://api.example/extensions", signer, {
      created: now,
      expires: now + 60,
      nonce: "extension-metadata-1"
    })
    const signatureInput = `${signed.headers.get("signature-input")};vendor="edge"`
    const [candidate] = parseSignatureInputHeader(signatureInput)
    if (candidate === undefined)
      throw new Error("Signature candidate is missing.")
    const signature = await signer.signMessage(
      createSignatureBaseMinimal({
        request: signed,
        components: candidate.components,
        signatureParamsValue: candidate.signatureParamsValue
      })
    )
    const headers = new Headers(signed.headers)
    headers.set("signature-input", signatureInput)
    headers.set(
      "signature",
      serializeSignatureHeader(
        candidate.label,
        base64Encode(hexToBytes(signature))
      )
    )

    expect(
      await verifyRequest({
        request: new Request(signed, { headers }),
        nonceStore: new BoundedMemoryNonceStore(),
        policy: { now: () => now },
        verifyMessage: universalVerify
      })
    ).toMatchObject({ ok: true })
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

  test("does not let foreign member limits mask a valid candidate", async () => {
    const signed = await signRequest("https://api.example/coexist", signer, {
      created: now,
      expires: now + 60,
      nonce: "coexisting-limit-member"
    })
    const components = Array.from(
      { length: 33 },
      (_, index) => `"x-foreign-${index}"`
    ).join(" ")
    const parameters = Array.from(
      { length: 17 },
      (_, index) => `;vendor${index}`
    ).join("")

    for (const foreign of [
      `cdn=(${components})`,
      `cdn=("@method")${parameters}`
    ]) {
      const headers = new Headers(signed.headers)
      headers.set(
        "signature-input",
        `${foreign}, ${headers.get("signature-input")}`
      )
      headers.set("signature", `cdn=:AA==:, ${headers.get("signature")}`)
      expect(
        (
          await verifyRequest({
            request: new Request(signed, { headers }),
            nonceStore: new BoundedMemoryNonceStore(),
            policy: { now: () => now },
            verifyMessage: universalVerify
          })
        ).ok
      ).toBe(true)
    }
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

  test("falls back safely for malformed clock inputs", async () => {
    const expired = await signRequest("https://api.example/timing", signer, {
      created: now - 100_000,
      expires: now - 99_900,
      nonce: "malformed-clock-1"
    })
    const malformedValues = [Number.NaN, "30", new Date()] as const

    for (const value of malformedValues) {
      const badSkew = await verifyRequest({
        request: expired.clone(),
        nonceStore: new BoundedMemoryNonceStore(),
        policy: {
          now: () => now,
          clockSkewSec: value as number
        },
        verifyMessage: universalVerify
      })
      const badNow = await verifyRequest({
        request: expired.clone(),
        nonceStore: new BoundedMemoryNonceStore(),
        policy: { now: (() => value) as () => number },
        verifyMessage: universalVerify
      })
      expect(badSkew).toEqual({ ok: false, reason: "request_expired" })
      expect(badNow).toEqual({ ok: false, reason: "request_expired" })
    }
  })

  test("fails closed for malformed replayable invalidation cutoffs", async () => {
    const replayable = await signRequest(
      "https://api.example/replayable",
      signer,
      { created: now, expires: now + 60, nonce: null }
    )
    for (const value of [Number.NaN, "1", new Date()] as const) {
      const result = await verifyRequest({
        request: replayable.clone(),
        nonceStore: new BoundedMemoryNonceStore(),
        policy: {
          now: () => now,
          replayable: true,
          replayableNotBefore: (async () => value) as () => Promise<number>
        },
        verifyMessage: universalVerify
      })
      expect(result).toEqual({
        ok: false,
        reason: "replayable_not_allowed"
      })
    }
  })

  test("reports malformed per-signature invalidation results as unavailable", async () => {
    const replayable = await signRequest(
      "https://api.example/replayable-invalidated",
      signer,
      { created: now, expires: now + 60, nonce: null }
    )
    for (const value of [undefined, 0] as const) {
      const policy: VerifyPolicy = {
        now: () => now,
        replayable: true
      }
      Object.defineProperty(policy, "replayableInvalidated", {
        value: async () => value
      })
      const result = await verifyRequest({
        request: replayable.clone(),
        nonceStore: new BoundedMemoryNonceStore(),
        policy,
        verifyMessage: universalVerify
      })
      expect(result).toEqual({
        ok: false,
        reason: "signature_verification_unavailable"
      })
    }
  })

  test("reports replayable invalidation backend failures as unavailable", async () => {
    const replayable = await signRequest(
      "https://api.example/replayable-unavailable",
      signer,
      { created: now, expires: now + 60, nonce: null }
    )
    const result = await verifyRequest({
      request: replayable,
      nonceStore: new BoundedMemoryNonceStore(),
      policy: {
        now: () => now,
        replayable: true,
        replayableNotBefore: async () => {
          throw new Error("Unavailable")
        }
      },
      verifyMessage: universalVerify
    })

    expect(result).toEqual({
      ok: false,
      reason: "signature_verification_unavailable"
    })
    if (result.ok) throw new Error("Expected verification to be unavailable.")
    expect(formatErc8128ProblemDetails(result).status).toBe(503)
  })

  test("returns a controlled failure for invalid required-header policies", async () => {
    const signed = await signRequest(
      "https://api.example/invalid-policy",
      signer,
      {
        created: now,
        expires: now + 60,
        nonce: "invalid-required-header"
      }
    )
    const result = await verifyRequest({
      request: signed,
      nonceStore: new BoundedMemoryNonceStore(),
      policy: {
        now: () => now,
        requiredCoveredHeadersWhenPresent: ["@query"]
      },
      verifyMessage: universalVerify
    })

    expect(result).toMatchObject({
      ok: false,
      reason: "signature_verification_unavailable"
    })
  })

  test("rejects non-finite optional verification limits", async () => {
    const signed = await signRequest(
      "https://api.example/invalid-limits",
      signer,
      {
        created: now,
        expires: now + 60,
        nonce: "invalid-policy-limit"
      }
    )
    const policies: VerifyPolicy[] = [
      { maxNonceWindowSec: Number.NaN },
      {
        delegation: {
          maxGrantValiditySec: Number.POSITIVE_INFINITY,
          verifyStatuses: () => []
        }
      },
      {
        delegation: {
          grantCacheTtlSec: Number.NaN,
          verifyStatuses: () => []
        }
      }
    ]

    for (const policy of policies) {
      expect(
        await verifyRequest({
          request: signed.clone(),
          nonceStore: new BoundedMemoryNonceStore(),
          policy: { ...policy, now: () => now },
          verifyMessage: universalVerify
        })
      ).toMatchObject({
        ok: false,
        reason: "signature_verification_unavailable"
      })
    }
  })

  test("defaults the account verification budget to two plus chain depth", async () => {
    const requests = await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        signRequest("https://api.example/candidates", signer, {
          created: now,
          expires: now + 60,
          label: `candidate${index}`,
          nonce: `budget-candidate-${index}`
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
    let calls = 0
    const result = await verifyRequest({
      request: new Request(requests[0], { headers }),
      nonceStore: new BoundedMemoryNonceStore(),
      policy: { now: () => now },
      verifyMessage: async () => {
        calls += 1
        return false
      }
    })

    expect(result).toEqual({
      ok: false,
      reason: "signature_verification_unavailable"
    })
    expect(calls).toBe(6)
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

  test("signs once and delegates redirects to fetch", async () => {
    const observed: Request[] = []
    let signatures = 0
    const countingSigner = {
      ...signer,
      signMessage: async (message: Uint8Array) => {
        signatures += 1
        return signer.signMessage(message)
      }
    }
    const fetchImpl: typeof fetch = Object.assign(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const request =
          input instanceof Request ? input : new Request(input, init)
        observed.push(request.clone())
        return new Response(null, {
          headers: { location: "https://next.example/continued" },
          status: 307
        })
      },
      { preconnect: () => {} }
    )

    const response = await signedFetch(
      new Request("https://api.example/start", {
        body: "redirected body",
        headers: { "content-type": "text/plain" },
        method: "POST",
        redirect: "follow"
      }),
      countingSigner,
      {
        created: now,
        expires: now + 60,
        fetch: fetchImpl,
        nonce: "direct-redirect-1"
      }
    )

    expect(response.status).toBe(307)
    expect(signatures).toBe(1)
    expect(observed).toHaveLength(1)
    expect(observed[0]?.url).toBe("https://api.example/start")
    expect(observed[0]?.redirect).toBe("follow")
    expect(await observed[0]?.text()).toBe("redirected body")
    expect(
      parseSignatureInputHeader(
        observed[0]?.headers.get("signature-input") ?? ""
      )[0]?.params.nonce
    ).toBe("direct-redirect-1")
  })

  test("preserves native redirect modes", async () => {
    const observed: Request[] = []
    const fetchImpl: typeof fetch = Object.assign(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const request =
          input instanceof Request ? input : new Request(input, init)
        observed.push(request.clone())
        return new Response(null, { status: 204 })
      },
      { preconnect: () => {} }
    )

    for (const redirect of ["follow", "manual", "error"] as const) {
      await signedFetch(
        new Request(`https://api.example/${redirect}`, { redirect }),
        signer,
        { fetch: fetchImpl }
      )
    }

    expect(observed.map(({ redirect }) => redirect)).toEqual([
      "follow",
      "manual",
      "error"
    ])
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
