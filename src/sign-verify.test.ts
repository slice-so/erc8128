import { describe, expect, test } from "bun:test"
import { recoverMessageAddress } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { VerificationUnavailableError } from "./lib/Erc8128Error"
import { bytesToHex } from "./lib/utilities"
import { signRequest } from "./sign"
import { BoundedMemoryNonceStore } from "./stores"
import { verifyRequest } from "./verify"

const account = privateKeyToAccount(`0x${"11".repeat(32)}`)
const now = Math.floor(Date.now() / 1_000)
const signer = {
  address: account.address,
  chainId: 1,
  signMessage: (message: Uint8Array) =>
    account.signMessage({ message: { raw: bytesToHex(message) } })
}

const universalVerify = async ({
  address,
  message,
  signature
}: Parameters<import("./types").VerifyMessageFn>[0]) =>
  (await recoverMessageAddress({ message, signature })).toLowerCase() ===
  address.toLowerCase()

describe("ERC-8128 direct signing and verification", () => {
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
    if (!result.ok) throw new Error("unreachable")
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
    ).resolves.toEqual({ ok: false, reason: "digest_mismatch" })
  })

  test("covers the digest and content type for received empty content", async () => {
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
    expect(signatureInput).toContain('"content-digest"')
    expect(signatureInput).toContain('"content-type"')
    expect(signed.headers.get("content-digest")).toBeTruthy()
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
      new Request("https://api.example/write", {
        body: "received",
        method: "POST"
      }),
      signer,
      { ...classBoundOptions, nonce: "class-bound-body" }
    )

    for (const request of [injectedType, signedWithoutDigest]) {
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
    ).toEqual({ ok: false, reason: "tag_not_found" })
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
    if (!result.ok) throw new Error(result.reason)
    expect(result.label).toBe("good")
    expect(nonceConsumes).toBe(1)
  })
})
