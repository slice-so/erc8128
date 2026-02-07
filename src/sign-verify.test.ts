import { describe, expect, test } from "bun:test"
import { createPublicClient, http } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { Erc8128Error, signRequest, verifyRequest } from "./index.js"
import type { Address, Hex, VerifyPolicy } from "./lib/types.js"

const publicClient = createPublicClient({
  transport: http("http://localhost:8787")
})

function makeSigner(args?: { chainId?: number }) {
  const chainId = args?.chainId ?? 1
  // Fixed key for deterministic test vectors.
  const privateKeyHex =
    "0x0123456789012345678901234567890123456789012345678901234567890123"
  const account = privateKeyToAccount(privateKeyHex)

  return {
    chainId,
    address: account.address as Address,
    signMessage: async (message: Uint8Array) => {
      return account.signMessage({ message: { raw: message } })
    }
  }
}

function makeVerifyMessage() {
  return async (args: {
    address: Address
    message: { raw: Hex }
    signature: Hex
  }) => {
    return publicClient.verifyMessage(args)
  }
}

function makeNonceStore() {
  const seen = new Set<string>()
  return {
    consume: async (key: string) => {
      if (seen.has(key)) return false
      seen.add(key)
      return true
    }
  }
}

function verifyWithPolicy(
  request: Request,
  policy: VerifyPolicy = {},
  deps?: {
    verifyMessage?: ReturnType<typeof makeVerifyMessage>
    nonceStore?: ReturnType<typeof makeNonceStore>
  }
) {
  const verifyMessage = deps?.verifyMessage ?? makeVerifyMessage()
  const nonceStore = deps?.nonceStore ?? makeNonceStore()
  return verifyRequest(request, verifyMessage, nonceStore, policy)
}

async function sha256B64(bytes: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes))
  return Buffer.from(hash).toString("base64")
}

describe("EIP-8128 signRequest/verifyRequest", () => {
  test("round-trips request-bound POST (auto content-digest, non-replayable nonce), -- test", async () => {
    const signer = makeSigner({ chainId: 1 })
    const created = 1_700_000_000
    const expires = created + 60
    const verifyMessage = makeVerifyMessage()

    const req = new Request("https://example.com/api/v1/hello?x=1", {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "hello"
    })

    const signed = await signRequest(req, signer, {
      created,
      expires,
      nonce: "nonce-1"
    })

    expect(signed).not.toBe(req)

    // Content-Digest
    const cd = signed.headers.get("content-digest")
    expect(cd).toBe(
      `sha-256=:${await sha256B64(new TextEncoder().encode("hello"))}:`
    )

    // Signature headers
    const sigInput = signed.headers.get("Signature-Input")
    const sig = signed.headers.get("Signature")
    expect(sigInput).toMatch(
      /^eth=\(.+\);created=\d+;expires=\d+;nonce="[^"]+";keyid="erc8128:\d+:0x[0-9a-f]{40}"$/
    )
    expect(sig).toMatch(/^eth=:[A-Za-z0-9+/]+={0,2}:$/)

    const nonceStore = makeNonceStore()
    const res = await verifyWithPolicy(
      signed,
      { now: () => created },
      { verifyMessage, nonceStore }
    )
    expect(res.ok).toBe(true)
    if (!res.ok) throw new Error("unreachable")
    expect(res.address.toLowerCase()).toBe(signer.address.toLowerCase())
    expect(res.chainId).toBe(1)
    expect(res.params.nonce).toBe("nonce-1")
    expect(res.replayable).toBe(false)
    expect(res.binding).toBe("request-bound")
  })

  test("request-bound signatures include required components for query/body", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60

    const signed = await signRequest(
      "https://example.com/needs?x=1",
      { method: "POST", body: "hi" },
      signer,
      { created, expires, nonce: "nonce-components" }
    )

    const sigInput = signed.headers.get("Signature-Input")
    expect(sigInput).toBeTruthy()
    if (!sigInput) throw new Error("unreachable")
    expect(sigInput).toContain('"@authority"')
    expect(sigInput).toContain('"@method"')
    expect(sigInput).toContain('"@path"')
    expect(sigInput).toContain('"@query"')
    expect(sigInput).toContain('"content-digest"')
  })

  test("request-bound signatures can include extra header components", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60
    const verifyMessage = makeVerifyMessage()

    const req = new Request("https://example.com/extra", {
      method: "GET",
      headers: {
        "content-type": "text/plain",
        "x-scope": "alpha"
      }
    })

    const signed = await signRequest(req, signer, {
      created,
      expires,
      nonce: "nonce-extra",
      components: ["content-type", "x-scope"]
    })

    const sigInput = signed.headers.get("Signature-Input")
    expect(sigInput).toBeTruthy()
    if (!sigInput) throw new Error("unreachable")
    expect(sigInput).toContain('"@authority"')
    expect(sigInput).toContain('"@method"')
    expect(sigInput).toContain('"@path"')
    expect(sigInput).toContain('"content-type"')
    expect(sigInput).toContain('"x-scope"')

    const nonceStore = makeNonceStore()
    const res = await verifyWithPolicy(
      signed,
      { now: () => created },
      { verifyMessage, nonceStore }
    )
    expect(res.ok).toBe(true)
  })

  test("default signing options set label/nonce and created/expires window", async () => {
    const signer = makeSigner()

    const signed = await signRequest(
      "https://example.com/defaults",
      { method: "GET" },
      signer
    )

    const sigInput = signed.headers.get("Signature-Input")
    const sig = signed.headers.get("Signature")
    expect(sigInput).toBeTruthy()
    expect(sig).toBeTruthy()
    if (!sigInput || !sig) throw new Error("unreachable")

    expect(sigInput.startsWith("eth=")).toBe(true)
    expect(sig).toMatch(/^eth=:[A-Za-z0-9+/]+={0,2}:$/)
    expect(sigInput).toMatch(/;nonce="[^"]+"/)
    const m = sigInput.match(/created=(\d+);expires=(\d+)/)
    expect(m).toBeTruthy()
    if (!m) throw new Error("unreachable")
    const created = Number(m[1])
    const expires = Number(m[2])
    expect(expires - created).toBe(60)
  })

  test("non-replayable signatures always include a nonce", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60

    const signed = await signRequest(
      "https://example.com/nonce-auto",
      { method: "GET" },
      signer,
      { created, expires, replay: "non-replayable" }
    )

    const sigInput = signed.headers.get("Signature-Input")
    expect(sigInput).toBeTruthy()
    if (!sigInput) throw new Error("unreachable")
    expect(sigInput).toMatch(/;nonce="[^"]+"/)
  })

  test("fails on invalid signer (empty signature)", async () => {
    const badSigner = {
      chainId: 1,
      address: "0x0000000000000000000000000000000000000000" as Address,
      signMessage: async () => "0x" as Hex
    }

    expect(
      signRequest(
        "https://example.com/bad-signer",
        { method: "GET" },
        badSigner
      )
    ).rejects.toBeInstanceOf(Erc8128Error)
  })

  test("fails on invalid request url", async () => {
    const signer = makeSigner()
    expect(
      signRequest("not a url", { method: "GET" }, signer)
    ).rejects.toBeInstanceOf(Error)
  })

  test("detects replay when using same nonce + nonceStore twice", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60
    const nonceStore = makeNonceStore()
    const verifyMessage = makeVerifyMessage()

    const signed = await signRequest(
      "https://example.com/replay",
      { method: "GET" },
      signer,
      { created, expires, nonce: "nonce-replay" }
    )

    const ok1 = await verifyWithPolicy(
      signed,
      { now: () => created },
      { verifyMessage, nonceStore }
    )
    expect(ok1.ok).toBe(true)

    const ok2 = await verifyWithPolicy(
      signed,
      { now: () => created },
      { verifyMessage, nonceStore }
    )
    expect(ok2).toEqual({ ok: false, reason: "replay" })
  })

  test("replayable signatures are rejected by default, but can be allowed by policy", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60
    const verifyMessage = makeVerifyMessage()

    const signed = await signRequest(
      "https://example.com/replayable",
      { method: "GET" },
      signer,
      { created, expires, replay: "replayable" }
    )

    const resDefault = await verifyWithPolicy(
      signed,
      { now: () => created },
      { verifyMessage }
    )
    expect(resDefault).toEqual({ ok: false, reason: "replayable_not_allowed" })

    const resAllowed = await verifyWithPolicy(
      signed,
      { now: () => created, replayable: true },
      { verifyMessage }
    )
    expect(resAllowed.ok).toBe(true)
  })

  test("label selection: strictLabel enforces the configured label", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60
    const verifyMessage = makeVerifyMessage()

    const signed = await signRequest(
      "https://example.com/labels",
      { method: "GET" },
      signer,
      { created, expires, nonce: "nonce-label", label: "foo" }
    )

    // Default policy label is "eth", but strictLabel=false allows choosing first label.
    const nonceStore = makeNonceStore()
    const res1 = await verifyWithPolicy(
      signed,
      { now: () => created },
      { verifyMessage, nonceStore }
    )
    expect(res1.ok).toBe(true)

    const res2 = await verifyWithPolicy(
      signed,
      { now: () => created, label: "eth", strictLabel: true },
      { verifyMessage, nonceStore: makeNonceStore() }
    )
    expect(res2).toEqual({ ok: false, reason: "label_not_found" })
  })

  test("verification attempts multiple signatures and succeeds on a later member", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60
    const verifyMessage = makeVerifyMessage()

    const signed = await signRequest(
      "https://example.com/fallback",
      { method: "GET" },
      signer,
      { created, expires, nonce: "nonce-fallback", label: "good" }
    )

    const goodSigInput = signed.headers.get("Signature-Input")
    const goodSig = signed.headers.get("Signature")
    expect(goodSigInput).toBeTruthy()
    expect(goodSig).toBeTruthy()
    if (!goodSigInput || !goodSig) throw new Error("unreachable")

    // Prepend a valid-looking member with a bad signature; verifier should fall through to "good".
    const badMember = goodSigInput.replace(/^good=/, "bad=")
    const badSig = `bad=:AA==:`

    const headers = new Headers(signed.headers)
    headers.set("Signature-Input", `${badMember}, ${goodSigInput}`)
    headers.set("Signature", `${badSig}, ${goodSig}`)
    const augmented = new Request(signed, { headers })

    const res = await verifyWithPolicy(
      augmented,
      { now: () => created },
      { verifyMessage, nonceStore: makeNonceStore() }
    )
    expect(res.ok).toBe(true)
    if (!res.ok) throw new Error("unreachable")
    expect(res.label).toBe("good")

    const limited = await verifyWithPolicy(
      augmented,
      { now: () => created, maxSignatureVerifications: 1 },
      { verifyMessage, nonceStore: makeNonceStore() }
    )
    expect(limited).toEqual({ ok: false, reason: "bad_signature" })
  })

  test("signature selection respects Signature-Input order across bindings", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60
    const verifyMessage = makeVerifyMessage()

    const classBound = await signRequest(
      "https://example.com/order",
      { method: "GET" },
      signer,
      {
        binding: "class-bound",
        components: ["@authority"],
        created,
        expires,
        nonce: "nonce-class",
        label: "class"
      }
    )

    const combined = await signRequest(classBound, signer, {
      created,
      expires,
      nonce: "nonce-request",
      label: "request",
      headerMode: "append"
    })

    const res = await verifyWithPolicy(
      combined,
      { now: () => created, classBoundPolicies: ["@authority"] },
      { verifyMessage, nonceStore: makeNonceStore() }
    )
    expect(res.ok).toBe(true)
    if (!res.ok) throw new Error("unreachable")
    expect(res.label).toBe("class")
    expect(res.binding).toBe("class-bound")
  })

  test("class-bound verification accepts any matching policy in a list", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60
    const verifyMessage = makeVerifyMessage()

    const signed = await signRequest(
      "https://example.com/class-bound-policies",
      { method: "GET" },
      signer,
      {
        binding: "class-bound",
        components: ["@authority", "@path"],
        created,
        expires,
        nonce: "nonce-class"
      }
    )

    const res = await verifyWithPolicy(
      signed,
      {
        now: () => created,
        classBoundPolicies: [
          ["@authority", "@method"],
          ["@authority", "@path"]
        ]
      },
      { verifyMessage, nonceStore: makeNonceStore() }
    )
    expect(res.ok).toBe(true)
    if (!res.ok) throw new Error("unreachable")
    expect(res.binding).toBe("class-bound")
    expect(res.replayable).toBe(false)
  })

  test("headerMode=append appends a second signature label and verifier can target it", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60
    const verifyMessage = makeVerifyMessage()

    const once = await signRequest(
      "https://example.com/append",
      { method: "GET" },
      signer,
      { created, expires, nonce: "nonce-1", label: "a" }
    )

    const twice = await signRequest(once, signer, {
      created,
      expires,
      nonce: "nonce-2",
      label: "b",
      headerMode: "append"
    })

    expect(twice.headers.get("Signature-Input")).toContain("a=")
    expect(twice.headers.get("Signature-Input")).toContain("b=")
    expect(twice.headers.get("Signature")).toContain("a=")
    expect(twice.headers.get("Signature")).toContain("b=")

    const nonceStore = makeNonceStore()
    const res = await verifyWithPolicy(
      twice,
      { now: () => created, label: "b", strictLabel: true },
      { verifyMessage, nonceStore }
    )
    expect(res.ok).toBe(true)
    if (!res.ok) throw new Error("unreachable")
    expect(res.label).toBe("b")
  })

  test("verifier selects requested label when multiple signatures exist", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60
    const verifyMessage = makeVerifyMessage()

    const signedA = await signRequest(
      "https://example.com/multi",
      { method: "GET" },
      signer,
      { created, expires, nonce: "nonce-a", label: "a" }
    )

    const signedAB = await signRequest(signedA, signer, {
      created,
      expires,
      nonce: "nonce-b",
      label: "b",
      headerMode: "append"
    })

    const res = await verifyWithPolicy(
      signedAB,
      { now: () => created, label: "a", strictLabel: true },
      { verifyMessage, nonceStore: makeNonceStore() }
    )
    expect(res.ok).toBe(true)
    if (!res.ok) throw new Error("unreachable")
    expect(res.label).toBe("a")
  })

  test("digest_required vs digest_mismatch", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60
    const verifyMessage = makeVerifyMessage()

    const signed = await signRequest(
      "https://example.com/digest",
      { method: "POST", body: "hello" },
      signer,
      { created, expires, nonce: "nonce-digest" }
    )

    // 1) Missing content-digest header
    const headersMissing = new Headers(signed.headers)
    headersMissing.delete("content-digest")
    const missing = new Request(signed, { headers: headersMissing })

    const resMissing = await verifyWithPolicy(
      missing,
      { now: () => created },
      { verifyMessage, nonceStore: makeNonceStore() }
    )
    expect(resMissing).toEqual({ ok: false, reason: "digest_required" })

    // 2) Body tampered but header preserved
    const tampered = new Request(signed.url, {
      method: signed.method,
      headers: signed.headers,
      body: "bye"
    })
    const resTampered = await verifyWithPolicy(
      tampered,
      { now: () => created },
      { verifyMessage, nonceStore: makeNonceStore() }
    )
    expect(resTampered).toEqual({ ok: false, reason: "digest_mismatch" })
  })

  test("bad keyid when no compliant member exists", async () => {
    const req = new Request("https://example.com/keyid", {
      method: "GET",
      headers: {
        "Signature-Input":
          'sig=("@authority");created=1700000000;expires=1700000060;keyid="not-erc8128:1:0x0000000000000000000000000000000000000000"',
        Signature: "sig=:AA==:"
      }
    })

    const res = await verifyWithPolicy(req, { now: () => 1 })
    expect(res).toEqual({ ok: false, reason: "bad_keyid" })
  })

  test("time checks: not_yet_valid, expired, validity_too_long", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60

    const signed = await signRequest(
      "https://example.com/time-cases",
      { method: "GET" },
      signer,
      { created, expires, nonce: "nonce-time-cases" }
    )

    const notYet = await verifyWithPolicy(signed, { now: () => created - 10 })
    expect(notYet).toEqual({ ok: false, reason: "not_yet_valid" })

    const expired = await verifyWithPolicy(signed, { now: () => expires + 1 })
    expect(expired).toEqual({ ok: false, reason: "expired" })

    const signedLong = await signRequest(
      "https://example.com/time-long",
      { method: "GET" },
      signer,
      { created, expires: created + 1000, nonce: "nonce-long" }
    )
    const longRes = await verifyWithPolicy(signedLong, { now: () => created })
    expect(longRes).toEqual({ ok: false, reason: "validity_too_long" })
  })

  test("nonce window enforcement", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60

    const signed = await signRequest(
      "https://example.com/nonce-edges",
      { method: "GET" },
      signer,
      { created, expires, nonce: "nonce-edge" }
    )

    const windowTooLong = await verifyWithPolicy(signed, {
      now: () => created,
      maxNonceWindowSec: 10
    })
    expect(windowTooLong).toEqual({
      ok: false,
      reason: "nonce_window_too_long"
    })
  })

  test("rejects when signed components don't match request shape", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60

    const signedQuery = await signRequest(
      "https://example.com/components?x=1",
      { method: "GET" },
      signer,
      { created, expires, nonce: "nonce-query" }
    )
    const sigInputQuery = signedQuery.headers.get("Signature-Input")
    expect(sigInputQuery).toBeTruthy()
    if (!sigInputQuery) throw new Error("unreachable")
    const withoutQuery = sigInputQuery.replace(' "@query"', "")
    const headersQuery = new Headers(signedQuery.headers)
    headersQuery.set("Signature-Input", withoutQuery)
    const tamperedQuery = new Request(signedQuery, { headers: headersQuery })

    const resQuery = await verifyWithPolicy(tamperedQuery, {
      now: () => created
    })
    expect(resQuery).toEqual({ ok: false, reason: "not_request_bound" })

    const signedBody = await signRequest(
      "https://example.com/components",
      { method: "POST", body: "hi" },
      signer,
      { created, expires, nonce: "nonce-body" }
    )
    const sigInputBody = signedBody.headers.get("Signature-Input")
    expect(sigInputBody).toBeTruthy()
    if (!sigInputBody) throw new Error("unreachable")
    const withoutDigest = sigInputBody.replace(' "content-digest"', "")
    const headersBody = new Headers(signedBody.headers)
    headersBody.set("Signature-Input", withoutDigest)
    const tamperedBody = new Request(signedBody, { headers: headersBody })

    const resBody = await verifyWithPolicy(tamperedBody, { now: () => created })
    expect(resBody).toEqual({ ok: false, reason: "not_request_bound" })
  })

  test("malformed Signature-Input/Signature returns bad_signature_input (non-throwing)", async () => {
    const req = new Request("https://example.com/bad", {
      method: "GET",
      headers: {
        "Signature-Input": "not-a-dictionary",
        Signature: "eth=:aaaa:"
      }
    })

    const res = await verifyWithPolicy(req, { now: () => 1 })
    expect(res.ok).toBe(false)
    if (res.ok) throw new Error("unreachable")
    expect(res.reason).toBe("bad_signature_input")
  })

  test("class-bound requires explicit components; verifier rejects class-bound by default", async () => {
    const signer = makeSigner()
    const verifyMessage = makeVerifyMessage()

    await expect(
      signRequest(
        "https://example.com/class-bound",
        { method: "GET" },
        signer,
        { binding: "class-bound" }
      )
    ).rejects.toBeInstanceOf(Erc8128Error)

    const created = 1_700_000_000
    const expires = created + 60
    const signed = await signRequest(
      "https://example.com/class-bound",
      { method: "GET" },
      signer,
      {
        binding: "class-bound",
        components: ["@authority"], // minimal class-bound
        created,
        expires,
        replay: "replayable"
      }
    )

    const resDefault = await verifyWithPolicy(signed, {
      now: () => created
    })
    expect(resDefault).toEqual({ ok: false, reason: "not_request_bound" })

    const resAllowed = await verifyWithPolicy(
      signed,
      {
        now: () => created,
        classBoundPolicies: ["@authority"],
        replayable: true
      },
      { verifyMessage }
    )
    expect(resAllowed.ok).toBe(true)
    if (!resAllowed.ok) throw new Error("unreachable")
    expect(resAllowed.binding).toBe("class-bound")
    expect(resAllowed.replayable).toBe(true)
  })

  test("bad_time is enforced before signature verification", async () => {
    const signer = makeSigner()
    const created = 1_700_000_000
    const expires = created + 60

    const signed = await signRequest(
      "https://example.com/time",
      { method: "GET" },
      signer,
      { created, expires, nonce: "nonce-time" }
    )

    const sigInput = signed.headers.get("Signature-Input")
    expect(sigInput).toBeTruthy()
    if (!sigInput) throw new Error("unreachable")

    // Make expires <= created (invalid), without changing Signature header (doesn't matter: time check happens first)
    const tamperedInput = sigInput.replace(
      `;expires=${expires}`,
      `;expires=${created}`
    )
    const headers = new Headers(signed.headers)
    headers.set("Signature-Input", tamperedInput)
    const tampered = new Request(signed, { headers })

    const res = await verifyWithPolicy(
      tampered,
      { now: () => created },
      { nonceStore: makeNonceStore() }
    )
    expect(res).toEqual({ ok: false, reason: "bad_time" })
  })
})
