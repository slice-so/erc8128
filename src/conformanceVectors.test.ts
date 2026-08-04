import { describe, expect, test } from "bun:test"
import { type Hex, hashMessage } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import fixture from "../conformance-vectors.json"
import { createSignatureBaseMinimal } from "./lib/engine/createSignatureBase"
import {
  parseSignatureHeader,
  parseSignatureInputHeader
} from "./lib/engine/createSignatureInput"
import { createUniversalAccountVerifier } from "./lib/universalAccountVerification"
import { base64Decode, bytesToHex } from "./lib/utilities"
import { signRequest } from "./sign"
import { BoundedMemoryNonceStore } from "./stores"
import type { NonceStore, VerifyPolicy } from "./types"
import { verifyRequest } from "./verify"

const vector = fixture.vectors[0]
if (vector === undefined) throw new Error("Direct vector is missing.")

const vectorRequest = (url = vector.request.url) =>
  new Request(url, {
    body: vector.request.body,
    headers: vector.request.headers,
    method: vector.request.method
  })

const universalNoCodeVerify = createUniversalAccountVerifier({
  getCode: async () => "0x" as const,
  verifySmartAccount: async () => false
})

const verifyDirect = (
  request: Request,
  nonceStore: NonceStore = new BoundedMemoryNonceStore(),
  policy: VerifyPolicy = {}
) =>
  verifyRequest({
    request,
    nonceStore,
    policy: {
      clockSkewSec: 30,
      now: () => 1_700_000_001,
      principal: "direct",
      ...policy
    },
    verifyMessage: universalNoCodeVerify
  })

test("verifies the updated direct conformance vector", async () => {
  const request = vectorRequest()
  const candidate = parseSignatureInputHeader(
    vector.request.headers["signature-input"]
  )[0]
  if (candidate === undefined) throw new Error("Direct candidate is missing.")
  const base = createSignatureBaseMinimal({
    request,
    components: candidate.components,
    signatureParamsValue: candidate.signatureParamsValue
  })
  expect(new TextDecoder().decode(base)).toBe(
    vector.requestSignature.signatureBase
  )
  expect(hashMessage({ raw: bytesToHex(base) })).toBe(
    vector.requestSignature.eip191Hash as Hex
  )
  const signature = parseSignatureHeader(vector.request.headers.signature).get(
    candidate.label
  )
  expect(bytesToHex(base64Decode(signature ?? "") ?? new Uint8Array())).toBe(
    vector.requestSignature.signature as Hex
  )

  const result = await verifyDirect(request)
  expect(result).toMatchObject({
    ok: true,
    delegated: false,
    principal: { address: vector.expected.principal, chainId: 1 },
    signer: { address: vector.expected.signer, chainId: 1 },
    binding: "request-bound"
  })
})

describe("direct conformance classifications", () => {
  test("atomically admits exactly one concurrent submission", async () => {
    const store = new BoundedMemoryNonceStore()
    const results = await Promise.all(
      Array.from({ length: 16 }, () => verifyDirect(vectorRequest(), store))
    )
    expect(results.filter(({ ok }) => ok)).toHaveLength(1)
    expect(
      results.filter((result) => !result.ok && result.reason === "nonce_reused")
    ).toHaveLength(15)
  })

  test("rejects a sequential second submission as nonce_reused", async () => {
    const store = new BoundedMemoryNonceStore()
    expect((await verifyDirect(vectorRequest(), store)).ok).toBe(true)
    expect(await verifyDirect(vectorRequest(), store)).toEqual({
      ok: false,
      reason: "nonce_reused"
    })
  })

  test("classifies direct-profile local policy failures before cryptography", async () => {
    const mutate = (update: (headers: Headers) => void) => {
      const request = vectorRequest()
      const headers = new Headers(request.headers)
      update(headers)
      return new Request(request, { headers })
    }
    const signatureInput = () => vector.request.headers["signature-input"]
    const cases: readonly [Request, string, VerifyPolicy?][] = [
      [
        mutate((headers) =>
          headers.set(
            "signature-input",
            signatureInput().replace(
              /keyid="[^"]+"/,
              'keyid="eip155:01:0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"'
            )
          )
        ),
        "invalid_keyid"
      ],
      [
        mutate((headers) =>
          headers.set(
            "signature-input",
            signatureInput().replace(
              "created=1700000000",
              "created=1700000000.0"
            )
          )
        ),
        "invalid_time"
      ],
      [
        mutate((headers) =>
          headers.set(
            "signature-input",
            signatureInput().replace("expires=1700000060", "expires=1700000400")
          )
        ),
        "request_validity_too_long",
        { maxValiditySec: 60 }
      ],
      [
        mutate((headers) =>
          headers.set(
            "signature-input",
            signatureInput().replace(' "@query"', "")
          )
        ),
        "insufficient_coverage"
      ],
      [
        mutate((headers) => headers.delete("content-digest")),
        "content_digest_required"
      ],
      [vectorRequest(), "principal_not_allowed", { principal: "delegated" }]
    ]

    for (const [request, reason, policy] of cases) {
      expect(
        await verifyDirect(request, new BoundedMemoryNonceStore(), policy)
      ).toMatchObject({
        ok: false,
        reason
      })
    }
  })

  test("distinguishes nonce_required from replayable_not_allowed", async () => {
    const account = privateKeyToAccount(
      "0x0000000000000000000000000000000000000000000000000000000000000001"
    )
    const replayable = await signRequest(
      "https://api.example/replayable",
      {
        address: account.address,
        chainId: 1,
        signMessage: (message) =>
          account.signMessage({ message: { raw: message } })
      },
      {
        created: 1_700_000_000,
        expires: 1_700_000_060,
        nonce: null
      }
    )

    expect(await verifyDirect(replayable.clone())).toEqual({
      ok: false,
      reason: "nonce_required"
    })
    expect(
      await verifyDirect(replayable.clone(), new BoundedMemoryNonceStore(), {
        replayable: true
      })
    ).toEqual({ ok: false, reason: "replayable_not_allowed" })
  })

  test("does not consume the nonce when a changed query has a bad signature", async () => {
    const store = new BoundedMemoryNonceStore()
    expect(
      await verifyDirect(
        vectorRequest("https://api.example/items?view=changed"),
        store
      )
    ).toEqual({ ok: false, reason: "bad_signature" })
    expect((await verifyDirect(vectorRequest(), store)).ok).toBe(true)
  })
})
