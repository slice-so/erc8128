import { expect, test } from "bun:test"
import { type Hex, hashMessage } from "viem"
import fixture from "../conformance-vectors.json"
import { createSignatureBaseMinimal } from "./lib/engine/createSignatureBase"
import {
  parseSignatureHeader,
  parseSignatureInputHeader
} from "./lib/engine/createSignatureInput"
import { base64Decode, bytesToHex } from "./lib/utilities"
import { BoundedMemoryNonceStore } from "./stores"
import { verifyRequest } from "./verify"

test("verifies the updated direct conformance vector", async () => {
  const vector = fixture.vectors[0]
  if (vector === undefined) throw new Error("Direct vector is missing.")
  const request = new Request(vector.request.url, {
    body: vector.request.body,
    headers: vector.request.headers,
    method: vector.request.method
  })
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

  const result = await verifyRequest({
    request,
    nonceStore: new BoundedMemoryNonceStore(),
    policy: {
      accountVerification: "eoa-only",
      clockSkewSec: 30,
      now: () => 1_700_000_001,
      principal: "direct"
    },
    verifyMessage: () => false
  })
  expect(result).toMatchObject({
    ok: true,
    delegated: false,
    principal: { address: vector.expected.principal, chainId: 1 },
    signer: { address: vector.expected.signer, chainId: 1 },
    binding: "request-bound"
  })
})
