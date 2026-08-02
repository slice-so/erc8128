import { expect, test } from "bun:test"
import {
  type Address,
  type Hex,
  hashMessage,
  recoverMessageAddress
} from "viem"
import fixture from "../conformance-vectors.json"
import { getDelegationGrantSignatureBase } from "./lib/delegation/createDelegationGrant"
import { createSignatureBaseMinimal } from "./lib/engine/createSignatureBase"
import {
  parseSignatureHeader,
  parseSignatureInputHeader
} from "./lib/engine/createSignatureInput"
import { base64Decode, bytesToHex } from "./lib/utilities"
import { BoundedMemoryNonceStore } from "./stores"
import { verifyRequest } from "./verify"

type ConformanceVector = {
  id: string
  kind: "direct" | "delegated"
  request: {
    method: string
    url: string
    headers: Record<string, string>
    body?: string
  }
  requestSignature: {
    label: string
    signatureBase: string
    eip191Hash: Hex
    signature: Hex
  }
  grantSignature?: {
    signatureBase: string
    eip191Hash: Hex
    signature: Hex
  }
  expected: {
    principal: Address
    signer: Address
    delegated: boolean
    binding: "request-bound"
    replayable: false
  }
}

const vectors: ConformanceVector[] = fixture.vectors.map((vector) => {
  if (vector.kind !== "direct" && vector.kind !== "delegated") {
    throw new Error(`Unsupported conformance vector kind: ${vector.kind}`)
  }
  if (
    vector.expected.binding !== "request-bound" ||
    vector.expected.replayable !== false
  ) {
    throw new Error(`Unsupported conformance posture: ${vector.id}`)
  }
  const headers = Object.fromEntries(
    Object.entries(vector.request.headers).filter(
      (entry): entry is [string, string] => entry[1] !== undefined
    )
  )
  const grantSignature = vector.grantSignature

  return {
    id: vector.id,
    kind: vector.kind,
    request: {
      method: vector.request.method,
      url: vector.request.url,
      headers,
      ...(vector.request.body === undefined
        ? {}
        : { body: vector.request.body })
    },
    requestSignature: {
      ...vector.requestSignature,
      eip191Hash: vector.requestSignature.eip191Hash as Hex,
      signature: vector.requestSignature.signature as Hex
    },
    ...(grantSignature === undefined
      ? {}
      : {
          grantSignature: {
            ...grantSignature,
            eip191Hash: grantSignature.eip191Hash as Hex,
            signature: grantSignature.signature as Hex
          }
        }),
    expected: {
      principal: vector.expected.principal as Address,
      signer: vector.expected.signer as Address,
      delegated: vector.expected.delegated,
      binding: vector.expected.binding,
      replayable: vector.expected.replayable
    }
  }
})

test.each(vectors)("verifies conformance vector $id", async (vector) => {
  const request = new Request(vector.request.url, {
    method: vector.request.method,
    headers: vector.request.headers,
    ...(vector.request.body === undefined ? {} : { body: vector.request.body })
  })
  const candidates = parseSignatureInputHeader(
    request.headers.get("signature-input") ?? ""
  )
  const requestCandidate = candidates.find(({ params }) =>
    vector.kind === "direct"
      ? params.tag === "erc8128"
      : params.tag === "erc8128-delegated"
  )
  if (!requestCandidate) throw new Error("Vector request candidate missing.")
  const requestSignatureB64 = parseSignatureHeader(
    request.headers.get("signature") ?? ""
  ).get(requestCandidate.label)
  const requestSignature =
    requestSignatureB64 === undefined ? null : base64Decode(requestSignatureB64)
  if (!requestSignature) throw new Error("Vector request signature missing.")
  const requestSignatureBase = createSignatureBaseMinimal({
    request,
    components: requestCandidate.components,
    signatureParamsValue: requestCandidate.signatureParamsValue
  })

  expect(new TextDecoder().decode(requestSignatureBase)).toBe(
    vector.requestSignature.signatureBase
  )
  expect(hashMessage({ raw: bytesToHex(requestSignatureBase) })).toBe(
    vector.requestSignature.eip191Hash
  )
  expect(bytesToHex(requestSignature)).toBe(vector.requestSignature.signature)

  const vectorGrantSignature = vector.grantSignature
  if (vectorGrantSignature) {
    const grantCandidate = candidates.find(
      ({ params }) => params.tag === "erc8128-delegation"
    )
    if (!grantCandidate) throw new Error("Vector grant candidate missing.")
    const grantSignatureB64 = parseSignatureHeader(
      request.headers.get("signature") ?? ""
    ).get(grantCandidate.label)
    const fieldValue = request.headers.get("erc-8128-delegation")
    if (!grantSignatureB64 || !fieldValue) {
      throw new Error("Vector delegation grant missing.")
    }
    const grantSignatureBase = getDelegationGrantSignatureBase({
      fieldValue,
      grantSignatureInput: grantCandidate.signatureParamsValue,
      grantSignatureB64
    })
    const grantSignature = base64Decode(grantSignatureB64)
    if (!grantSignature) throw new Error("Vector grant signature missing.")

    expect(new TextDecoder().decode(grantSignatureBase)).toBe(
      vectorGrantSignature.signatureBase
    )
    expect(hashMessage({ raw: bytesToHex(grantSignatureBase) })).toBe(
      vectorGrantSignature.eip191Hash
    )
    expect(bytesToHex(grantSignature)).toBe(vectorGrantSignature.signature)
  }

  const result = await verifyRequest({
    request,
    nonceStore: new BoundedMemoryNonceStore(),
    policy: {
      now: () => 1_760_000_020,
      principal: vector.kind,
      ...(vector.kind === "direct"
        ? { accountVerification: "eoa-only" as const }
        : { delegation: { audience: "https://api.example" } })
    },
    verifyMessage: async ({ address, message, signature }) =>
      (
        await recoverMessageAddress({
          message,
          signature: signature as Hex
        })
      ).toLowerCase() === address.toLowerCase()
  })
  if (!result.ok) throw new Error(result.reason)

  expect(result.principal.address.toLowerCase()).toBe(
    vector.expected.principal.toLowerCase()
  )
  expect(result.signer.address.toLowerCase()).toBe(
    vector.expected.signer.toLowerCase()
  )
  expect(result.delegated).toBe(vector.expected.delegated)
  expect(result.binding).toBe(vector.expected.binding)
  expect(result.replayable).toBe(vector.expected.replayable)
})
