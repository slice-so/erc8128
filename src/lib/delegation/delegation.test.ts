import { describe, expect, test } from "bun:test"
import { type Hex, hashDomain, hashStruct, recoverAddress } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { BoundedMemoryNonceStore } from "../../stores"
import type {
  Delegation,
  DelegationChain,
  DelegationLink,
  NonceStore
} from "../../types"
import { verifyRequest } from "../../verify"
import { hashEthereumMessage } from "../ecdsa"
import { createSignatureBaseMinimal } from "../engine/createSignatureBase"
import { parseSignatureInputHeader } from "../engine/createSignatureInput"
import { formatErc8128ProblemDetails } from "../problemDetails"
import { bytesToHex } from "../utilities"
import { completeDelegationGrant } from "./createDelegationGrant"
import { createDelegatedSignerClient } from "./delegatedSignerClient"
import { resolveDelegationChain } from "./delegationChain"
import {
  decodeDelegationLink,
  encodeDelegationLink,
  formatDelegationField,
  getDelegationTypedData,
  hashDelegation,
  normalizeAudienceOrigin,
  parseDelegationField
} from "./delegationField"

const root = privateKeyToAccount(
  "0x0000000000000000000000000000000000000000000000000000000000000002"
)
const delegateA = privateKeyToAccount(
  "0x0000000000000000000000000000000000000000000000000000000000000003"
)
const delegateB = privateKeyToAccount(
  "0x0000000000000000000000000000000000000000000000000000000000000004"
)
const delegateC = privateKeyToAccount(
  "0x0000000000000000000000000000000000000000000000000000000000000005"
)

const g0Grant: Delegation = {
  issuer: `eip155:1:${root.address.toLowerCase()}`,
  delegate: `eip155:1:${delegateA.address.toLowerCase()}`,
  audiences: ["https://api.example", "https://backup.example"],
  id: `0x${"11".repeat(32)}`,
  epoch: 7,
  validAfter: 1_699_999_000,
  validUntil: 1_700_003_600,
  maxRequestValiditySeconds: 60,
  delegateIsEOA: true,
  requireNonReplayable: true,
  requiredComponents: ["@authority"],
  permissions: ["resource:read", "resource:write"],
  parentGrantHash: `0x${"00".repeat(32)}`
}
const g0: DelegationLink = {
  grant: g0Grant,
  signature:
    "0x479e35478cb0051c60f6b7e9f5ccbf4680508efbf4f689dbec460322ad61d41b394997be2fab4c7f05893d6d60e8c211547925a69f5e575f8afe0f4d5dcfc8691c"
}
const g1Grant: Delegation = {
  issuer: `eip155:1:${delegateA.address.toLowerCase()}`,
  delegate: `eip155:1:${delegateB.address.toLowerCase()}`,
  audiences: ["https://api.example"],
  id: `0x${"22".repeat(32)}`,
  epoch: 3,
  validAfter: 1_699_999_500,
  validUntil: 1_700_001_800,
  maxRequestValiditySeconds: 60,
  delegateIsEOA: true,
  requireNonReplayable: true,
  requiredComponents: ["@method"],
  permissions: ["resource:read"],
  parentGrantHash:
    "0x4a274dc6f56120c748e8494b1e5d4d058849594fef1b885759eb97ea6d5c63c2"
}
const g1: DelegationLink = {
  grant: g1Grant,
  signature:
    "0x5f10163c0c576641abebbd758589d380b283ecbabdb14e0d071b09a5d99af39570bc80e418c6a5888e068965073f38755fccead52d5830bb29e109a9fdccc00e1b"
}
// Cross-checked byte-for-byte against @ipld/dag-cbor 9.2.7.
const g0Cbor =
  "0x8e78336569703135353a313a30783262356164356334373935633032363531346638333137633761323135653231386463636436636678336569703135353a313a307836383133656239333632333732656566363230306633623164626333663831393637316362613639827368747470733a2f2f6170692e6578616d706c657668747470733a2f2f6261636b75702e6578616d706c6558201111111111111111111111111111111111111111111111111111111111111111071a6553ed181a6553ff10183cf5f5816a40617574686f72697479826d7265736f757263653a726561646e7265736f757263653a7772697465582000000000000000000000000000000000000000000000000000000000000000005841479e35478cb0051c60f6b7e9f5ccbf4680508efbf4f689dbec460322ad61d41b394997be2fab4c7f05893d6d60e8c211547925a69f5e575f8afe0f4d5dcfc8691c"
const g1Cbor =
  "0x8e78336569703135353a313a30783638313365623933363233373265656636323030663362316462633366383139363731636261363978336569703135353a313a307831656666343762633361313061343564346232333062356431306533373735316665366161373138817368747470733a2f2f6170692e6578616d706c6558202222222222222222222222222222222222222222222222222222222222222222031a6553ef0c1a6553f808183cf5f58167406d6574686f64816d7265736f757263653a7265616458204a274dc6f56120c748e8494b1e5d4d058849594fef1b885759eb97ea6d5c63c258415f10163c0c576641abebbd758589d380b283ecbabdb14e0d071b09a5d99af39570bc80e418c6a5888e068965073f38755fccead52d5830bb29e109a9fdccc00e1b"

const signer = (account: typeof delegateA) => ({
  address: account.address,
  chainId: 1,
  signMessage: (message: Uint8Array) =>
    account.signMessage({ message: { raw: message } })
})

const verify = (
  request: Request,
  options: {
    maximumDepth?: number
    nonceStore?: NonceStore
    requiredPermissions?: readonly string[]
    statusBatch?: (links: readonly DelegationLink[]) => void
    status?: (
      link: DelegationLink
    ) => "valid" | "revoked" | "epoch-mismatch" | "unavailable"
  } = {}
) =>
  verifyRequest({
    request,
    nonceStore: options.nonceStore ?? new BoundedMemoryNonceStore(),
    policy: {
      now: () => 1_700_000_001,
      clockSkewSec: 30,
      principal: "delegated",
      delegation: {
        ...(options.maximumDepth === undefined
          ? {}
          : { maxChainDepth: options.maximumDepth }),
        requiredPermissions: options.requiredPermissions ?? ["resource:read"],
        verifyStatuses: (contexts) => {
          const links = contexts.map(({ link }) => link)
          options.statusBatch?.(links)
          return links.map((link) => options.status?.(link) ?? "valid")
        }
      }
    },
    verifyDigest: async ({ address, digest, signature }) =>
      (await recoverAddress({ hash: digest, signature })).toLowerCase() ===
      address.toLowerCase(),
    verifyMessage: () => false
  })

const signedVectorRequest = (
  account: typeof delegateA,
  chain: DelegationChain,
  nonce: string
) =>
  createDelegatedSignerClient(signer(account), chain).signRequest(
    "https://api.example/resource?x=1",
    {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      nonce
    }
  )

describe("EIP-712 Delegation grants", () => {
  test("requires explicit policy for HTTP loopback audiences", () => {
    for (const origin of [
      "http://localhost:3000",
      "http://127.0.0.2:3000",
      "http://[::1]:3000"
    ]) {
      expect(() => normalizeAudienceOrigin(origin)).toThrow()
      expect(
        normalizeAudienceOrigin(origin, { allowLoopbackAudiences: true })
      ).toBe(origin)
    }
  })

  test("matches the fixed grant digests and signatures", async () => {
    const g0TypedData = getDelegationTypedData(g0Grant)
    const g1TypedData = getDelegationTypedData(g1Grant)
    const types = {
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
        { name: "chainId", type: "uint256" }
      ],
      ...g0TypedData.types
    } as const
    expect(
      hashDomain({
        domain: {
          ...g0TypedData.domain,
          chainId: BigInt(g0TypedData.domain.chainId)
        },
        types
      })
    ).toBe("0xe75cfb820d01daf33b6457696c96272bcf1383d1e3b6da5d7ee1e9e993a5ce73")
    expect(
      hashStruct({
        data: g0TypedData.message,
        primaryType: g0TypedData.primaryType,
        types
      })
    ).toBe("0x82906303eba6d0fa5d1b6315869673e5e80e4cb0b19230f8b32cd5aeb9921536")
    expect(
      hashStruct({
        data: g1TypedData.message,
        primaryType: g1TypedData.primaryType,
        types
      })
    ).toBe("0xab39f11f8d1d4060992c0fc26f6c8e043d77db6e8afc52d4fd6f84780ab5be82")
    expect(hashDelegation(g0Grant)).toBe(
      "0x4a274dc6f56120c748e8494b1e5d4d058849594fef1b885759eb97ea6d5c63c2"
    )
    expect(hashDelegation(g1Grant)).toBe(
      "0x2a3352573606edaff0d80c092e6054fafd799302037d306af2c5446dfed638e8"
    )
    expect(await root.signTypedData(getDelegationTypedData(g0Grant))).toBe(
      g0.signature
    )
    expect(await delegateA.signTypedData(getDelegationTypedData(g1Grant))).toBe(
      g1.signature
    )
  })

  test("matches the independently verified deterministic CBOR links", () => {
    const encodedG0 = encodeDelegationLink(g0)
    const encodedG1 = encodeDelegationLink(g1)
    expect(encodedG0[0]).toBe(0x8e)
    expect(encodedG1[0]).toBe(0x8e)
    expect(encodedG0).toHaveLength(343)
    expect(encodedG1).toHaveLength(302)
    expect(bytesToHex(encodedG0)).toBe(g0Cbor)
    expect(bytesToHex(encodedG1)).toBe(g1Cbor)
    expect(decodeDelegationLink(encodedG0)).toEqual(g0)
    expect(decodeDelegationLink(encodedG1)).toEqual(g1)
    const trailing = new Uint8Array(encodedG0.length + 1)
    trailing.set(encodedG0)
    expect(() => decodeDelegationLink(trailing)).toThrow()
  })

  test("accepts only consecutive ordered byte-sequence members", () => {
    const field = formatDelegationField({ links: [g0, g1] })
    expect(parseDelegationField(field).chain).toEqual({ links: [g0, g1] })
    expect(() => parseDelegationField(field.replace("g1=", "g2="))).toThrow()
    expect(() => parseDelegationField(`${field}, extra=:AA==:`)).toThrow()
  })

  test("resolves recursive attenuation and rejects broadening", () => {
    const resolved = resolveDelegationChain(
      parseDelegationField(formatDelegationField({ links: [g0, g1] }))
    )
    expect(resolved.effectiveAudiences).toEqual(["https://api.example"])
    expect(resolved.effectivePermissions).toEqual(["resource:read"])
    expect(
      resolved.effectiveRequiredComponents.map(({ name }) => name)
    ).toEqual(["@authority", "@method"])
    const broadened = {
      ...g1,
      grant: { ...g1.grant, maxRequestValiditySeconds: 61 }
    }
    expect(() =>
      resolveDelegationChain(
        parseDelegationField(formatDelegationField({ links: [g0, broadened] }))
      )
    ).toThrow("broadens")
  })
})

describe("Delegated Request Signatures", () => {
  test("matches and verifies the one-link fixed request vector", async () => {
    const request = await signedVectorRequest(
      delegateA,
      { links: [g0] },
      "ASNFZ4mrze8QMlR2mLrc_g"
    )
    expect(request.headers.get("signature-input")).toBe(
      'request=("@scheme" "@authority" "@method" "@path" "@query" "erc-8128-delegation";sf);created=1700000000;expires=1700000060;nonce="ASNFZ4mrze8QMlR2mLrc_g";keyid="eip155:1:0x6813eb9362372eef6200f3b1dbc3f819671cba69";tag="erc8128-delegated"'
    )
    expect(request.headers.get("signature")).toBe(
      "request=:GXzD4Ufm62IUiQU+yrwGx52V9nO34m3ZVw+ULKOFfnYisiECwMvf+6zrx5zPsXg516lSh+7Tulk5W0kIg/2FIhs=:"
    )
    const candidate = parseSignatureInputHeader(
      request.headers.get("signature-input") ?? ""
    )[0]
    if (candidate === undefined)
      throw new Error("Request candidate is missing.")
    const signatureBase = createSignatureBaseMinimal({
      request,
      components: candidate.components,
      signatureParamsValue: candidate.signatureParamsValue
    })
    expect(signatureBase).toHaveLength(834)
    expect(bytesToHex(hashEthereumMessage(signatureBase))).toBe(
      "0xb11b7a98450116d11b50079fce56781818eefd4c3d4228edfc29ed084d98f2b7"
    )
    expect(request.headers.get("signature-input")).not.toContain(
      "authorization="
    )
    const result = await verify(request)
    expect(result).toMatchObject({
      ok: true,
      delegated: true,
      principal: { address: root.address.toLowerCase(), chainId: 1 },
      signer: { address: delegateA.address.toLowerCase(), chainId: 1 },
      delegationIds: [g0.grant.id]
    })
  })

  test("matches and verifies the depth-two fixed request vector", async () => {
    const request = await signedVectorRequest(
      delegateB,
      { links: [g0, g1] },
      "RERERERERERERERERERERA"
    )
    expect(request.headers.get("signature")).toBe(
      "request=:5LUwOoSsWH4LvBtg7RjWRTvubwx5IAf5qOA3Iug+Wf5D1myMWuwmmDcTED1ylafcJ6WJwYu9Llczq1g+7gL/axw=:"
    )
    const candidate = parseSignatureInputHeader(
      request.headers.get("signature-input") ?? ""
    )[0]
    if (candidate === undefined)
      throw new Error("Request candidate is missing.")
    const signatureBase = createSignatureBaseMinimal({
      request,
      components: candidate.components,
      signatureParamsValue: candidate.signatureParamsValue
    })
    expect(signatureBase).toHaveLength(1_245)
    expect(bytesToHex(hashEthereumMessage(signatureBase))).toBe(
      "0x60cd8c4caceb661cd173d1a5b02c89994f06c9b1dcebde049a00f08aa651bc86"
    )
    const result = await verify(request)
    expect(result).toMatchObject({
      ok: true,
      delegated: true,
      principal: { address: root.address.toLowerCase(), chainId: 1 },
      signer: { address: delegateB.address.toLowerCase(), chainId: 1 },
      delegationIds: [g0.grant.id, g1.grant.id]
    })
  })

  test("enforces depth, permissions, and every link's status", async () => {
    const request = await signedVectorRequest(
      delegateB,
      { links: [g0, g1] },
      "RERERERERERERERERERERA"
    )
    const tooLong = await verify(request, { maximumDepth: 1 })
    expect(tooLong).toEqual({
      ok: false,
      reason: "delegation_chain_too_long"
    })
    if (tooLong.ok) throw new Error("Expected depth failure.")
    expect(formatErc8128ProblemDetails(tooLong).status).toBe(400)

    const insufficient = await verify(request, {
      requiredPermissions: ["resource:write"]
    })
    expect(insufficient).toEqual({
      ok: false,
      reason: "insufficient_permissions"
    })
    if (insufficient.ok) throw new Error("Expected permission failure.")
    expect(formatErc8128ProblemDetails(insufficient).status).toBe(403)

    const revoked = await verify(request, {
      status: (link) => (link.grant.id === g1.grant.id ? "revoked" : "valid")
    })
    expect(revoked).toEqual({ ok: false, reason: "authorization_revoked" })
    if (revoked.ok) throw new Error("Expected revocation failure.")
    expect(formatErc8128ProblemDetails(revoked).status).toBe(401)
  })

  test("checks revocation and epoch state across a derived three-link chain", async () => {
    const g2Grant: Delegation = {
      ...g1Grant,
      issuer: `eip155:1:${delegateB.address.toLowerCase()}`,
      delegate: `eip155:1:${delegateC.address.toLowerCase()}`,
      id: `0x${"33".repeat(32)}`,
      epoch: 5,
      validAfter: 1_699_999_600,
      validUntil: 1_700_001_200,
      requiredComponents: [],
      permissions: [],
      parentGrantHash: hashDelegation(g1Grant)
    }
    const g2: DelegationLink = {
      grant: g2Grant,
      signature: await delegateB.signTypedData(getDelegationTypedData(g2Grant))
    }
    const request = await signedVectorRequest(
      delegateC,
      { links: [g0, g1, g2] },
      "three-link-derived-vector"
    )

    const statusBatches: string[][] = []
    expect(
      (
        await verify(request.clone(), {
          statusBatch: (links) =>
            statusBatches.push(links.map(({ grant }) => grant.id))
        })
      ).ok
    ).toBe(true)
    expect(statusBatches).toEqual([[g0.grant.id, g1.grant.id, g2.grant.id]])

    expect(
      await verify(request.clone(), {
        status: (link) => (link.grant.id === g1.grant.id ? "revoked" : "valid")
      })
    ).toEqual({ ok: false, reason: "authorization_revoked" })
    expect(
      await verify(request.clone(), {
        status: (link) =>
          link.grant.id === g1.grant.id ? "epoch-mismatch" : "valid"
      })
    ).toEqual({ ok: false, reason: "authorization_epoch_mismatch" })
  })

  test("lets a later delegated candidate win without consuming the failed nonce", async () => {
    const bad = await signedVectorRequest(
      delegateA,
      { links: [g0] },
      "delegated-failed-candidate"
    )
    const good = await createDelegatedSignerClient(signer(delegateA), {
      links: [g0]
    }).signRequest("https://api.example/resource?x=1", {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      label: "later",
      nonce: "delegated-later-winner"
    })
    const corrupted = (bad.headers.get("signature") ?? "").replace(
      /:([A-Za-z0-9+/])/,
      (_match, first: string) => `:${first === "A" ? "B" : "A"}`
    )
    const headers = new Headers(good.headers)
    headers.set(
      "signature-input",
      `${bad.headers.get("signature-input")}, ${good.headers.get("signature-input")}`
    )
    headers.set("signature", `${corrupted}, ${good.headers.get("signature")}`)
    const nonceStore = new BoundedMemoryNonceStore()

    expect(
      (await verify(new Request(good, { headers }), { nonceStore })).ok
    ).toBe(true)
    expect((await verify(bad, { nonceStore })).ok).toBe(true)
  })

  test("verifies proofs leaf-to-root and consumes the nonce last", async () => {
    const request = await signedVectorRequest(
      delegateB,
      { links: [g0, g1] },
      "RERERERERERERERERERERA"
    )
    const order: string[] = []
    let nonceConsumes = 0
    const result = await verifyRequest({
      request,
      nonceStore: {
        consume: async () => {
          nonceConsumes += 1
          return true
        }
      },
      policy: {
        now: () => 1_700_000_001,
        clockSkewSec: 30,
        delegation: {
          requiredPermissions: ["resource:read"],
          verifyStatuses: (contexts) =>
            contexts.map(({ link }) => {
              order.push(`status:${link.grant.id}`)
              return "valid"
            })
        }
      },
      verifyDigest: async ({ digest }) => {
        order.push(`proof:${digest}`)
        return digest !== hashDelegation(g0.grant)
      },
      verifyMessage: () => false
    })
    expect(result).toEqual({ ok: false, reason: "bad_grant_signature" })
    expect(order).toEqual([
      `proof:${hashDelegation(g1.grant)}`,
      `proof:${hashDelegation(g0.grant)}`
    ])
    expect(nonceConsumes).toBe(0)
  })

  test("a signed chain builder embeds the EIP-712 proof only", async () => {
    const prepared = {
      grant: g0Grant,
      digest: hashDelegation(g0Grant),
      typedData: getDelegationTypedData(g0Grant)
    }
    const link = completeDelegationGrant(
      prepared,
      (await root.signTypedData(prepared.typedData)) as Hex
    )
    expect(link).toEqual(g0)
    expect(Object.keys(link).sort()).toEqual(["grant", "signature"])
  })
})
