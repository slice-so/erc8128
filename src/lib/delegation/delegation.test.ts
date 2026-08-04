import { describe, expect, test } from "bun:test"
import { type Hex, recoverAddress } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { BoundedMemoryNonceStore } from "../../stores"
import type { Delegation, DelegationChain, DelegationLink } from "../../types"
import { verifyRequest } from "../../verify"
import { completeDelegationGrant } from "./createDelegationGrant"
import { createDelegatedSignerClient } from "./delegatedSignerClient"
import { resolveDelegationChain } from "./delegationChain"
import {
  decodeDelegationLink,
  encodeDelegationLink,
  formatDelegationField,
  getDelegationTypedData,
  hashDelegation,
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

const g0Grant: Delegation = {
  root: `eip155:1:${root.address.toLowerCase()}`,
  delegate: `eip155:1:${delegateA.address.toLowerCase()}`,
  aud: ["https://api.example", "https://backup.example"],
  id: `0x${"11".repeat(32)}`,
  epoch: 7,
  created: 1_699_999_000,
  expires: 1_700_003_600,
  maxAge: 60,
  delegateIsEOA: true,
  allowReplayable: true,
  components: ["@authority"],
  scope: ["resource:read", "resource:write"],
  parent: `0x${"00".repeat(32)}`
}
const g0: DelegationLink = {
  grant: g0Grant,
  signature:
    "0x537590cfd51670d5327bdbb8a62ad78db94e9c6a3435bcea00a8c2bf8580cbab714ecb346e551920aa78cd4c1e36a44c89f7a6e6db3b2151285761c851cfa4921c"
}
const g1Grant: Delegation = {
  root: `eip155:1:${delegateA.address.toLowerCase()}`,
  delegate: `eip155:1:${delegateB.address.toLowerCase()}`,
  aud: ["https://api.example"],
  id: `0x${"22".repeat(32)}`,
  epoch: 3,
  created: 1_699_999_500,
  expires: 1_700_001_800,
  maxAge: 60,
  delegateIsEOA: true,
  allowReplayable: true,
  components: ["@method"],
  scope: ["resource:read"],
  parent: "0xf2095d8d781dcdc7b02ed53da67de81daeb7efaa882f455169a614f70262a366"
}
const g1: DelegationLink = {
  grant: g1Grant,
  signature:
    "0x03e5baed77bd76300a15567ac9ef02994a891e10cf728f6e75ac292748fd31b41ecf0187c091f8d3997a34243a96df13ecbe11f93186f32b087caba7a0e24e0b1c"
}

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
    requiredScopes?: readonly string[]
    status?: (
      link: DelegationLink
    ) => "valid" | "revoked" | "epoch-mismatch" | "unavailable"
  } = {}
) =>
  verifyRequest({
    request,
    nonceStore: new BoundedMemoryNonceStore(),
    policy: {
      now: () => 1_700_000_001,
      clockSkewSec: 30,
      principal: "delegated",
      delegation: {
        ...(options.maximumDepth === undefined
          ? {}
          : { maxChainDepth: options.maximumDepth }),
        requiredScopes: options.requiredScopes ?? ["resource:read"],
        verifyStatus: ({ link }) => options.status?.(link) ?? "valid"
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
  test("matches the fixed grant digests and signatures", async () => {
    expect(hashDelegation(g0Grant)).toBe(
      "0xf2095d8d781dcdc7b02ed53da67de81daeb7efaa882f455169a614f70262a366"
    )
    expect(hashDelegation(g1Grant)).toBe(
      "0x0267ed56f6e57f6b0ca5c813abe73a7a6317dff19ba6b2a4a39c03eba1d1dece"
    )
    expect(await root.signTypedData(getDelegationTypedData(g0Grant))).toBe(
      g0.signature
    )
    expect(await delegateA.signTypedData(getDelegationTypedData(g1Grant))).toBe(
      g1.signature
    )
  })

  test("strictly round-trips ABI links and rejects trailing bytes", () => {
    const encoded = encodeDelegationLink(g0)
    expect(encoded).toHaveLength(1_376)
    expect(decodeDelegationLink(encoded)).toEqual(g0)
    const trailing = new Uint8Array(encoded.length + 32)
    trailing.set(encoded)
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
    expect(resolved.effectiveAudience).toEqual(["https://api.example"])
    expect(resolved.effectiveScope).toEqual(["resource:read"])
    expect(resolved.effectiveComponents.map(({ name }) => name)).toEqual([
      "@authority",
      "@method"
    ])
    const broadened = {
      ...g1,
      grant: { ...g1.grant, maxAge: 61 }
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
      "request=:gJVoCxIQDQlHUvCcT1CnW8kAosnj3JLRWw8lj7uIjehaICXcn5uqJErUYy5CY3rRf/xjUZwq4zdEoqPR7MraeBs=:"
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
      "request=:BFdolKrFYQUmMwPv6ZFiZTMkrtayqRD7naU2mNYuHP13HE+kBmmU+5wawoPE0TpA78GJFz3DU2LeeC7cLKpYBxw=:"
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

  test("enforces depth, scopes, and every link's status", async () => {
    const request = await signedVectorRequest(
      delegateB,
      { links: [g0, g1] },
      "RERERERERERERERERERERA"
    )
    expect(await verify(request, { maximumDepth: 1 })).toEqual({
      ok: false,
      reason: "delegation_chain_too_long"
    })
    expect(
      await verify(request, { requiredScopes: ["resource:write"] })
    ).toEqual({ ok: false, reason: "insufficient_scope" })
    expect(
      await verify(request, {
        status: (link) => (link.grant.id === g1.grant.id ? "revoked" : "valid")
      })
    ).toEqual({ ok: false, reason: "authorization_revoked" })
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
          requiredScopes: ["resource:read"],
          verifyStatus: ({ link }) => {
            order.push(`status:${link.grant.id}`)
            return "valid"
          }
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
