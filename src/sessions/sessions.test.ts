import { describe, expect, it } from "bun:test"
import { formatKeyId } from "../lib/keyId"
import { signRequest } from "../sign"
import {
  createEoaHttpSigner,
  createSessionSignerKeypair
} from "./eoaVerify"
import {
  createSessionGrantMessage,
  parseSessionGrantMessage,
  validateSessionGrant
} from "./grant"
import { createMemoryNonceStore, createMemorySessionRegistry } from "./memory"
import { createSessionRequestVerifier } from "./requestVerifier"
import { openSealedPayload, sealPayload } from "./seal"
import { verifySessionGrant } from "./verifyGrant"

const now = 1_800_000_000

describe("ERC-8128 session grants", () => {
  it("pins the canonical 15-line grammar and byte-sorts scopes", () => {
    const account = createSessionSignerKeypair()
    const session = createSessionSignerKeypair()
    const message = createSessionGrantMessage({
      account: account.address,
      appOrigin: "https://app.example",
      audience: "https://api.example",
      chainId: 8453,
      expiresAt: now + 60,
      issuedAt: now,
      nonce: "abcdefghijklmnop",
      scopes: ["write:orders", "read:orders"],
      sessionSigner: session.address
    })
    expect(message.split("\n")).toHaveLength(15)
    expect(message).toContain("Scopes: read:orders write:orders")
    const parsed = parseSessionGrantMessage(message)
    expect(parsed).not.toBeNull()
    expect(
      parsed !== null &&
        validateSessionGrant(parsed, {
          account: account.address,
          appOrigin: "https://app.example",
          audience: "https://api.example",
          chainId: 8453,
          now,
          scopes: ["read:orders", "write:orders"]
        })
    ).toBe(true)
  })

  it("verifies an EOA account grant once and rejects replay", async () => {
    const account = createSessionSignerKeypair()
    const session = createSessionSignerKeypair()
    const signer = createEoaHttpSigner({ chainId: 8453, privateKey: account.privateKey })
    const message = createSessionGrantMessage({
      account: account.address,
      appOrigin: "https://app.example",
      audience: "https://api.example",
      chainId: 8453,
      expiresAt: now + 60,
      issuedAt: now,
      nonce: "abcdefghijklmnop",
      scopes: [],
      sessionSigner: session.address
    })
    const signature = await signer.signMessage(new TextEncoder().encode(message))
    const parameters = {
      expected: {
        account: account.address,
        appOrigin: "https://app.example",
        audience: "https://api.example",
        chainId: 8453,
        now
      },
      message,
      nonceStore: createMemoryNonceStore(),
      signature
    }
    expect(await verifySessionGrant(parameters)).not.toBeNull()
    expect(await verifySessionGrant(parameters)).toBeNull()
  })

  it("rejects malformed scope, duplicate scope, and oversized messages", () => {
    const account = createSessionSignerKeypair()
    const base = {
      account: account.address,
      appOrigin: "https://app.example",
      audience: "https://api.example",
      chainId: 1,
      expiresAt: now + 60,
      issuedAt: now,
      nonce: "abcdefghijklmnop",
      sessionSigner: account.address
    }
    expect(() => createSessionGrantMessage({ ...base, scopes: ["UPPER"] })).toThrow()
    expect(() => createSessionGrantMessage({ ...base, scopes: ["read", "read"] })).toThrow()
    expect(() => createSessionGrantMessage({
      ...base,
      nonce: "a".repeat(4_000),
      scopes: []
    })).toThrow()
  })
})

describe("ERC-8128 session request verifier", () => {
  it("uses a registered signer and fails after registry revocation", async () => {
    const account = createSessionSignerKeypair()
    const session = createSessionSignerKeypair()
    const signer = createEoaHttpSigner({ chainId: 8453, privateKey: session.privateKey })
    const registry = createMemorySessionRegistry()
    const keyId = formatKeyId(8453, session.address)
    await registry.set(keyId, {
      account: account.address,
      appOrigin: "https://app.example",
      audience: "https://api.example",
      chainId: 8453,
      expiresAt: Math.floor(Date.now() / 1000) + 60,
      grantMessage: "grant",
      issuedAt: Math.floor(Date.now() / 1000),
      nonce: "abcdefghijklmnop",
      scopes: [],
      sessionSigner: session.address,
      signerScheme: "eoa",
      version: 1
    })
    const request = await signRequest("https://api.example/me", signer, {
      nonce: "request-nonce-0001"
    })
    const verifier = createSessionRequestVerifier({
      audience: "https://api.example",
      nonceStore: createMemoryNonceStore(),
      registry
    })
    expect((await verifier.verify(request)).ok).toBe(true)
    await registry.delete(keyId)
    expect(await verifier.verify(request)).toEqual({ ok: false, reason: "no_session" })
  })
})

describe("session payload sealing", () => {
  it("round-trips the v1 format and rejects a different secret", async () => {
    const sealed = await sealPayload({ payload: { value: 1 }, secret: "secret" })
    expect(sealed.startsWith("v1.")).toBe(true)
    expect(await openSealedPayload<{ value: number }>({ secret: "secret", value: sealed })).toEqual({ value: 1 })
    expect(await openSealedPayload({ secret: "wrong", value: sealed })).toBeNull()
  })
})
