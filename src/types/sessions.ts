import type { Address, Hex } from "./core"
import type { NonceStore, VerifyMessageFn, VerifyResult } from "./verifying"
import type { VerifyPolicy } from "./policy"
import type { EthHttpSigner } from "./signing"

export type SessionGrant = {
  account: Address
  appOrigin: string
  audience: string
  chainId: number
  expiresAt: number
  issuedAt: number
  nonce: string
  scopes: readonly string[]
  sessionSigner: Address
  signerScheme: "eoa"
  version: 1
}

export type CreateSessionGrantMessageParameters = Omit<
  SessionGrant,
  "signerScheme" | "version"
>

export type ValidateSessionGrantExpected = {
  account: Address
  appOrigin: string
  audience: string
  chainId: number
  clockSkewSeconds?: number
  maxTtlSeconds?: number
  now?: number
  scopes?: readonly string[]
  sessionSigner?: Address
}

export type VerifySessionGrantParameters = {
  expected: ValidateSessionGrantExpected
  message: string
  nonceStore: NonceStore
  signature: Hex
  verifyMessage?: VerifyMessageFn
}

export type SessionRegistryRecord = SessionGrant & {
  grantMessage: string
}

export type SessionRegistry = {
  delete: (keyId: string) => Promise<void>
  get: (keyId: string) => Promise<SessionRegistryRecord | null>
  set: (keyId: string, record: SessionRegistryRecord) => Promise<void>
}

export type CreateSessionRequestVerifierParameters = {
  audience: string
  nonceStore: NonceStore
  policy?: VerifyPolicy
  registry: SessionRegistry
  verifyMessage?: VerifyMessageFn
}

export type SessionRequestVerificationResult =
  | VerifyResult
  | { ok: false; reason: "no_session" | "session_expired" }

export type SessionSignerKeypair = {
  address: Address
  privateKey: Hex
}

export type EoaHttpSigner = EthHttpSigner & {
  privateKey: Hex
}
