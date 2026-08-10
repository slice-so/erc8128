import type {
  DiscoveryDocument,
  NonceStore,
  VerifyResult
} from "@slicekit/erc8128"
import type { ContentfulStatusCode } from "hono/utils/http-status"

type SuccessfulVerification = Extract<VerifyResult, { ok: true }>
type SuccessfulDirectVerification = Extract<
  VerifyResult,
  { ok: true; delegated: false }
>

export type CacheStrategy = "secondary-storage" | "database"

export type CachedVerification = Omit<
  SuccessfulDirectVerification,
  "ok" | "replay"
> & {
  replay: "replayable"
}

export interface VerificationCacheStore {
  get(signatureHeader: string): Promise<CachedVerification | null>
  set(
    signatureHeader: string,
    value: CachedVerification,
    ttlSec: number
  ): Promise<void>
  delete(signatureHeader: string): Promise<void>
}

export interface InvalidationStore {
  getNotBefore(keyId: string): Promise<number | null>
}

export interface VerificationRuntimeConfig {
  cacheStrategy: CacheStrategy
  nonceStore: NonceStore
  verificationCache: VerificationCacheStore
  invalidationStore: InvalidationStore
  close?: () => Promise<void>
}

export interface VerificationBindings {
  hyperdrive?: string
  databaseUrl?: string
  redisUrl?: string
}

export interface VerifyRequestResultEnvelope {
  result: VerifyResult
  responseHeaders: Headers
  cachedVerification: boolean
}

export interface VerificationRuntime {
  cacheStrategy: CacheStrategy
  getConfig: () => DiscoveryDocument
  verifyRequest: <CfHostMetadata, Cf>(
    request: Request<CfHostMetadata, Cf>
  ) => Promise<VerifyRequestResultEnvelope>
  close: () => Promise<void>
}

export type VerificationHttpPayloadValue =
  | string
  | number
  | boolean
  | string[]
  | SuccessfulVerification["principal"]
  | SuccessfulDirectVerification["components"]
  | SuccessfulDirectVerification["params"]
  | undefined

export type VerificationHttpResponse = {
  status: ContentfulStatusCode
  payload: Record<string, VerificationHttpPayloadValue>
  headers: Headers
}
