import type {
  BindingMode,
  DiscoveryDocument,
  NonceStore,
  SignatureParams,
  VerifyResult
} from "@slicekit/erc8128"
import type { ContentfulStatusCode } from "hono/utils/http-status"

export type CacheStrategy = "secondary-storage" | "database"

export type CachedVerification = {
  address: `0x${string}`
  chainId: number
  label: string
  components: string[]
  params: SignatureParams
  replayable: true
  binding: BindingMode
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
  verifyRequest: (request: Request) => Promise<VerifyRequestResultEnvelope>
  close: () => Promise<void>
}

export type VerificationHttpPayloadValue =
  | string
  | number
  | boolean
  | string[]
  | SignatureParams
  | undefined

export type VerificationHttpResponse = {
  status: ContentfulStatusCode
  payload: Record<string, VerificationHttpPayloadValue>
  headers: Headers
}
