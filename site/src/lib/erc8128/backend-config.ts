/**
 * Better-auth instance factory — cached per storage mode, base URL, and
 * verifier so in-memory storage survives across requests.
 *
 * The ERC-8128 plugin owns replay protection, invalidation, and verification
 * cache. App routes call the plugin's server API directly.
 */

import { betterAuth, env } from "@slicekit/better-auth"
import { memoryAdapter } from "@slicekit/better-auth/adapters/memory"
import {
  type ERC8128PluginOptions,
  type Erc8128ServerApi,
  erc8128,
  getErc8128Api
} from "@slicekit/better-auth/plugins/erc8128"
import type { VerifyMessageFn } from "@slicekit/erc8128"
import { createPublicClient, http } from "viem"
import { mainnet } from "viem/chains"
import { createMemorySecondaryStorage } from "./secondary-storage-memory"
import type { StorageMode } from "./storage-header"

export type CacheStrategy = "none" | "secondary-storage" | "database"

export interface AuthInstance {
  handler: (request: Request) => Promise<Response>
  erc8128: Erc8128ServerApi
  cacheStrategy: CacheStrategy
}

type AuthInstanceCache = Map<string, WeakMap<VerifyMessageFn, AuthInstance>>

const CACHE_STRATEGY: Record<StorageMode, CacheStrategy> = {
  none: "none",
  redis: "secondary-storage",
  postgres: "database"
}

const VERIFY_ROUTE_POLICY: NonNullable<ERC8128PluginOptions["routePolicy"]> = {
  "/verify": [
    {
      methods: ["GET", "POST", "PUT", "PATCH"],
      replayable: true,
      classBoundPolicies: [["@authority"]]
    },
    {
      methods: ["DELETE"],
      replayable: false
    }
  ]
}

const authInstanceCache: AuthInstanceCache = new Map()

export const rpcUrl = `https://eth-mainnet.g.alchemy.com/v2/${env.SECRET_ALCHEMY_KEY ?? ""}`
export const publicClient = createPublicClient({
  chain: mainnet,
  transport: http(rpcUrl)
})

function createMemoryDb() {
  return {
    user: [] as Record<string, unknown>[],
    session: [] as Record<string, unknown>[],
    account: [] as Record<string, unknown>[],
    verification: [] as Record<string, unknown>[],
    walletAddress: [] as Record<string, unknown>[],
    erc8128Nonce: [] as Record<string, unknown>[],
    erc8128Invalidation: [] as Record<string, unknown>[]
  }
}

function normalizeBaseURL(baseURL: string) {
  return new URL(baseURL).toString().replace(/\/$/, "")
}

function getCachedAuthInstance(
  mode: StorageMode,
  baseURL: string,
  verifyMessage: VerifyMessageFn
) {
  const cacheKey = `${mode}:${normalizeBaseURL(baseURL)}`
  return authInstanceCache.get(cacheKey)?.get(verifyMessage) ?? null
}

function setCachedAuthInstance(
  mode: StorageMode,
  baseURL: string,
  verifyMessage: VerifyMessageFn,
  instance: AuthInstance
) {
  const cacheKey = `${mode}:${normalizeBaseURL(baseURL)}`
  let instancesByVerifier = authInstanceCache.get(cacheKey)

  if (!instancesByVerifier) {
    instancesByVerifier = new WeakMap()
    authInstanceCache.set(cacheKey, instancesByVerifier)
  }

  instancesByVerifier.set(verifyMessage, instance)
}

export function getAuthInstance(
  mode: StorageMode,
  baseURL: string,
  verifyMessage = publicClient.verifyMessage
): AuthInstance {
  const cached = getCachedAuthInstance(mode, baseURL, verifyMessage)
  if (cached) {
    return cached
  }

  const secondaryStorage =
    mode === "redis" ? createMemorySecondaryStorage() : undefined

  const auth = betterAuth({
    database: memoryAdapter(createMemoryDb()),
    basePath: "/api/auth",
    baseURL: normalizeBaseURL(baseURL),
    ...(secondaryStorage ? { secondaryStorage } : {}),
    plugins: [
      erc8128({
        verifyMessage,
        authPrecedence: "signature-first",
        anonymous: true,
        maxValiditySec: 300,
        clockSkewSec: 30,
        routePolicy: VERIFY_ROUTE_POLICY
      })
    ]
  })

  const instance: AuthInstance = {
    handler: (request: Request) => auth.handler(request),
    erc8128: getErc8128Api(auth),
    cacheStrategy: CACHE_STRATEGY[mode]
  }

  setCachedAuthInstance(mode, baseURL, verifyMessage, instance)

  return instance
}
