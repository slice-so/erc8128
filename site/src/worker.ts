import {
  formatErc8128ProblemDetails,
  VerificationUnavailableError,
  type VerifyMessageFn
} from "@slicekit/erc8128"
import { type Context, Hono } from "hono"
import { cors } from "hono/cors"
import { createPublicClient, http } from "viem"
import { mainnet } from "viem/chains"
import {
  cleanupExpiredVerificationStorage,
  getDiscoveryDocument,
  getVerificationRuntime
} from "./lib/erc8128/backend-config"
import {
  parseConfiguredStorageMode,
  parseStorageMode
} from "./lib/erc8128/storage-header"
import {
  buildVerifyExceptionResponse,
  buildVerifyResultResponse
} from "./lib/erc8128/verify-response"
import type {
  StorageMode,
  VerificationHttpResponse,
  VerificationRuntime
} from "./types"

type Env = {
  Bindings: RuntimeBindings
  Variables: {
    storageMode: StorageMode
    verificationRequest: Request
    verificationRuntime: VerificationRuntime
  }
}

export type StorageRuntimeBindings = {
  ERC8128_ENABLE_STORAGE_HEADER?: string
  ERC8128_ENVIRONMENT?: "development" | "production" | "test"
  ERC8128_STORAGE_MODE?: string
}

type RuntimeBindings = CloudflareBindings & StorageRuntimeBindings

type VerificationRpcBindings = {
  ERC8128_SECRET_ALCHEMY_ID?: string
}

let cachedVerifyMessage:
  | { alchemyId: string; verifyMessage: VerifyMessageFn }
  | undefined

export const MAX_VERIFY_BODY_BYTES = 1_048_576

export function resolveStorageSelection(
  bindings: StorageRuntimeBindings,
  headers: Headers
) {
  const configuredStorageMode = parseConfiguredStorageMode(
    bindings.ERC8128_STORAGE_MODE
  )
  const allowHeaderOverride =
    bindings.ERC8128_ENVIRONMENT !== "production" &&
    bindings.ERC8128_ENABLE_STORAGE_HEADER === "true"
  return {
    allowHeaderOverride,
    storageMode: parseStorageMode(
      headers,
      configuredStorageMode,
      allowHeaderOverride
    )
  }
}

export function getVerifyMessage(
  bindings: VerificationRpcBindings
): VerifyMessageFn | null {
  const alchemyId = bindings.ERC8128_SECRET_ALCHEMY_ID?.trim()
  if (!alchemyId) return null
  if (cachedVerifyMessage?.alchemyId === alchemyId) {
    return cachedVerifyMessage.verifyMessage
  }
  const publicClient = createPublicClient({
    chain: mainnet,
    transport: http(`https://eth-mainnet.g.alchemy.com/v2/${alchemyId}`)
  })
  const verifyMessage: VerifyMessageFn = async (args) => {
    try {
      return await publicClient.verifyMessage(args)
    } catch {
      throw new VerificationUnavailableError(
        "The Ethereum account-verification RPC is unavailable."
      )
    }
  }
  cachedVerifyMessage = { alchemyId, verifyMessage }
  return verifyMessage
}

export async function bufferVerificationRequest(
  request: Request
): Promise<Request | null> {
  const contentLength = request.headers.get("content-length")
  if (contentLength !== null) {
    const declaredLength = Number(contentLength)
    if (
      Number.isFinite(declaredLength) &&
      declaredLength > MAX_VERIFY_BODY_BYTES
    ) {
      return null
    }
  }
  if (request.body === null) return request

  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > MAX_VERIFY_BODY_BYTES) {
      await reader.cancel()
      return null
    }
    chunks.push(value)
  }
  const body = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new Request(request, { body })
}

function jsonWithHeaders(c: Context<Env>, response: VerificationHttpResponse) {
  const res = c.json(response.payload, response.status)
  for (const [key, value] of response.headers.entries()) {
    res.headers.set(key, value)
  }
  return res
}

const app = new Hono<Env>()

app.use(
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowHeaders: ["*"],
    maxAge: 86400
  })
)

app.get("/.well-known/erc8128", (c) => {
  return c.json(getDiscoveryDocument(new URL(c.req.url).origin))
})

app.get("/playground-config", (c) => {
  const storage = resolveStorageSelection(c.env, new Headers())
  return c.json({
    storageMode: storage.storageMode,
    storageOverrideEnabled: storage.allowHeaderOverride
  })
})

app.use("/verify", async (c, next) => {
  const verificationRequest = await bufferVerificationRequest(c.req.raw)
  if (verificationRequest === null) {
    return c.json(
      {
        type: "https://erc8128.org/problems/request-body-too-large",
        title: "Request body is too large",
        status: 413,
        detail: `Request bodies are limited to ${MAX_VERIFY_BODY_BYTES} bytes.`
      },
      413,
      { "content-type": "application/problem+json" }
    )
  }
  const verifyMessage = getVerifyMessage(c.env)
  if (!verifyMessage) {
    const problem = formatErc8128ProblemDetails({
      ok: false,
      reason: "signature_verification_unavailable",
      detail: "ERC8128_SECRET_ALCHEMY_ID must be configured."
    })
    return c.json({ ok: false, ...problem }, problem.status)
  }
  const { storageMode } = resolveStorageSelection(
    c.env,
    verificationRequest.headers
  )
  let verificationRuntime: VerificationRuntime | undefined

  try {
    const bindings =
      storageMode === "postgres"
        ? {
            hyperdrive: c.env.HYPERDRIVE?.connectionString,
            databaseUrl: c.env.DATABASE_URL
          }
        : { redisUrl: c.env.REDIS_URL }
    verificationRuntime = await getVerificationRuntime(
      storageMode,
      new URL(c.req.url).origin,
      bindings,
      verifyMessage
    )
    c.set("storageMode", storageMode)
    c.set("verificationRequest", verificationRequest)
    c.set("verificationRuntime", verificationRuntime)
    await next()
  } finally {
    if (verificationRuntime) {
      if (storageMode === "postgres") {
        await verificationRuntime.close()
      } else {
        try {
          c.executionCtx.waitUntil(verificationRuntime.close())
        } catch {
          await verificationRuntime.close()
        }
      }
    }
  }
})

app.on(["GET", "POST", "PUT", "DELETE"], "/verify", async (c) => {
  const { storageMode, verificationRequest, verificationRuntime } = c.var
  const t0 = performance.now()

  try {
    const {
      result: verifyResult,
      responseHeaders,
      cachedVerification
    } = await verificationRuntime.verifyRequest(verificationRequest)

    const verifyMs = Math.round((performance.now() - t0) * 10) / 10
    const response = buildVerifyResultResponse({
      verifyResult,
      responseHeaders,
      metadata: {
        verifyMs,
        storageMode,
        cacheStrategy: verificationRuntime.cacheStrategy,
        cachedVerification
      }
    })

    const res = jsonWithHeaders(c, response)
    res.headers.set("cache-control", "no-store")
    return res
  } catch (error) {
    const verifyMs = Math.round((performance.now() - t0) * 10) / 10
    const response = buildVerifyExceptionResponse({
      error: error instanceof Error || typeof error === "string" ? error : null,
      verifyMs
    })

    const res = jsonWithHeaders(c, response)
    res.headers.set("cache-control", "no-store")
    return res
  }
})

export default {
  fetch: app.fetch,
  scheduled(
    controller: ScheduledController,
    env: CloudflareBindings,
    ctx: ExecutionContext
  ) {
    ctx.waitUntil(
      cleanupExpiredVerificationStorage(
        {
          hyperdrive: env.HYPERDRIVE?.connectionString,
          databaseUrl: env.DATABASE_URL
        },
        new Date(controller.scheduledTime)
      ).then((result) => {
        console.info("[erc8128/site] cron cleanup completed", {
          scheduledTime: new Date(controller.scheduledTime).toISOString(),
          ...result
        })
      })
    )
  }
} satisfies ExportedHandler<CloudflareBindings>
