import { env } from "cloudflare:workers"
import { type Context, Hono } from "hono"
import { cors } from "hono/cors"
import { createPublicClient, http } from "viem"
import { mainnet } from "viem/chains"
import {
  cleanupExpiredVerificationStorage,
  getDiscoveryDocument,
  getVerificationRuntime
} from "./lib/erc8128/backend-config"
import { parseStorageMode } from "./lib/erc8128/storage-header"
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
  Variables: {
    storageMode: StorageMode
    verificationRuntime: VerificationRuntime
  }
}

const alchemyRpcUrl = `https://eth-mainnet.g.alchemy.com/v2/${env.SECRET_ALCHEMY_KEY}`

const publicClient = createPublicClient({
  chain: mainnet,
  transport: http(alchemyRpcUrl)
})

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

app.use("/verify", async (c, next) => {
  const storageMode = parseStorageMode(c.req.raw.headers)

  const verificationRuntime = await getVerificationRuntime(
    storageMode,
    new URL(c.req.url).origin,
    {
      hyperdrive: env.HYPERDRIVE.connectionString,
      databaseUrl: env.DATABASE_URL,
      redisUrl: env.REDIS_URL
    },
    publicClient.verifyMessage
  )

  c.set("storageMode", storageMode)
  c.set("verificationRuntime", verificationRuntime)

  try {
    await next()
  } finally {
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
})

app.on(["GET", "POST", "PUT", "DELETE"], "/verify", async (c) => {
  const { storageMode, verificationRuntime } = c.var
  const t0 = performance.now()

  try {
    const {
      result: verifyResult,
      responseHeaders,
      cachedVerification
    } = await verificationRuntime.verifyRequest(c.req.raw)

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
          hyperdrive: env.HYPERDRIVE.connectionString,
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
