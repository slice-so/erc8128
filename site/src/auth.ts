import { env } from "cloudflare:workers"
import { betterAuth } from "@slicekit/better-auth"
import { drizzleAdapter } from "@slicekit/better-auth/adapters/drizzle"
import { erc8128 } from "@slicekit/better-auth/plugins/erc8128"
import { drizzle } from "drizzle-orm/node-postgres"
import { Client } from "pg"
import { createPublicClient, http } from "viem"
import { mainnet } from "viem/chains"
import * as authSchema from "./auth-schema"

const databaseUrl = env.HYPERDRIVE?.connectionString.trim()

if (!databaseUrl) {
  throw new Error(
    "[erc8128/site] HYPERDRIVE is required to import src/auth.ts for better-auth migrations"
  )
}

const rpcUrl = `https://eth-mainnet.g.alchemy.com/v2/${process.env.SECRET_ALCHEMY_KEY ?? ""}`

const publicClient = createPublicClient({
  chain: mainnet,
  transport: http(rpcUrl)
})

const client = new Client({ connectionString: databaseUrl })

export const auth = betterAuth({
  baseURL: process.env.BETTER_AUTH_URL ?? "http://localhost:3000",
  database: drizzleAdapter(
    drizzle({
      client,
      casing: "snake_case"
    }),
    {
      provider: "pg",
      schema: authSchema
    }
  ),
  plugins: [
    erc8128({
      verifyMessage: publicClient.verifyMessage,
      routePolicy: {
        "/verify": [
          {
            methods: ["GET", "POST", "PUT"],
            replayable: true,
            classBoundPolicies: ["@authority"]
          },
          {
            methods: ["DELETE"],
            replayable: false
          }
        ]
      }
    })
  ]
})
