import { betterAuth } from "@slicekit/better-auth"
import { drizzleAdapter } from "@slicekit/better-auth/adapters/drizzle"
import { erc8128 } from "@slicekit/better-auth/plugins/erc8128"
import { drizzle } from "drizzle-orm/node-postgres"
import { Client } from "pg"
import { createPublicClient, http } from "viem"
import { mainnet } from "viem/chains"
import {
  account,
  erc8128Invalidation,
  session,
  user,
  verification,
  walletAddress
} from "./auth-schema"

const databaseUrl =
  process.env.WRANGLER_HYPERDRIVE_LOCAL_CONNECTION_STRING?.trim() ||
  process.env.DATABASE_URL?.trim()

if (!databaseUrl) {
  throw new Error(
    "[erc8128/site] WRANGLER_HYPERDRIVE_LOCAL_CONNECTION_STRING or DATABASE_URL is required to import src/auth.ts for better-auth migrations"
  )
}

const rpcUrl = `https://eth-mainnet.g.alchemy.com/v2/${process.env.SECRET_ALCHEMY_KEY ?? ""}`

const publicClient = createPublicClient({
  chain: mainnet,
  transport: http(rpcUrl)
})

const client = new Client({ connectionString: databaseUrl })
const authTables = {
  user,
  session,
  account,
  verification,
  walletAddress,
  erc8128Invalidation
}

export const auth = betterAuth({
  baseURL: process.env.BETTER_AUTH_URL ?? "http://localhost:3000",
  database: drizzleAdapter(
    drizzle({
      client,
      casing: "snake_case"
    }),
    {
      provider: "pg",
      schema: authTables
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
