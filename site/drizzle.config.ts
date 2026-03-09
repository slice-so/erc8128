import { existsSync, readFileSync } from "node:fs"
import { resolve } from "node:path"
import { defineConfig } from "drizzle-kit"

function loadEnvFile(filePath: string) {
  if (!existsSync(filePath)) {
    return
  }

  const contents = readFileSync(filePath, "utf8")

  for (const line of contents.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("#")) {
      continue
    }

    const equalsIndex = trimmed.indexOf("=")
    if (equalsIndex === -1) {
      continue
    }

    const key = trimmed.slice(0, equalsIndex).trim()
    const value = trimmed.slice(equalsIndex + 1).trim()

    if (!(key in process.env)) {
      process.env[key] = value
    }
  }
}

loadEnvFile(resolve(process.cwd(), ".env"))

const databaseUrl =
  process.env.WRANGLER_HYPERDRIVE_LOCAL_CONNECTION_STRING?.trim() ||
  process.env.DATABASE_URL?.trim()

if (!databaseUrl) {
  throw new Error(
    "[erc8128/site] WRANGLER_HYPERDRIVE_LOCAL_CONNECTION_STRING or DATABASE_URL is required for Drizzle migrations"
  )
}

export default defineConfig({
  dialect: "postgresql",
  schema: "./src/auth-schema.ts",
  out: "./drizzle",
  dbCredentials: {
    url: databaseUrl
  }
})
