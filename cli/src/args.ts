import { existsSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import path from "node:path"
import type { BindingMode, ReplayMode } from "@slicekit/erc8128"
import { Command } from "commander"

export interface CliOptions {
  // HTTP options
  method: string
  headers: string[]
  data?: string
  output?: string
  include: boolean
  verbose: boolean
  json: boolean
  fail: boolean
  dryRun: boolean

  // Wallet options
  privateKey?: string
  keyfile?: string
  keyid?: string
  keyIdAddress?: string
  keystore?: string
  password?: string
  ledger: boolean
  trezor: boolean

  // ERC-8128 options
  chainId: number
  binding: BindingMode
  replay: ReplayMode
  ttl: number
  components: string[]

  // Positional
  url: string
}

export function parseArgs(
  argv: string[] = process.argv,
  options: { exitOverride?: boolean } = {}
): CliOptions {
  const config = loadConfig(argv)
  const program = new Command()
  let parsed: CliOptions | undefined

  if (options.exitOverride) {
    program.exitOverride()
  }

  program
    .name("erc8128")
    .description("ERC-8128 tools")
    .version("0.1.0")
    .command("curl")
    .description("Sign and send a curl-like HTTP request with ERC-8128")
    .argument("<url>", "URL to fetch")
    .option("--config <path>", "Path to .erc8128rc.json")
    .option("-X, --request <method>", "HTTP method", config.method ?? "GET")
    .option("-H, --header <header>", "Add header (repeatable)", collect, [
      ...(config.headers ?? [])
    ])
    .option(
      "-d, --data <data>",
      "Request body (use @file or @- for stdin)",
      config.data
    )
    .option("-o, --output <file>", "Write response to file", config.output)
    .option(
      "-i, --include",
      "Include response headers in output",
      config.include ?? false
    )
    .option("-v, --verbose", "Show request details", config.verbose ?? false)
    .option("--json", "Output response as JSON", config.json ?? false)
    .option(
      "--dry-run",
      "Sign only, do not send the request",
      config.dryRun ?? false
    )
    .option(
      "--fail",
      "Exit non-zero for non-2xx responses",
      config.fail ?? false
    )
    .option("--private-key <key>", "Raw private key (⚠️  insecure)")
    .option(
      "--keyfile <path>",
      "Path to a raw private key file",
      config.keyfile
    )
    .option(
      "--keyid <keyid>",
      "Expected key id (eip155:chainId:address)",
      config.keyid
    )
    .option(
      "--keystore <path>",
      "Path to encrypted keystore file",
      config.keystore
    )
    .option("--password <pass>", "Keystore password (or prompts interactively)")
    .option(
      "--ledger",
      "Use Ledger hardware wallet (not yet implemented)",
      config.ledger ?? false
    )
    .option(
      "--trezor",
      "Use Trezor hardware wallet (not yet implemented)",
      config.trezor ?? false
    )
    .option("--chain-id <id>", "Chain ID", parseIntOption, config.chainId)
    .option(
      "--binding <mode>",
      "Binding mode: request-bound | class-bound",
      validateBinding,
      config.binding ?? "request-bound"
    )
    .option(
      "--replay <mode>",
      "Replay mode: non-replayable | replayable",
      validateReplay,
      config.replay ?? "non-replayable"
    )
    .option(
      "--ttl <seconds>",
      "Signature TTL in seconds",
      parseIntOption,
      config.ttl ?? 60
    )
    .option(
      "--components <component>",
      "Additional components to sign (repeatable, comma-separated)",
      collect,
      [...(config.components ?? [])]
    )
    .action((url: string, options: Record<string, unknown>) => {
      const keyIdInfo =
        typeof options.keyid === "string"
          ? parseKeyId(options.keyid)
          : undefined
      const chainId = resolveChainId(options.chainId, keyIdInfo)
      const components = normalizeComponents(options.components as string[])

      if (
        (options.binding as BindingMode) === "class-bound" &&
        components.length === 0
      ) {
        throw new Error("components are required for class-bound signatures.")
      }

      parsed = {
        method: String(options.request).toUpperCase(),
        headers: options.header as string[],
        data: options.data as string | undefined,
        output: options.output as string | undefined,
        include: Boolean(options.include),
        verbose: Boolean(options.verbose),
        json: Boolean(options.json),
        fail: Boolean(options.fail),
        dryRun: Boolean(options.dryRun),
        privateKey: options.privateKey as string | undefined,
        keyfile: options.keyfile as string | undefined,
        keyid: options.keyid as string | undefined,
        keyIdAddress: keyIdInfo?.address,
        keystore: options.keystore as string | undefined,
        password: options.password as string | undefined,
        ledger: Boolean(options.ledger),
        trezor: Boolean(options.trezor),
        chainId,
        binding: options.binding as BindingMode,
        replay: options.replay as ReplayMode,
        ttl: options.ttl as number,
        components,
        url
      }
    })

  program.parse(argv)

  if (!parsed) {
    program.help()
    throw new Error("No command provided.")
  }

  return parsed
}

function collect(value: string, previous: string[]): string[] {
  return previous.concat([value])
}

function parseIntOption(value: string): number {
  const parsed = Number.parseInt(value, 10)
  if (Number.isNaN(parsed)) {
    throw new Error(`Invalid number: ${value}`)
  }
  return parsed
}

function resolveChainId(
  chainId: unknown,
  keyIdInfo?: { chainId: number }
): number {
  if (typeof chainId === "number" && keyIdInfo) {
    if (chainId !== keyIdInfo.chainId) {
      throw new Error(
        `Key ID chain ID (${keyIdInfo.chainId}) does not match --chain-id (${chainId}).`
      )
    }
  }
  if (typeof chainId === "number") return chainId
  if (keyIdInfo) return keyIdInfo.chainId
  return 1
}

function validateBinding(value: string): BindingMode {
  if (value !== "request-bound" && value !== "class-bound") {
    throw new Error(
      `Invalid binding mode: ${value}. Must be 'request-bound' or 'class-bound'.`
    )
  }
  return value as BindingMode
}

function validateReplay(value: string): ReplayMode {
  if (value !== "non-replayable" && value !== "replayable") {
    throw new Error(
      `Invalid replay mode: ${value}. Must be 'non-replayable' or 'replayable'.`
    )
  }
  return value as ReplayMode
}

function normalizeComponents(components: string[]): string[] {
  return components
    .flatMap((component) => component.split(","))
    .map((component) => component.trim())
    .filter((component) => component.length > 0)
}

function parseKeyId(value: string): { chainId: number; address: string } {
  const parts = value.split(":")
  if (parts.length !== 3) {
    throw new Error(
      `Invalid keyid format: ${value}. Expected eip155:chainId:address.`
    )
  }

  const [namespace, chainIdRaw, addressRaw] = parts
  if (namespace !== "eip155" && namespace !== "erc8128") {
    throw new Error(
      `Invalid keyid namespace: ${namespace}. Expected eip155 or erc8128.`
    )
  }

  const chainId = parseIntOption(chainIdRaw)
  const address = addressRaw.startsWith("0x") ? addressRaw : `0x${addressRaw}`

  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(`Invalid keyid address: ${addressRaw}.`)
  }

  return { chainId, address: address.toLowerCase() }
}

type CliConfig = {
  method?: string
  headers?: string[]
  data?: string
  output?: string
  include?: boolean
  verbose?: boolean
  json?: boolean
  fail?: boolean
  dryRun?: boolean
  privateKey?: string
  keyfile?: string
  keyid?: string
  keystore?: string
  password?: string
  ledger?: boolean
  trezor?: boolean
  chainId?: number
  binding?: BindingMode
  replay?: ReplayMode
  ttl?: number
  components?: string[]
}

function loadConfig(argv: string[]): CliConfig {
  const configPath = resolveConfigPath(argv)
  if (!configPath) return {}

  try {
    const raw = readFileSync(configPath, "utf-8")
    const parsed = JSON.parse(raw) as CliConfig
    if (!parsed || typeof parsed !== "object") {
      throw new Error("Config must be a JSON object.")
    }

    if (parsed.headers && !Array.isArray(parsed.headers)) {
      throw new Error("Config.headers must be an array of strings.")
    }
    if (parsed.components && !Array.isArray(parsed.components)) {
      throw new Error("Config.components must be an array of strings.")
    }

    return parsed
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to load config: ${error.message}`)
    }
    throw error
  }
}

function resolveConfigPath(argv: string[]): string | undefined {
  const configFlagIndex = argv.findIndex((arg) => arg === "--config")
  if (configFlagIndex !== -1) {
    const value = argv[configFlagIndex + 1]
    if (!value) throw new Error("Missing value for --config.")
    return path.resolve(process.cwd(), value)
  }

  const inlineFlag = argv.find((arg) => arg.startsWith("--config="))
  if (inlineFlag) {
    const value = inlineFlag.split("=").slice(1).join("=")
    if (!value) throw new Error("Missing value for --config.")
    return path.resolve(process.cwd(), value)
  }

  const cwdPath = path.resolve(process.cwd(), ".erc8128rc.json")
  if (existsSync(cwdPath)) return cwdPath

  const homePath = path.join(homedir(), ".erc8128rc.json")
  if (existsSync(homePath)) return homePath

  return undefined
}
