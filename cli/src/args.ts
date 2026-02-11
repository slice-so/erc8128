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

  // Wallet options
  privateKey?: string
  keystore?: string
  password?: string
  ledger: boolean
  trezor: boolean

  // ERC-8128 options
  chainId: number
  binding: BindingMode
  replay: ReplayMode
  ttl: number

  // Positional
  url: string
}

export function parseArgs(): CliOptions {
  const program = new Command()

  program
    .name("eth-fetch")
    .description("Sign HTTP requests with ERC-8128 (Ethereum HTTP signatures)")
    .version("0.1.0")
    .argument("<url>", "URL to fetch")
    .option("-X, --request <method>", "HTTP method", "GET")
    .option("-H, --header <header>", "Add header (repeatable)", collect, [])
    .option("-d, --data <data>", "Request body")
    .option("-o, --output <file>", "Write response to file")
    .option("-i, --include", "Include response headers in output", false)
    .option("-v, --verbose", "Show request details", false)
    .option("--private-key <key>", "Raw private key (⚠️  insecure)")
    .option("--keystore <path>", "Path to encrypted keystore file")
    .option("--password <pass>", "Keystore password (or prompts interactively)")
    .option(
      "--ledger",
      "Use Ledger hardware wallet (not yet implemented)",
      false
    )
    .option(
      "--trezor",
      "Use Trezor hardware wallet (not yet implemented)",
      false
    )
    .option("--chain-id <id>", "Chain ID", parseIntOption, 1)
    .option(
      "--binding <mode>",
      "Binding mode: request-bound | class-bound",
      validateBinding,
      "request-bound"
    )
    .option(
      "--replay <mode>",
      "Replay mode: non-replayable | replayable",
      validateReplay,
      "non-replayable"
    )
    .option("--ttl <seconds>", "Signature TTL in seconds", parseIntOption, 60)

  program.parse()

  const url = program.args[0]
  if (!url) {
    program.help()
  }

  const opts = program.opts()

  return {
    method: opts.request.toUpperCase(),
    headers: opts.header,
    data: opts.data,
    output: opts.output,
    include: opts.include,
    verbose: opts.verbose,
    privateKey: opts.privateKey,
    keystore: opts.keystore,
    password: opts.password,
    ledger: opts.ledger,
    trezor: opts.trezor,
    chainId: opts.chainId,
    binding: opts.binding,
    replay: opts.replay,
    ttl: opts.ttl,
    url
  }
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
