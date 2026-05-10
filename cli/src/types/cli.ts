import type { BindingMode, ReplayMode } from "@slicekit/erc8128"

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
  interactive: boolean

  // ERC-8128 options
  chainId: number
  binding: BindingMode
  replay: ReplayMode
  ttl: number
  components: string[]

  // Positional
  url: string
}
