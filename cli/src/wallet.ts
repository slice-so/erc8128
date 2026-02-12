import { readFile } from "node:fs/promises"
import { stdin as input, stdout as output } from "node:process"
import { createInterface } from "node:readline"
import type { EthHttpSigner } from "@slicekit/erc8128"
import type { PrivateKeyAccount } from "viem"
import { privateKeyToAccount } from "viem/accounts"

export interface WalletOptions {
  privateKey?: string
  keyfile?: string
  keystore?: string
  password?: string
  ledger: boolean
  trezor: boolean
  chainId: number
}

export async function createSigner(
  opts: WalletOptions
): Promise<EthHttpSigner> {
  // Check for hardware wallets (not yet implemented)
  if (opts.ledger) {
    throw new Error("Ledger support is not yet implemented")
  }
  if (opts.trezor) {
    throw new Error("Trezor support is not yet implemented")
  }

  // Try private key from options
  if (opts.privateKey) {
    console.error(
      "⚠️  Warning: Using raw private key is insecure. Consider using --keystore instead."
    )
    return createSignerFromPrivateKey(opts.privateKey, opts.chainId)
  }

  // Try private key from file
  if (opts.keyfile) {
    const key = await readKeyFile(opts.keyfile)
    return createSignerFromPrivateKey(key, opts.chainId)
  }

  // Try keystore
  if (opts.keystore) {
    const password = opts.password ?? (await promptPassword())
    return createSignerFromKeystore(opts.keystore, password, opts.chainId)
  }

  // Try environment variable
  const envKey = process.env.ETH_PRIVATE_KEY
  if (envKey) {
    console.error(
      "⚠️  Warning: Using raw private key from ETH_PRIVATE_KEY is insecure. Consider using --keystore instead."
    )
    return createSignerFromPrivateKey(envKey, opts.chainId)
  }

  throw new Error(
    "No wallet specified. Use --keyfile, --private-key, --keystore, or set ETH_PRIVATE_KEY environment variable."
  )
}

function createSignerFromPrivateKey(
  privateKey: string,
  chainId: number
): EthHttpSigner {
  const normalizedKey = privateKey.startsWith("0x")
    ? (privateKey as `0x${string}`)
    : (`0x${privateKey}` as `0x${string}`)

  const account = privateKeyToAccount(normalizedKey)

  return accountToSigner(account, chainId)
}

async function createSignerFromKeystore(
  keystorePath: string,
  _password: string,
  _chainId: number
): Promise<EthHttpSigner> {
  try {
    const keystoreJson = await readFile(keystorePath, "utf-8")
    const _keystore = JSON.parse(keystoreJson)

    // Use viem's decryption if available, otherwise implement basic v3 decryption
    // For now, we'll throw an error suggesting manual decryption
    throw new Error(
      "Keystore decryption not yet implemented. Please extract your private key manually and use --private-key."
    )
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to load keystore: ${error.message}`)
    }
    throw error
  }
}

async function promptPassword(): Promise<string> {
  const rl = createInterface({ input, output })

  return new Promise((resolve) => {
    // Note: This won't hide the password input. For production, consider using 'read' package
    rl.question("Enter keystore password: ", (answer) => {
      rl.close()
      resolve(answer)
    })
  })
}

async function readKeyFile(path: string): Promise<string> {
  const key =
    path === "-"
      ? await readStdin()
      : await readFile(path, { encoding: "utf-8" })

  return key.trim()
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  }
  return Buffer.concat(chunks).toString("utf-8")
}

function accountToSigner(
  account: PrivateKeyAccount,
  chainId: number
): EthHttpSigner {
  return {
    address: account.address,
    chainId,
    signMessage: async (message: Uint8Array): Promise<`0x${string}`> => {
      // EIP-191 personal sign
      return account.signMessage({
        message: { raw: Buffer.from(message) }
      })
    }
  }
}
