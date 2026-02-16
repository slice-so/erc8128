import {
  createDecipheriv,
  pbkdf2Sync,
  scryptSync,
  timingSafeEqual
} from "node:crypto"
import { readFile } from "node:fs/promises"
import { stdin as input, stdout as output } from "node:process"
import { createInterface } from "node:readline"
import type { EthHttpSigner } from "@slicekit/erc8128"
import type { Hex, PrivateKeyAccount } from "viem"
import { hexToBytes, keccak256 } from "viem"
import { privateKeyToAccount } from "viem/accounts"

export interface WalletOptions {
  privateKey?: string
  keyfile?: string
  keystore?: string
  password?: string
  interactive?: boolean
  chainId: number
}

export async function createSigner(
  opts: WalletOptions
): Promise<EthHttpSigner> {
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
    const password =
      opts.password ??
      process.env.ETH_KEYSTORE_PASSWORD ??
      (opts.interactive ? await promptPassword() : undefined)

    if (!password) {
      throw new Error(
        "Keystore password required. Use --password, set ETH_KEYSTORE_PASSWORD, or pass --interactive to prompt."
      )
    }

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
  password: string,
  chainId: number
): Promise<EthHttpSigner> {
  try {
    const keystoreJson = await readFile(keystorePath, "utf-8")
    const keystore = JSON.parse(keystoreJson) as {
      version?: unknown
      crypto?: Record<string, unknown>
      Crypto?: Record<string, unknown>
    }
    if (keystore.version !== 3) {
      throw new Error(
        `Unsupported keystore version: ${String(keystore.version)}. Expected version 3.`
      )
    }

    const cryptoSection = getKeystoreCryptoSection(keystore)
    const privateKey = decryptKeystorePrivateKey(cryptoSection, password)
    return createSignerFromPrivateKey(privateKey, chainId)
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(
        `Failed to load keystore: ${normalizeKeystoreError(error)}`
      )
    }
    throw error
  }
}

function getKeystoreCryptoSection(keystore: {
  crypto?: Record<string, unknown>
  Crypto?: Record<string, unknown>
}): Record<string, unknown> {
  const cryptoSection = keystore.crypto ?? keystore.Crypto
  if (!cryptoSection || typeof cryptoSection !== "object") {
    throw new Error("Invalid keystore: missing crypto section.")
  }
  return cryptoSection
}

function decryptKeystorePrivateKey(
  cryptoSection: Record<string, unknown>,
  password: string
): `0x${string}` {
  const cipher = getString(cryptoSection.cipher, "cipher")
  if (cipher !== "aes-128-ctr") {
    throw new Error(`Unsupported cipher: ${cipher}. Expected aes-128-ctr.`)
  }

  const ciphertext = hexToBuffer(
    getString(cryptoSection.ciphertext, "ciphertext")
  )
  const mac = normalizeHex(getString(cryptoSection.mac, "mac"))

  const cipherparams = getObject(cryptoSection.cipherparams, "cipherparams")
  const iv = hexToBuffer(getString(cipherparams.iv, "cipherparams.iv"))

  const kdf = getString(cryptoSection.kdf, "kdf")
  const kdfparams = getObject(cryptoSection.kdfparams, "kdfparams")
  const derivedKey = deriveKeystoreKey(password, kdf, kdfparams)

  const computedMac = normalizeHex(
    keccak256(Buffer.concat([derivedKey.subarray(16, 32), ciphertext]))
  )
  if (!timingSafeEqual(Buffer.from(computedMac), Buffer.from(mac))) {
    throw new Error("Invalid keystore password.")
  }

  const decipher = createDecipheriv(
    "aes-128-ctr",
    derivedKey.subarray(0, 16),
    iv
  )
  const privateKeyBytes = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ])

  if (privateKeyBytes.length !== 32) {
    throw new Error(
      "Invalid keystore payload: decrypted private key has wrong length."
    )
  }

  return normalizeHex(privateKeyBytesToHex(privateKeyBytes))
}

function deriveKeystoreKey(
  password: string,
  kdf: string,
  kdfparams: Record<string, unknown>
): Buffer {
  const dklen = getNumber(kdfparams.dklen, "kdfparams.dklen")
  const salt = hexToBuffer(getString(kdfparams.salt, "kdfparams.salt"))

  if (kdf === "scrypt") {
    const n = getNumber(kdfparams.n, "kdfparams.n")
    const r = getNumber(kdfparams.r, "kdfparams.r")
    const p = getNumber(kdfparams.p, "kdfparams.p")
    return scryptSync(password, salt, dklen, { N: n, r, p })
  }

  if (kdf === "pbkdf2") {
    const c = getNumber(kdfparams.c, "kdfparams.c")
    const prf = getString(kdfparams.prf, "kdfparams.prf")
    if (prf !== "hmac-sha256") {
      throw new Error(`Unsupported pbkdf2 prf: ${prf}. Expected hmac-sha256.`)
    }
    return pbkdf2Sync(password, salt, c, dklen, "sha256")
  }

  throw new Error(`Unsupported kdf: ${kdf}. Expected scrypt or pbkdf2.`)
}

function normalizeHex(value: string): `0x${string}` {
  return (
    value.startsWith("0x") ? value.toLowerCase() : `0x${value.toLowerCase()}`
  ) as Hex
}

function hexToBuffer(value: string): Buffer {
  return Buffer.from(hexToBytes(normalizeHex(value)))
}

function privateKeyBytesToHex(privateKeyBytes: Buffer): string {
  return privateKeyBytes.toString("hex")
}

function getObject(value: unknown, key: string): Record<string, unknown> {
  if (!value || typeof value !== "object") {
    throw new Error(`Invalid keystore: missing ${key}.`)
  }
  return value as Record<string, unknown>
}

function getString(value: unknown, key: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Invalid keystore: missing ${key}.`)
  }
  return value
}

function getNumber(value: unknown, key: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`Invalid keystore: missing ${key}.`)
  }
  return value
}

function normalizeKeystoreError(error: Error): string {
  const message = error.message.toLowerCase()
  if (message.includes("invalid keystore password")) {
    return "Invalid keystore password."
  }
  if (message.includes("unexpected token")) {
    return "Invalid keystore JSON."
  }
  return error.message
}

async function promptPassword(): Promise<string> {
  if (!input.isTTY || !output.isTTY) {
    throw new Error(
      "Interactive password prompt requires a TTY. Use --password or set ETH_KEYSTORE_PASSWORD."
    )
  }

  const rl = createInterface({ input, output, terminal: true })
  const mutableRl = rl as unknown as {
    stdoutMuted?: boolean
    _writeToOutput?: (value: string) => void
  }
  mutableRl.stdoutMuted = true
  mutableRl._writeToOutput = (value: string) => {
    if (!mutableRl.stdoutMuted) {
      output.write(value)
      return
    }
    if (value.includes("\n")) {
      output.write(value)
    }
  }

  return new Promise((resolve) => {
    rl.question("Enter keystore password: ", (answer) => {
      mutableRl.stdoutMuted = false
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
