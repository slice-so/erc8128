import { base64UrlEncode, randomBytes, utf8Encode } from "../lib/utilities"
import type {
  CreateSessionGrantMessageParameters,
  SessionGrant,
  ValidateSessionGrantExpected
} from "../types"

export const defaultSessionGrantTtlSeconds = 30 * 24 * 60 * 60
const maximumMessageBytes = 4_096
const scopePattern = /^[a-z0-9][a-z0-9_.:-]{0,63}$/
const addressPattern = /^0x[0-9a-fA-F]{40}$/

const canonicalOrigin = (value: string) => {
  const url = new URL(value)
  if (
    url.origin !== value ||
    (url.protocol !== "https:" && url.hostname !== "localhost")
  ) {
    throw new Error("Session grant origins must be canonical secure origins.")
  }
  return value
}

const canonicalAddress = (value: string) => {
  if (!addressPattern.test(value))
    throw new Error("Session grant address is invalid.")
  return value.toLowerCase() as `0x${string}`
}

const canonicalScopes = (values: readonly string[]) => {
  if (values.length > 16 || values.some((value) => !scopePattern.test(value))) {
    throw new Error("Session grant scopes are invalid.")
  }
  const sorted = [...values].sort()
  if (new Set(sorted).size !== sorted.length) {
    throw new Error("Session grant scopes must be unique.")
  }
  return sorted
}

const assertInteger = (value: number, label: string) => {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer.`)
  }
  return value
}

export const createSessionGrantMessage = (
  input: CreateSessionGrantMessageParameters
) => {
  const grant: SessionGrant = {
    account: canonicalAddress(input.account),
    appOrigin: canonicalOrigin(input.appOrigin),
    audience: canonicalOrigin(input.audience),
    chainId: assertInteger(input.chainId, "Chain ID"),
    expiresAt: assertInteger(input.expiresAt, "Expires At"),
    issuedAt: assertInteger(input.issuedAt, "Issued At"),
    nonce: input.nonce,
    scopes: canonicalScopes(input.scopes),
    sessionSigner: canonicalAddress(input.sessionSigner),
    signerScheme: "eoa",
    version: 1
  }
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(grant.nonce)) {
    throw new Error("Session grant nonce is invalid.")
  }
  if (grant.expiresAt <= grant.issuedAt) {
    throw new Error("Session grant expiry must follow issuance.")
  }
  const message = [
    "Sign in with Slice",
    "",
    "Authorize this application to use an ERC-8128 session.",
    "",
    "Version: 1",
    `App Origin: ${grant.appOrigin}`,
    `Audience: ${grant.audience}`,
    `Account: ${grant.account}`,
    `Session Signer: ${grant.sessionSigner}`,
    "Signer Scheme: eoa",
    `Chain ID: ${grant.chainId}`,
    `Scopes: ${grant.scopes.join(" ")}`,
    `Issued At: ${grant.issuedAt}`,
    `Expires At: ${grant.expiresAt}`,
    `Nonce: ${grant.nonce}`
  ].join("\n")
  if (utf8Encode(message).length > maximumMessageBytes) {
    throw new Error("Session grant message exceeds 4096 bytes.")
  }
  return message
}

export const parseSessionGrantMessage = (
  message: string
): SessionGrant | null => {
  if (
    utf8Encode(message).length > maximumMessageBytes ||
    message.includes("\r")
  )
    return null
  const lines = message.split("\n")
  if (
    lines.length !== 15 ||
    lines[0] !== "Sign in with Slice" ||
    lines[1] !== "" ||
    lines[2] !== "Authorize this application to use an ERC-8128 session." ||
    lines[3] !== "" ||
    lines[4] !== "Version: 1" ||
    lines[9] !== "Signer Scheme: eoa"
  )
    return null
  const field = (index: number, prefix: string) =>
    lines[index]?.startsWith(prefix)
      ? lines[index]?.slice(prefix.length)
      : undefined
  const appOrigin = field(5, "App Origin: ")
  const audience = field(6, "Audience: ")
  const account = field(7, "Account: ")
  const sessionSigner = field(8, "Session Signer: ")
  const chainId = Number(field(10, "Chain ID: "))
  const scopesValue = field(11, "Scopes: ")
  const issuedAt = Number(field(12, "Issued At: "))
  const expiresAt = Number(field(13, "Expires At: "))
  const nonce = field(14, "Nonce: ")
  if (
    appOrigin === undefined ||
    audience === undefined ||
    account === undefined ||
    sessionSigner === undefined ||
    scopesValue === undefined ||
    nonce === undefined
  )
    return null
  try {
    const canonical = createSessionGrantMessage({
      account: canonicalAddress(account),
      appOrigin,
      audience,
      chainId,
      expiresAt,
      issuedAt,
      nonce,
      scopes: scopesValue === "" ? [] : scopesValue.split(" "),
      sessionSigner: canonicalAddress(sessionSigner)
    })
    if (canonical !== message) return null
    return {
      account: canonicalAddress(account),
      appOrigin,
      audience,
      chainId,
      expiresAt,
      issuedAt,
      nonce,
      scopes: scopesValue === "" ? [] : scopesValue.split(" "),
      sessionSigner: canonicalAddress(sessionSigner),
      signerScheme: "eoa",
      version: 1
    }
  } catch {
    return null
  }
}

export const validateSessionGrant = (
  grant: SessionGrant,
  expected: ValidateSessionGrantExpected
) => {
  const now = expected.now ?? Math.floor(Date.now() / 1000)
  const skew = expected.clockSkewSeconds ?? 60
  const maxTtl = expected.maxTtlSeconds ?? defaultSessionGrantTtlSeconds
  const expectedScopes = canonicalScopes(expected.scopes ?? [])
  return (
    grant.appOrigin === canonicalOrigin(expected.appOrigin) &&
    grant.audience === canonicalOrigin(expected.audience) &&
    grant.account === canonicalAddress(expected.account) &&
    grant.chainId === expected.chainId &&
    (expected.sessionSigner === undefined ||
      grant.sessionSigner === canonicalAddress(expected.sessionSigner)) &&
    grant.scopes.length === expectedScopes.length &&
    grant.scopes.every((scope, index) => scope === expectedScopes[index]) &&
    grant.issuedAt <= now + skew &&
    grant.expiresAt >= now - skew &&
    grant.expiresAt - grant.issuedAt <= maxTtl
  )
}

export const createSessionGrantNonce = () => base64UrlEncode(randomBytes(32))
