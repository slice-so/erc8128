const sealedPayloadVersion = "v1"
const ivByteLength = 12
const encoder = new TextEncoder()
const decoder = new TextDecoder()

const base64UrlEncode = (bytes: Uint8Array) => {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "")
}

const base64UrlDecode = (value: string) => {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/")
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4)
  return Uint8Array.from(atob(`${normalized}${padding}`), (character) =>
    character.charCodeAt(0)
  )
}

const getSealingKey = async ({
  secret,
  usage
}: {
  secret: string
  usage: "decrypt" | "encrypt"
}) => {
  if (!secret.trim()) throw new Error("Sealing secret is required.")
  const keyBytes = await crypto.subtle.digest("SHA-256", encoder.encode(secret))
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, [
    usage
  ])
}

export const sealPayload = async <Payload>({
  payload,
  secret
}: {
  payload: Payload
  secret: string
}) => {
  const key = await getSealingKey({ secret, usage: "encrypt" })
  const iv = crypto.getRandomValues(new Uint8Array(ivByteLength))
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(payload))
  )
  const sealed = new Uint8Array(iv.byteLength + ciphertext.byteLength)
  sealed.set(iv)
  sealed.set(new Uint8Array(ciphertext), iv.byteLength)
  return `${sealedPayloadVersion}.${base64UrlEncode(sealed)}`
}

export const openSealedPayload = async <Payload>({
  isExpired,
  secret,
  value
}: {
  isExpired?: (payload: Payload) => boolean
  secret: string
  value: string | null | undefined
}): Promise<Payload | null> => {
  if (!value) return null
  const [version, encoded] = value.split(".")
  if (version !== sealedPayloadVersion || !encoded) return null
  try {
    const sealed = base64UrlDecode(encoded)
    const key = await getSealingKey({ secret, usage: "decrypt" })
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: sealed.slice(0, ivByteLength) },
      key,
      sealed.slice(ivByteLength)
    )
    const payload = JSON.parse(decoder.decode(plaintext)) as Payload
    return isExpired?.(payload) ? null : payload
  } catch {
    return null
  }
}
