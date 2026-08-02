import { DELEGATION_FIELD_NAME } from "./delegation/delegationField"

export const redirectStatuses = new Set([301, 302, 303, 307, 308])

export function redirectMethod(status: number, method: string): string {
  if (status === 303 && method !== "HEAD") return "GET"
  if ((status === 301 || status === 302) && method === "POST") return "GET"
  return method
}

export function unsignedRedirectHeaders(
  input: Headers,
  delegated = false
): Headers {
  const headers = new Headers(input)
  headers.delete("signature")
  headers.delete("signature-input")
  headers.delete("content-digest")
  headers.delete("content-length")
  if (delegated) headers.delete(DELEGATION_FIELD_NAME)
  return headers
}
