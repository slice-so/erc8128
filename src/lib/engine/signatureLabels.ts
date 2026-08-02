import { Erc8128Error } from "../Erc8128Error"
import {
  parseSignatureHeader,
  parseSignatureInputHeader
} from "./createSignatureInput"

export function collectSignatureLabels(
  signatureInput: string | null,
  signature: string | null
): Set<string> {
  try {
    return new Set([
      ...(signatureInput === null
        ? []
        : parseSignatureInputHeader(signatureInput).map(({ label }) => label)),
      ...(signature === null ? [] : parseSignatureHeader(signature).keys())
    ])
  } catch {
    throw new Erc8128Error(
      "PARSE_ERROR",
      "Existing signature dictionaries are malformed."
    )
  }
}

export function allocateSignatureLabel(
  preferred: string,
  used: ReadonlySet<string>
): string {
  const base = /^[a-z*][a-z0-9_.*-]*$/.test(preferred) ? preferred : "sig"
  if (!used.has(base)) return base
  for (let index = 1; index < 100; index += 1) {
    const candidate = `${base}${index}`
    if (!used.has(candidate)) return candidate
  }
  throw new Erc8128Error(
    "INVALID_OPTIONS",
    "No collision-free signature label available."
  )
}
