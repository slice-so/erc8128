import { Eip8128Error } from "../types.js"
import { sanitizeUrl, utf8Encode } from "../utilities.js"
import { quoteSfString } from "./serializations.js"

export function createSignatureBaseMinimal(args: {
  request: Request
  components: string[]
  signatureParamsValue: string // the inner-list+params string, e.g. ("@authority"...);created=...;...
}): Uint8Array {
  const { request, components, signatureParamsValue } = args
  const url = sanitizeUrl(request.url)

  const lines: string[] = []
  for (const comp of components) {
    const value = componentValueMinimal({ request, url, component: comp })

    // strict: no CR/LF and only visible ASCII + SP
    if (
      /[^\x20-\x7E]/.test(value) ||
      value.includes("\r") ||
      value.includes("\n")
    ) {
      throw new Eip8128Error(
        "BAD_DERIVED_VALUE",
        `Component ${comp} produced invalid characters.`
      )
    }
    lines.push(`${quoteSfString(comp)}: ${value}`)
  }

  const sigParamsLine = `${quoteSfString("@signature-params")}: ${signatureParamsValue}`
  const base = lines.length
    ? `${lines.join("\n")}\n${sigParamsLine}`
    : sigParamsLine
  return utf8Encode(base)
}

function componentValueMinimal(args: {
  request: Request
  url: URL
  component: string
}): string {
  const { request, url, component } = args

  switch (component) {
    case "@method": {
      const m = (request.method || "GET").toUpperCase()
      ensureNoCrlf(m, "@method")
      return m
    }
    case "@authority": {
      const scheme = url.protocol.replace(":", "").toLowerCase()
      const hostname = url.hostname.toLowerCase()
      const port = url.port

      let authority = hostname
      if (port) {
        const p = Number(port)
        const isDefault =
          (scheme === "http" && p === 80) || (scheme === "https" && p === 443)
        if (!isDefault) authority = `${hostname}:${port}`
      }
      ensureNoCrlf(authority, "@authority")
      return authority
    }
    case "@path": {
      const path = url.pathname || "/"
      ensureNoCrlf(path, "@path")
      return path
    }
    case "@query": {
      const q = url.search || ""
      ensureNoCrlf(q, "@query")
      return q
    }
    default: {
      // header field component (e.g. content-digest)
      const v = request.headers.get(component)
      if (v == null)
        throw new Eip8128Error(
          "BAD_HEADER_VALUE",
          `Required header "${component}" is missing.`
        )
      const canon = canonicalizeFieldValue(v)
      ensureNoCrlf(canon, component)
      return canon
    }
  }
}

function canonicalizeFieldValue(v: string): string {
  return v.trim().replace(/[ \t]+/g, " ")
}

function ensureNoCrlf(value: string, name: string) {
  if (value.includes("\r") || value.includes("\n")) {
    throw new Eip8128Error("BAD_DERIVED_VALUE", `${name} contains CR/LF.`)
  }
}
