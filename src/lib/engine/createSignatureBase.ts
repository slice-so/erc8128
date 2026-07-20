import type { SignatureParams } from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { sanitizeUrl, utf8Encode } from "../utilities"
import { parseSignatureInputHeader } from "./createSignatureInput"
import {
  quoteSfString,
  serializeSignatureParamsInnerList
} from "./serializations"

export function parseSignatureBase(base: string): {
  entries: ReadonlyArray<{ name: string; value: string }>
  params: SignatureParams
} | null {
  if (
    base.length === 0 ||
    base.includes("\r") ||
    base.endsWith("\n") ||
    // biome-ignore lint/suspicious/noControlCharactersInRegex: RFC 9421 permits LF delimiters but no other controls.
    /[^\x0A\x20-\x7E]/.test(base)
  ) {
    return null
  }
  const lines = base.split("\n")
  if (lines.length < 2) return null
  const parsedLines: { name: string; value: string }[] = []
  for (const line of lines) {
    const match = /^("(?:[^"\\]|\\["\\])*"): (.*)$/.exec(line)
    if (match === null) return null
    const quotedName = match[1]
    const value = match[2]
    if (quotedName === undefined || value === undefined) return null
    let name = ""
    for (let index = 1; index < quotedName.length - 1; index += 1) {
      const character = quotedName[index]
      if (character === "\\") {
        index += 1
        const escaped = quotedName[index]
        if (escaped !== "\\" && escaped !== '"') return null
        name += escaped
      } else {
        name += character
      }
    }
    if (quoteSfString(name) !== quotedName || name.length === 0) return null
    parsedLines.push({ name, value })
  }
  const signatureParams = parsedLines.at(-1)
  if (signatureParams?.name !== "@signature-params") return null
  const entries = parsedLines.slice(0, -1)
  if (new Set(entries.map(({ name }) => name)).size !== entries.length) {
    return null
  }
  try {
    const [member] = parseSignatureInputHeader(`eth=${signatureParams.value}`)
    if (
      member === undefined ||
      member.components.length !== entries.length ||
      member.components.some(
        (component, index) => component !== entries[index]?.name
      ) ||
      serializeSignatureParamsInnerList(member.components, member.params) !==
        signatureParams.value
    ) {
      return null
    }
    return { entries, params: member.params }
  } catch {
    return null
  }
}

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
      throw new Erc8128Error(
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
        throw new Erc8128Error(
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
    throw new Erc8128Error("BAD_DERIVED_VALUE", `${name} contains CR/LF.`)
  }
}
