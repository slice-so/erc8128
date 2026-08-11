import type {
  ComponentIdentifier,
  CoveredComponent,
  ParsedSignatureParams
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { sanitizeUrl, utf8Encode } from "../utilities"
import {
  componentIdentifierEquals,
  normalizeComponentIdentifier,
  serializeComponentIdentifier
} from "./componentIdentifier"
import { parseSignatureInputHeader } from "./createSignatureInput"
import { quoteSfString } from "./serializations"
import {
  canonicalizeSfDictionary,
  parseSfDictionary,
  parseSfInnerList,
  serializeSfMember
} from "./structuredFields"

export function parseSignatureBase(base: string): {
  entries: ReadonlyArray<{
    component: ComponentIdentifier
    name: string
    value: string
  }>
  params: ParsedSignatureParams
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
  const parsedLines: {
    component: ComponentIdentifier
    name: string
    value: string
  }[] = []
  for (const line of lines) {
    const separator = findComponentSeparator(line)
    if (separator < 0) return null
    const identifier = line.slice(0, separator)
    const value = line.slice(separator + 2)
    let component: ComponentIdentifier
    try {
      const parsed = parseSfInnerList(`(${identifier})`)
      const item = parsed.items[0]
      if (
        parsed.items.length !== 1 ||
        item === undefined ||
        typeof item.value !== "string"
      )
        return null
      component = normalizeComponentIdentifier({
        name: item.value,
        ...(Object.keys(item.params ?? {}).length
          ? {
              params: item.params as NonNullable<ComponentIdentifier["params"]>
            }
          : {})
      })
      if (serializeComponentIdentifier(component) !== identifier) return null
    } catch {
      return null
    }
    parsedLines.push({ component, name: component.name, value })
  }
  const signatureParams = parsedLines.at(-1)
  if (signatureParams?.name !== "@signature-params") return null
  const entries = parsedLines.slice(0, -1)
  if (
    new Set(
      entries.map(({ component }) => serializeComponentIdentifier(component))
    ).size !== entries.length
  ) {
    return null
  }
  try {
    if (
      serializeSfMember(parseSfInnerList(signatureParams.value)) !==
      signatureParams.value
    ) {
      return null
    }
    const [member] = parseSignatureInputHeader(
      `request=${signatureParams.value}`
    )
    if (
      member === undefined ||
      member.components.length !== entries.length ||
      member.components.some(
        (component, index) =>
          !componentIdentifierEquals(
            component,
            entries[index]?.component ?? { name: "" }
          )
      ) ||
      member.signatureParamsValue !== signatureParams.value
    ) {
      return null
    }
    return { entries, params: member.params }
  } catch {
    return null
  }
}

function findComponentSeparator(line: string): number {
  let quoted = false
  let escaped = false
  for (let index = 0; index < line.length - 1; index += 1) {
    const character = line[index]
    if (quoted) {
      if (escaped) escaped = false
      else if (character === "\\") escaped = true
      else if (character === '"') quoted = false
      continue
    }
    if (character === '"') quoted = true
    else if (character === ":" && line[index + 1] === " ") return index
  }
  return -1
}

export function createSignatureBaseMinimal(args: {
  request: Request
  components: readonly CoveredComponent[]
  signatureParamsValue: string // the inner-list+params string, e.g. ("@authority"...);created=...;...
}): Uint8Array {
  const { request, components, signatureParamsValue } = args
  const url = sanitizeUrl(request.url)

  const lines: string[] = []
  for (const rawComponent of components) {
    const component = normalizeComponentIdentifier(rawComponent)
    const value = componentValueMinimal({ request, url, component })

    // strict: no CR/LF and only visible ASCII + SP
    if (
      /[^\x20-\x7E]/.test(value) ||
      value.includes("\r") ||
      value.includes("\n")
    ) {
      throw new Erc8128Error(
        "BAD_DERIVED_VALUE",
        `Component ${component.name} produced invalid characters.`
      )
    }
    lines.push(`${serializeComponentIdentifier(component)}: ${value}`)
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
  component: ComponentIdentifier
}): string {
  const { request, url, component } = args

  if (component.params?.req || component.params?.tr || component.params?.name) {
    throw new Erc8128Error(
      "BAD_DERIVED_VALUE",
      `Component ${component.name} uses parameters unavailable in Fetch requests.`
    )
  }

  switch (component.name) {
    case "@scheme": {
      return url.protocol.slice(0, -1).toLowerCase()
    }
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
      const q = url.search || "?"
      ensureNoCrlf(q, "@query")
      return q
    }
    default: {
      // header field component (e.g. content-digest)
      const v = request.headers.get(component.name)
      if (v == null)
        throw new Erc8128Error(
          "BAD_HEADER_VALUE",
          `Required header "${component.name}" is missing.`
        )
      if (component.params?.bs && component.params?.sf) {
        throw new Erc8128Error(
          "BAD_DERIVED_VALUE",
          "The bs and sf component parameters cannot be combined."
        )
      }
      let canonical = canonicalizeFieldValue(v)
      if (component.params?.sf) {
        canonical = component.params.key
          ? serializeSelectedDictionaryMember(v, component.params.key)
          : canonicalizeSfDictionary(v)
      } else if (component.params?.key) {
        throw new Erc8128Error(
          "BAD_DERIVED_VALUE",
          "The key component parameter requires sf."
        )
      }
      if (component.params?.bs) {
        canonical = serializeSfMember({
          value: {
            type: "binary",
            value: new TextEncoder().encode(canonicalizeFieldValue(v))
          }
        })
      }
      ensureNoCrlf(canonical, component.name)
      return canonical
    }
  }
}

function serializeSelectedDictionaryMember(value: string, key: string): string {
  const member = parseSfDictionary(value)[key]
  if (member === undefined) {
    throw new Erc8128Error(
      "BAD_DERIVED_VALUE",
      `Structured Field Dictionary has no ${key} member.`
    )
  }
  return serializeSfMember(member)
}

function canonicalizeFieldValue(v: string): string {
  return v.trim()
}

function ensureNoCrlf(value: string, name: string) {
  if (value.includes("\r") || value.includes("\n")) {
    throw new Erc8128Error("BAD_DERIVED_VALUE", `${name} contains CR/LF.`)
  }
}
