import type {
  SfBareItem,
  SfByteSequence,
  SfDictionary,
  SfInnerList,
  SfItem,
  SfMember,
  SfParameters,
  SfToken
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { base64Decode, base64Encode } from "../utilities"

const MAX_FIELD_LENGTH = 65_536
const MAX_DICTIONARY_MEMBERS = 64
const MAX_INNER_LIST_ITEMS = 64
const MAX_PARAMETERS = 32
const MAX_STRING_LENGTH = 4_096
const MAX_BINARY_LENGTH = 65_536

export function parseSfDictionary(value: string): SfDictionary {
  if (value.length === 0 || value.length > MAX_FIELD_LENGTH) {
    throw parseError("Structured Field Dictionary has an invalid size.")
  }

  const parser = new StructuredFieldParser(value)
  const dictionary: SfDictionary = {}
  parser.skipOptionalWhitespace()
  while (!parser.done()) {
    if (Object.keys(dictionary).length >= MAX_DICTIONARY_MEMBERS) {
      throw parseError("Structured Field Dictionary has too many members.")
    }
    const key = parser.parseKey()
    if (dictionary[key] !== undefined) {
      throw parseError(`Duplicate Structured Field Dictionary member: ${key}.`)
    }

    let member: SfMember
    if (parser.peek() === "=") {
      parser.advance()
      member = parser.parseMember()
    } else {
      member = { value: true, params: parser.parseParameters() }
    }
    dictionary[key] = member

    parser.skipOptionalWhitespace()
    if (parser.done()) break
    parser.expect(",")
    parser.skipOptionalWhitespace()
    if (parser.done()) throw parseError("Trailing Dictionary comma.")
  }
  return dictionary
}

export function serializeSfDictionary(dictionary: SfDictionary): string {
  const entries = Object.entries(dictionary)
  if (entries.length === 0 || entries.length > MAX_DICTIONARY_MEMBERS) {
    throw new Erc8128Error(
      "BAD_HEADER_VALUE",
      "Structured Field Dictionary has an invalid member count."
    )
  }
  return entries
    .map(([key, member]) => {
      assertKey(key)
      if (isItem(member) && member.value === true) {
        return `${key}${serializeParameters(member.params)}`
      }
      return `${key}=${serializeMember(member)}`
    })
    .join(", ")
}

export function canonicalizeSfDictionary(value: string): string {
  return serializeSfDictionary(parseSfDictionary(value))
}

export function parseSfInnerList(value: string): SfInnerList {
  if (value.length === 0 || value.length > MAX_FIELD_LENGTH) {
    throw parseError("Structured Field Inner List has an invalid size.")
  }
  const parser = new StructuredFieldParser(value)
  const member = parser.parseMember()
  parser.skipOptionalWhitespace()
  if (!parser.done() || !isInnerList(member)) {
    throw parseError("Expected one complete Structured Field Inner List.")
  }
  return member
}

export function serializeSfMember(member: SfMember): string {
  return serializeMember(member)
}

export function sfToken(value: string): SfToken {
  assertToken(value)
  return { type: "token", value }
}

export function sfBinary(value: Uint8Array): SfByteSequence {
  if (value.length > MAX_BINARY_LENGTH) {
    throw new Erc8128Error("BAD_HEADER_VALUE", "Byte Sequence is too large.")
  }
  return { type: "binary", value }
}

function serializeMember(member: SfMember): string {
  if (isInnerList(member)) {
    if (
      member.items.length === 0 ||
      member.items.length > MAX_INNER_LIST_ITEMS
    ) {
      throw new Erc8128Error(
        "BAD_HEADER_VALUE",
        "Structured Field Inner List has an invalid item count."
      )
    }
    return `(${member.items.map(serializeItem).join(" ")})${serializeParameters(member.params)}`
  }
  return serializeItem(member)
}

function serializeItem(item: SfItem): string {
  return `${serializeBareItem(item.value)}${serializeParameters(item.params)}`
}

function serializeBareItem(item: SfBareItem): string {
  if (typeof item === "string") {
    if (item.length > MAX_STRING_LENGTH) {
      throw new Erc8128Error("BAD_HEADER_VALUE", "String is too large.")
    }
    if (!/^[\x20-\x7E]*$/.test(item)) {
      throw new Erc8128Error(
        "BAD_HEADER_VALUE",
        "Structured Field strings must contain visible ASCII or spaces."
      )
    }
    return `"${item.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`
  }
  if (typeof item === "boolean") return item ? "?1" : "?0"
  if (typeof item === "number") {
    if (!Number.isFinite(item)) {
      throw new Erc8128Error(
        "BAD_HEADER_VALUE",
        "Invalid Structured Field number."
      )
    }
    if (Number.isInteger(item)) {
      if (Math.abs(item) > 999_999_999_999_999) {
        throw new Erc8128Error("BAD_HEADER_VALUE", "Integer is out of range.")
      }
      return String(item)
    }
    if (Math.abs(item) >= 1_000_000_000_000) {
      throw new Erc8128Error("BAD_HEADER_VALUE", "Decimal is out of range.")
    }
    const rounded = Math.round(item * 1_000) / 1_000
    if (rounded !== item) {
      throw new Erc8128Error(
        "BAD_HEADER_VALUE",
        "Decimal has more than three fractional digits."
      )
    }
    return rounded.toFixed(3).replace(/0+$/, "").replace(/\.$/, ".0")
  }
  if (item.type === "token") {
    assertToken(item.value)
    return item.value
  }
  if (item.value.length > MAX_BINARY_LENGTH) {
    throw new Erc8128Error("BAD_HEADER_VALUE", "Byte Sequence is too large.")
  }
  return `:${base64Encode(item.value)}:`
}

function serializeParameters(parameters?: SfParameters): string {
  if (!parameters) return ""
  const entries = Object.entries(parameters)
  if (entries.length > MAX_PARAMETERS) {
    throw new Erc8128Error("BAD_HEADER_VALUE", "Too many parameters.")
  }
  return entries
    .map(([key, value]) => {
      assertKey(key)
      return value === true ? `;${key}` : `;${key}=${serializeBareItem(value)}`
    })
    .join("")
}

function isInnerList(member: SfMember): member is SfInnerList {
  return "items" in member
}

function isItem(member: SfMember): member is SfItem {
  return "value" in member
}

function assertKey(key: string): void {
  if (!/^[a-z*][a-z0-9_.*-]*$/.test(key)) {
    throw new Erc8128Error("BAD_HEADER_VALUE", `Invalid key: ${key}.`)
  }
}

function assertToken(token: string): void {
  if (!/^[A-Za-z*][A-Za-z0-9_.*:/!#$%&'+\-^`|~]*$/.test(token)) {
    throw new Erc8128Error("BAD_HEADER_VALUE", `Invalid token: ${token}.`)
  }
}

function parseError(message: string): Erc8128Error {
  return new Erc8128Error("PARSE_ERROR", message)
}

class StructuredFieldParser {
  private index = 0

  constructor(private readonly source: string) {}

  done(): boolean {
    return this.index === this.source.length
  }

  peek(): string | undefined {
    return this.source[this.index]
  }

  advance(): void {
    this.index += 1
  }

  expect(value: string): void {
    if (this.peek() !== value) throw parseError(`Expected '${value}'.`)
    this.advance()
  }

  skipOptionalWhitespace(): void {
    while (this.peek() === " " || this.peek() === "\t") this.advance()
  }

  parseKey(): string {
    const start = this.index
    const first = this.peek()
    if (first === undefined || !/[a-z*]/.test(first)) {
      throw parseError("Invalid Structured Field key.")
    }
    this.advance()
    while (
      this.peek() !== undefined &&
      /[a-z0-9_.*-]/.test(this.peek() ?? "")
    ) {
      this.advance()
    }
    return this.source.slice(start, this.index)
  }

  parseMember(): SfMember {
    if (this.peek() === "(") return this.parseInnerList()
    return this.parseItem()
  }

  parseItem(): SfItem {
    return { value: this.parseBareItem(), params: this.parseParameters() }
  }

  parseInnerList(): SfInnerList {
    this.expect("(")
    const items: SfItem[] = []
    while (true) {
      while (this.peek() === " ") this.advance()
      if (this.peek() === ")") {
        this.advance()
        break
      }
      if (items.length >= MAX_INNER_LIST_ITEMS) {
        throw parseError("Structured Field Inner List has too many items.")
      }
      items.push(this.parseItem())
      if (this.peek() !== " " && this.peek() !== ")") {
        throw parseError("Inner List items must be separated by spaces.")
      }
    }
    if (items.length === 0) throw parseError("Inner List must not be empty.")
    return { items, params: this.parseParameters() }
  }

  parseParameters(): SfParameters {
    const parameters: SfParameters = {}
    while (this.peek() === ";") {
      if (Object.keys(parameters).length >= MAX_PARAMETERS) {
        throw parseError("Too many Structured Field parameters.")
      }
      this.advance()
      const key = this.parseKey()
      if (parameters[key] !== undefined) {
        throw parseError(`Duplicate Structured Field parameter: ${key}.`)
      }
      if (this.peek() === "=") {
        this.advance()
        parameters[key] = this.parseBareItem()
      } else {
        parameters[key] = true
      }
    }
    return parameters
  }

  parseBareItem(): SfBareItem {
    const next = this.peek()
    if (next === '"') return this.parseString()
    if (next === ":") return this.parseBinary()
    if (next === "?") return this.parseBoolean()
    if (next === "-" || (next !== undefined && /[0-9]/.test(next))) {
      return this.parseNumber()
    }
    return this.parseToken()
  }

  private parseString(): string {
    this.expect('"')
    let result = ""
    while (!this.done()) {
      const character = this.peek()
      this.advance()
      if (character === '"') return result
      if (character === "\\") {
        const escaped = this.peek()
        if (escaped !== '"' && escaped !== "\\") {
          throw parseError("Invalid Structured Field string escape.")
        }
        result += escaped
        this.advance()
      } else {
        if (character === undefined || !/^[\x20-\x7E]$/.test(character)) {
          throw parseError("Invalid Structured Field string character.")
        }
        result += character
      }
      if (result.length > MAX_STRING_LENGTH)
        throw parseError("String is too large.")
    }
    throw parseError("Unterminated Structured Field string.")
  }

  private parseBinary(): SfByteSequence {
    this.expect(":")
    const start = this.index
    while (this.peek() !== undefined && this.peek() !== ":") this.advance()
    if (this.done()) throw parseError("Unterminated Byte Sequence.")
    const encoded = this.source.slice(start, this.index)
    this.advance()
    if (
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
        encoded
      )
    ) {
      throw parseError("Invalid base64 Byte Sequence.")
    }
    const decoded = base64Decode(encoded)
    if (decoded === null || base64Encode(decoded) !== encoded) {
      throw parseError("Non-canonical Byte Sequence.")
    }
    if (decoded.length > MAX_BINARY_LENGTH)
      throw parseError("Byte Sequence is too large.")
    return { type: "binary", value: decoded }
  }

  private parseBoolean(): boolean {
    this.expect("?")
    const value = this.peek()
    if (value !== "0" && value !== "1") throw parseError("Invalid Boolean.")
    this.advance()
    return value === "1"
  }

  private parseNumber(): number {
    const start = this.index
    if (this.peek() === "-") this.advance()
    const integerStart = this.index
    while (this.peek() !== undefined && /[0-9]/.test(this.peek() ?? ""))
      this.advance()
    const integerDigits = this.index - integerStart
    if (integerDigits === 0 || integerDigits > 15)
      throw parseError("Invalid Integer.")
    if (this.peek() === ".") {
      if (integerDigits > 12) throw parseError("Invalid Decimal.")
      this.advance()
      const fractionStart = this.index
      while (this.peek() !== undefined && /[0-9]/.test(this.peek() ?? ""))
        this.advance()
      const fractionDigits = this.index - fractionStart
      if (fractionDigits === 0 || fractionDigits > 3)
        throw parseError("Invalid Decimal.")
    }
    const value = Number(this.source.slice(start, this.index))
    if (!Number.isFinite(value)) throw parseError("Invalid number.")
    return value
  }

  private parseToken(): SfToken {
    const start = this.index
    const first = this.peek()
    if (first === undefined || !/[A-Za-z*]/.test(first))
      throw parseError("Invalid token.")
    this.advance()
    while (
      this.peek() !== undefined &&
      /[A-Za-z0-9_.*:/!#$%&'+\-^`|~]/.test(this.peek() ?? "")
    ) {
      this.advance()
    }
    return { type: "token", value: this.source.slice(start, this.index) }
  }
}
