import type { Delegation, DelegationLink, Hex } from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { bytesToHex, hexToBytes } from "../utilities"
import {
  MAX_DELEGATION_ARRAY_ENTRIES,
  MAX_DELEGATION_LINK_BYTES,
  MAX_DELEGATION_STRING_BYTES
} from "./limits"

const ARRAY_ELEMENT_COUNT = 14
const UINT32_MAX = 0xffff_ffffn
const MAX_SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER)
const textDecoder = new TextDecoder("utf-8", {
  fatal: true,
  ignoreBOM: true
})
const textEncoder = new TextEncoder()

class LinkEncoder {
  readonly chunks: Uint8Array[] = []
  length = 0

  append(bytes: Uint8Array): void {
    if (this.length + bytes.length > MAX_DELEGATION_LINK_BYTES) {
      throw tooLarge("Delegation Link is too large.")
    }
    this.chunks.push(bytes)
    this.length += bytes.length
  }

  finish(): Uint8Array {
    const output = new Uint8Array(this.length)
    let offset = 0
    for (const chunk of this.chunks) {
      output.set(chunk, offset)
      offset += chunk.length
    }
    return output
  }
}

class LinkDecoder {
  offset = 0

  constructor(readonly bytes: Uint8Array) {
    if (bytes.length > MAX_DELEGATION_LINK_BYTES) {
      throw tooLarge("Delegation Link is too large.")
    }
  }

  readArrayLength(maximum: number, name: string): number {
    const length = this.readHead(4, name)
    if (length > BigInt(maximum)) {
      throw tooLarge(`${name} has too many entries.`)
    }
    return Number(length)
  }

  readBoolean(name: string): boolean {
    const initial = this.readInitial(name)
    if (initial === 0xf4) return false
    if (initial === 0xf5) return true
    throw parseError(`${name} must be Boolean.`)
  }

  readBytes(name: string, expectedLength?: number): Uint8Array {
    const length = this.readHead(2, name)
    this.assertRemaining(length, name)
    if (expectedLength !== undefined && length !== BigInt(expectedLength)) {
      throw parseError(`${name} must contain exactly ${expectedLength} bytes.`)
    }
    const size = Number(length)
    const value = this.bytes.slice(this.offset, this.offset + size)
    this.offset += size
    return value
  }

  readString(name: string): string {
    const length = this.readHead(3, name)
    this.assertRemaining(length, name)
    if (length > BigInt(MAX_DELEGATION_STRING_BYTES)) {
      throw tooLarge(`${name} String is too large.`)
    }
    const size = Number(length)
    const value = this.bytes.subarray(this.offset, this.offset + size)
    this.offset += size
    try {
      return textDecoder.decode(value)
    } catch {
      throw parseError(`${name} contains malformed UTF-8.`)
    }
  }

  readStringArray(name: string): string[] {
    const length = this.readArrayLength(MAX_DELEGATION_ARRAY_ENTRIES, name)
    const values: string[] = []
    for (let index = 0; index < length; index += 1) {
      values.push(this.readString(name))
    }
    return values
  }

  readUint(name: string, maximum = MAX_SAFE_INTEGER): number {
    const value = this.readHead(0, name)
    if (value > maximum) {
      throw parseError(`${name} is outside its supported integer range.`)
    }
    return Number(value)
  }

  private assertRemaining(length: bigint, name: string): void {
    if (length > BigInt(this.bytes.length - this.offset)) {
      throw parseError(`${name} payload is truncated.`)
    }
  }

  private readHead(expectedMajorType: number, name: string): bigint {
    const initial = this.readInitial(name)
    const majorType = initial >> 5
    const additionalInformation = initial & 0x1f
    if (majorType !== expectedMajorType) {
      throw parseError(`${name} has an unsupported CBOR type.`)
    }
    if (additionalInformation < 24) return BigInt(additionalInformation)
    if (additionalInformation === 31) {
      throw parseError("Indefinite-length CBOR is forbidden.")
    }
    if (additionalInformation > 27) {
      throw parseError("Reserved CBOR additional information is forbidden.")
    }
    const byteLength = 1 << (additionalInformation - 24)
    if (this.offset + byteLength > this.bytes.length) {
      throw parseError(`${name} head is truncated.`)
    }
    let value = 0n
    for (let index = 0; index < byteLength; index += 1) {
      value = (value << 8n) | BigInt(this.bytes[this.offset + index] ?? 0)
    }
    this.offset += byteLength
    const shortestMinimum = [24n, 0x100n, 0x1_0000n, 0x1_0000_0000n][
      additionalInformation - 24
    ]
    if (shortestMinimum === undefined || value < shortestMinimum) {
      throw parseError("CBOR heads must use the shortest form.")
    }
    return value
  }

  private readInitial(name: string): number {
    const value = this.bytes[this.offset]
    if (value === undefined) throw parseError(`${name} is truncated.`)
    this.offset += 1
    return value
  }
}

function encodeHead(majorType: number, value: bigint): Uint8Array {
  if (value < 24n) return Uint8Array.of((majorType << 5) | Number(value))
  const byteLength =
    value <= 0xffn ? 1 : value <= 0xffffn ? 2 : value <= UINT32_MAX ? 4 : 8
  const output = new Uint8Array(1 + byteLength)
  output[0] = (majorType << 5) | (23 + Math.log2(byteLength) + 1)
  let remaining = value
  for (let index = output.length - 1; index > 0; index -= 1) {
    output[index] = Number(remaining & 0xffn)
    remaining >>= 8n
  }
  return output
}

function appendBytes(encoder: LinkEncoder, bytes: Uint8Array): void {
  encoder.append(encodeHead(2, BigInt(bytes.length)))
  encoder.append(bytes)
}

function appendString(encoder: LinkEncoder, value: string): void {
  if (!value.isWellFormed()) {
    throw parseError("Delegation strings must contain well-formed Unicode.")
  }
  const bytes = textEncoder.encode(value)
  if (bytes.length > MAX_DELEGATION_STRING_BYTES) {
    throw tooLarge("Delegation String is too large.")
  }
  encoder.append(encodeHead(3, BigInt(bytes.length)))
  encoder.append(bytes)
}

function appendStringArray(
  encoder: LinkEncoder,
  values: readonly string[]
): void {
  if (values.length > MAX_DELEGATION_ARRAY_ENTRIES) {
    throw tooLarge("Delegation Array has too many entries.")
  }
  encoder.append(encodeHead(4, BigInt(values.length)))
  for (const value of values) appendString(encoder, value)
}

function appendUint(encoder: LinkEncoder, value: number): void {
  encoder.append(encodeHead(0, BigInt(value)))
}

export function encodeDelegationLinkCbor(link: DelegationLink): Uint8Array {
  const { grant } = link
  const encoder = new LinkEncoder()
  encoder.append(encodeHead(4, BigInt(ARRAY_ELEMENT_COUNT)))
  appendString(encoder, grant.issuer)
  appendString(encoder, grant.delegate)
  appendStringArray(encoder, grant.audiences)
  appendBytes(encoder, hexToBytes(grant.id))
  appendUint(encoder, grant.epoch)
  appendUint(encoder, grant.validAfter)
  appendUint(encoder, grant.validUntil)
  appendUint(encoder, grant.maxRequestValiditySeconds)
  encoder.append(Uint8Array.of(grant.delegateIsEOA ? 0xf5 : 0xf4))
  encoder.append(Uint8Array.of(grant.requireNonReplayable ? 0xf5 : 0xf4))
  appendStringArray(encoder, grant.requiredComponents)
  appendStringArray(encoder, grant.permissions)
  appendBytes(encoder, hexToBytes(grant.parentGrantHash))
  appendBytes(encoder, hexToBytes(link.signature))
  return encoder.finish()
}

export function decodeDelegationLinkCbor(bytes: Uint8Array): DelegationLink {
  const decoder = new LinkDecoder(bytes)
  if (
    decoder.readArrayLength(MAX_DELEGATION_ARRAY_ENTRIES, "Delegation Link") !==
    ARRAY_ELEMENT_COUNT
  ) {
    throw parseError(
      `Delegation Link must contain ${ARRAY_ELEMENT_COUNT} elements.`
    )
  }
  const grant: Delegation = {
    issuer: decoder.readString("issuer"),
    delegate: decoder.readString("delegate"),
    audiences: decoder.readStringArray("audiences"),
    id: bytesToHex(decoder.readBytes("id", 32)) as Hex,
    epoch: decoder.readUint("epoch"),
    validAfter: decoder.readUint("validAfter"),
    validUntil: decoder.readUint("validUntil"),
    maxRequestValiditySeconds: decoder.readUint(
      "maxRequestValiditySeconds",
      UINT32_MAX
    ),
    delegateIsEOA: decoder.readBoolean("delegateIsEOA"),
    requireNonReplayable: decoder.readBoolean("requireNonReplayable"),
    requiredComponents: decoder.readStringArray("requiredComponents"),
    permissions: decoder.readStringArray("permissions"),
    parentGrantHash: bytesToHex(decoder.readBytes("parentGrantHash", 32)) as Hex
  }
  const signatureBytes = decoder.readBytes("signature")
  if (signatureBytes.length === 0) {
    throw parseError("Delegation proof is empty.")
  }
  if (decoder.offset !== bytes.length) {
    throw parseError("Delegation Link contains trailing bytes.")
  }
  return { grant, signature: bytesToHex(signatureBytes) as Hex }
}

function parseError(message: string): Erc8128Error {
  return new Erc8128Error("PARSE_ERROR", message)
}

function tooLarge(message: string): Erc8128Error {
  return new Erc8128Error("DELEGATION_TOO_LARGE", message)
}
