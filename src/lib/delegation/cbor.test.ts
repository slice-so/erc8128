import { describe, expect, test } from "bun:test"
import type { DelegationLink } from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { bytesToHex, hexToBytes } from "../utilities"
import { completeDelegationGrant } from "./createDelegationGrant"
import {
  decodeDelegationLink,
  encodeDelegationLink,
  getDelegationTypedData,
  hashDelegation
} from "./delegationField"

const link: DelegationLink = {
  grant: {
    root: `eip155:1:0x${"11".repeat(20)}`,
    delegate: `eip155:1:0x${"22".repeat(20)}`,
    aud: ["https://api.example"],
    id: `0x${"33".repeat(32)}`,
    epoch: 7,
    created: 10,
    expires: 20,
    maxAge: 1,
    delegateIsEOA: true,
    allowReplayable: false,
    components: [],
    scope: [],
    parent: `0x${"00".repeat(32)}`
  },
  signature: "0x01"
}

const concatenate = (...parts: readonly Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(
    parts.reduce((length, part) => length + part.length, 0)
  )
  let offset = 0
  for (const part of parts) {
    output.set(part, offset)
    offset += part.length
  }
  return output
}

const findBytes = (bytes: Uint8Array, needle: Uint8Array): number => {
  for (let offset = 0; offset <= bytes.length - needle.length; offset += 1) {
    if (needle.every((value, index) => bytes[offset + index] === value)) {
      return offset
    }
  }
  throw new Error("Expected CBOR subsequence was not found.")
}

const replaceBytes = (
  bytes: Uint8Array,
  offset: number,
  removed: number,
  replacement: Uint8Array
): Uint8Array =>
  concatenate(
    bytes.slice(0, offset),
    replacement,
    bytes.slice(offset + removed)
  )

const expectErrorCode = (
  operation: () => void,
  expected: "DELEGATION_TOO_LARGE" | "PARSE_ERROR"
) => {
  let code: Erc8128Error["code"] | undefined
  try {
    operation()
  } catch (error) {
    if (error instanceof Erc8128Error) code = error.code
  }
  expect(code).toBe(expected)
}

describe("deterministic Delegation Link CBOR", () => {
  test("rejects the previous ABI framing without a fallback", () => {
    expectErrorCode(
      () => decodeDelegationLink(Uint8Array.of(0x00, 0x00, 0x00, 0x40)),
      "PARSE_ERROR"
    )
  })

  test("uses shortest integer heads at every supported breakpoint", () => {
    const cases = [
      [23, "0x17"],
      [24, "0x1818"],
      [255, "0x18ff"],
      [256, "0x190100"],
      [65_535, "0x19ffff"],
      [65_536, "0x1a00010000"],
      [Number.MAX_SAFE_INTEGER, "0x1b001fffffffffffff"]
    ] as const
    for (const [epoch, expected] of cases) {
      const candidate = {
        ...link,
        grant: { ...link.grant, epoch }
      }
      const encoded = encodeDelegationLink(candidate)
      const id = concatenate(
        Uint8Array.of(0x58, 0x20),
        hexToBytes(link.grant.id)
      )
      const epochOffset = findBytes(encoded, id) + id.length
      const expectedBytes = hexToBytes(expected)
      expect(
        bytesToHex(
          encoded.slice(epochOffset, epochOffset + expectedBytes.length)
        )
      ).toBe(expected)
      expect(decodeDelegationLink(encoded)).toEqual(candidate)
    }
  })

  test("has an exact encoded length for a representative large proof", () => {
    const signature = Uint8Array.from(
      { length: 1_400 },
      (_, index) => index % 251
    )
    const encoded = encodeDelegationLink({
      ...link,
      signature: bytesToHex(signature)
    })
    expect(encoded).toHaveLength(1_607)
    expect(decodeDelegationLink(encoded).signature).toBe(bytesToHex(signature))
  })

  test("rejects non-deterministic, unsupported, and truncated CBOR", () => {
    const encoded = encodeDelegationLink(link)
    const id = concatenate(Uint8Array.of(0x58, 0x20), hexToBytes(link.grant.id))
    const epochOffset = findBytes(encoded, id) + id.length
    const booleanOffset = findBytes(
      encoded,
      Uint8Array.of(0xf5, 0xf4, 0x80, 0x80)
    )
    const scalarOffset = findBytes(
      encoded,
      Uint8Array.of(0x07, 0x0a, 0x14, 0x01, 0xf5)
    )
    const cases = [
      replaceBytes(encoded, 1, 2, Uint8Array.of(0x79, 0x00, 0x33)),
      replaceBytes(encoded, epochOffset, 1, Uint8Array.of(0x18, 0x07)),
      replaceBytes(encoded, epochOffset, 1, hexToBytes("0x1b0020000000000000")),
      replaceBytes(
        encoded,
        scalarOffset + 3,
        1,
        hexToBytes("0x1b0000000100000000")
      ),
      replaceBytes(encoded, 0, 1, Uint8Array.of(0x9f)),
      replaceBytes(encoded, 1, 1, Uint8Array.of(0x7f)),
      replaceBytes(encoded, 0, 1, Uint8Array.of(0xae)),
      replaceBytes(encoded, 0, 1, Uint8Array.of(0xc0)),
      replaceBytes(encoded, 0, 1, Uint8Array.of(0xf9, 0x00, 0x00)),
      replaceBytes(encoded, 0, 1, Uint8Array.of(0x20)),
      replaceBytes(encoded, 0, 1, Uint8Array.of(0xf6)),
      replaceBytes(encoded, 0, 1, Uint8Array.of(0x8d)),
      replaceBytes(encoded, booleanOffset, 1, Uint8Array.of(0xf6)),
      replaceBytes(encoded, encoded.length - 2, 2, Uint8Array.of(0x5f)),
      concatenate(encoded, Uint8Array.of(0x00)),
      Uint8Array.of(0x9b),
      Uint8Array.of(0x8e, 0x78, 0x33)
    ]
    for (const malformed of cases) {
      expectErrorCode(() => decodeDelegationLink(malformed), "PARSE_ERROR")
    }
    for (const reserved of [0x9c, 0x9d, 0x9e]) {
      expectErrorCode(
        () => decodeDelegationLink(Uint8Array.of(reserved)),
        "PARSE_ERROR"
      )
    }
  })

  test("rejects malformed UTF-8 and malformed fixed-width byte strings", () => {
    const encoded = encodeDelegationLink(link)
    const malformedUtf8 = encoded.slice()
    malformedUtf8[3] = 0xff
    expectErrorCode(() => decodeDelegationLink(malformedUtf8), "PARSE_ERROR")

    const idHead = findBytes(
      encoded,
      concatenate(Uint8Array.of(0x58, 0x20), hexToBytes(link.grant.id))
    )
    expectErrorCode(
      () =>
        decodeDelegationLink(
          replaceBytes(encoded, idHead, 2, Uint8Array.of(0x58, 0x1f))
        ),
      "PARSE_ERROR"
    )
    const parentHead = findBytes(
      encoded,
      concatenate(Uint8Array.of(0x58, 0x20), hexToBytes(link.grant.parent))
    )
    expectErrorCode(
      () =>
        decodeDelegationLink(
          replaceBytes(encoded, parentHead, 2, Uint8Array.of(0x58, 0x1f))
        ),
      "PARSE_ERROR"
    )
    expectErrorCode(
      () =>
        decodeDelegationLink(
          replaceBytes(encoded, encoded.length - 2, 2, Uint8Array.of(0x40))
        ),
      "PARSE_ERROR"
    )
  })

  test("preserves a leading Unicode byte-order mark as string content", () => {
    const candidate = {
      ...link,
      grant: { ...link.grant, scope: ["\ufeffresource:read"] }
    }
    expect(decodeDelegationLink(encodeDelegationLink(candidate))).toEqual(
      candidate
    )
  })

  test("enforces string, array, link, and issuance limits", () => {
    const oversizedString = concatenate(
      Uint8Array.of(0x8e, 0x79, 0x01, 0x01),
      new Uint8Array(257).fill(0x61)
    )
    expectErrorCode(
      () => decodeDelegationLink(oversizedString),
      "DELEGATION_TOO_LARGE"
    )

    const encoded = encodeDelegationLink(link)
    const rootLength = new TextEncoder().encode(link.grant.root).length
    const delegateLength = new TextEncoder().encode(link.grant.delegate).length
    const audienceOffset = 1 + 2 + rootLength + 2 + delegateLength
    expectErrorCode(
      () =>
        decodeDelegationLink(
          replaceBytes(encoded, audienceOffset, 1, Uint8Array.of(0x98, 0x21))
        ),
      "DELEGATION_TOO_LARGE"
    )

    const oversizedSignature = new Uint8Array(8_192).fill(1)
    expectErrorCode(
      () =>
        encodeDelegationLink({
          ...link,
          signature: bytesToHex(oversizedSignature)
        }),
      "DELEGATION_TOO_LARGE"
    )
    expectErrorCode(
      () =>
        completeDelegationGrant(
          {
            grant: link.grant,
            digest: hashDelegation(link.grant),
            typedData: getDelegationTypedData(link.grant)
          },
          oversizedSignature
        ),
      "DELEGATION_TOO_LARGE"
    )
    expectErrorCode(
      () => decodeDelegationLink(new Uint8Array(8_193)),
      "DELEGATION_TOO_LARGE"
    )
  })

  test("rejects unpaired UTF-16 surrogates before encoding", () => {
    expectErrorCode(
      () =>
        encodeDelegationLink({
          ...link,
          grant: { ...link.grant, scope: ["\ud800"] }
        }),
      "PARSE_ERROR"
    )
  })
})
