import { describe, expect, test } from "bun:test"
import {
  canonicalizeSfDictionary,
  parseSfDictionary,
  serializeSfDictionary,
  sfBinary,
  sfToken
} from "./structuredFields"

describe("RFC 9651 Structured Fields", () => {
  test("round trips the Dictionary subset used by delegation", () => {
    const dictionary = {
      flag: { value: true, params: { enabled: true } },
      identity: {
        value: "eip155:1:0x0000000000000000000000000000000000000001"
      },
      id: { value: sfBinary(new Uint8Array(32).fill(7)) },
      posture: {
        items: [
          { value: "@query", params: { req: true } },
          { value: sfToken("content-digest") }
        ],
        params: { version: 1 }
      }
    }
    const serialized = serializeSfDictionary(dictionary)
    expect(serializeSfDictionary(parseSfDictionary(serialized))).toBe(
      serialized
    )
    expect(
      canonicalizeSfDictionary(
        `flag;enabled,\t${serialized.slice(serialized.indexOf("identity"))}`
      )
    ).toBe(serialized)
  })

  test("canonicalizes whitespace and applies last-wins duplicates", () => {
    expect(canonicalizeSfDictionary('a="one",\tb=("two"  "three");p')).toBe(
      'a="one", b=("two" "three");p'
    )
    expect(parseSfDictionary("a=?1, a=?0")).toEqual({
      a: { value: false, params: {} }
    })
    expect(() => parseSfDictionary('a=("one", "two")')).toThrow()
    expect(() => parseSfDictionary("a=:AQ:")).toThrow()
  })
})
