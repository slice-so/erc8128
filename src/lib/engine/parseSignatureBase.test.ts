import { describe, expect, it } from "bun:test"
import {
  createSignatureBaseMinimal,
  parseSignatureBase
} from "./createSignatureBase"
import { serializeSignatureParamsInnerList } from "./serializations"

const request = new Request("https://api.example.test/path?value=1", {
  headers: { "content-digest": "sha-256=:AAAA:" },
  method: "POST"
})
const components = [
  "@method",
  "@authority",
  "@path",
  "@query",
  "content-digest"
]
const params = {
  created: 1_800_000_000,
  expires: 1_800_000_060,
  keyid: "erc8128:1:0x0000000000000000000000000000000000000001",
  nonce: "nonce"
}
const signatureParamsValue = serializeSignatureParamsInnerList(
  components,
  params
)
const base = new TextDecoder().decode(
  createSignatureBaseMinimal({ request, components, signatureParamsValue })
)

describe("parseSignatureBase", () => {
  it("differentially parses the backend signature-base builder", () => {
    expect(parseSignatureBase(base)).toEqual({
      entries: [
        { name: "@method", value: "POST" },
        { name: "@authority", value: "api.example.test" },
        { name: "@path", value: "/path" },
        { name: "@query", value: "?value=1" },
        { name: "content-digest", value: "sha-256=:AAAA:" }
      ],
      params
    })
  })

  it("rejects duplicates, noncanonical params, escaping, and trailing data", () => {
    const cases = [
      base.replace('"@authority":', '"@method":'),
      base.replace(
        ";expires=1800000060",
        ";created=1800000001;expires=1800000060"
      ),
      base.replace(";keyid=", ";extra=1;keyid="),
      base.replace('"@method"', '"\\@method"'),
      `${base}\n`,
      `${base} trailing`,
      base.replace("\n", "\r\n")
    ]
    for (const candidate of cases)
      expect(parseSignatureBase(candidate)).toBeNull()
  })
})
