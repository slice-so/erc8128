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
  "@scheme",
  "@authority",
  "@path",
  "@query",
  "content-digest"
]
const params = {
  created: 1_800_000_000,
  expires: 1_800_000_060,
  keyid: "eip155:1:0x0000000000000000000000000000000000000001",
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
        { component: { name: "@method" }, name: "@method", value: "POST" },
        { component: { name: "@scheme" }, name: "@scheme", value: "https" },
        {
          component: { name: "@authority" },
          name: "@authority",
          value: "api.example.test"
        },
        { component: { name: "@path" }, name: "@path", value: "/path" },
        { component: { name: "@query" }, name: "@query", value: "?value=1" },
        {
          component: { name: "content-digest" },
          name: "content-digest",
          value: "sha-256=:AAAA:"
        }
      ],
      params
    })
  })

  it("preserves legal signature-parameter order and unsupported alg for policy checks", () => {
    const reordered = base.replace(
      `;nonce="nonce";keyid="${params.keyid}"`,
      `;keyid="${params.keyid}";nonce="nonce";alg="eip191"`
    )
    expect(parseSignatureBase(reordered)?.params).toEqual({
      created: params.created,
      expires: params.expires,
      keyid: params.keyid,
      nonce: params.nonce,
      alg: "eip191"
    })
  })

  it("rejects duplicate signature parameters without replacing received text", () => {
    const duplicate = base.replace(
      ";expires=1800000060",
      ";created=1800000001;expires=1800000060"
    )
    expect(parseSignatureBase(duplicate)).toBeNull()
  })

  it("rejects unsupported params, escaping, duplicates, and trailing data", () => {
    const cases = [
      base.replace('"@authority":', '"@method":'),
      base.replace(";keyid=", ";extra=1;keyid="),
      base.replace(";created=", "; created="),
      base.replace('"@method"', '"\\@method"'),
      `${base}\n`,
      `${base} trailing`,
      base.replace("\n", "\r\n")
    ]
    for (const candidate of cases)
      expect(parseSignatureBase(candidate)).toBeNull()
  })
})
