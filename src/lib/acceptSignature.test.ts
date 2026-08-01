import { describe, expect, test } from "bun:test"
import {
  acceptSignatureMemberToSignOptions,
  buildAcceptSignatureHeader,
  normalizeAcceptSignatureSignOptions,
  parseAcceptSignatureHeader,
  selectAcceptSignatureRetryOptions
} from "./acceptSignature"
import { Erc8128Error } from "./Erc8128Error"

const identifiers = (names: readonly string[]) =>
  names.map((name) => ({ name }))

describe("Accept-Signature", () => {
  test("round trips structural components and mandatory parameters", () => {
    const header = buildAcceptSignatureHeader({
      requestBoundRequired: [
        "@scheme",
        "@authority",
        "@method",
        "@path",
        "@query",
        { name: "x-context", params: { sf: true, key: "tenant" } }
      ],
      classBoundPolicies: [["@authority", "x-tenant"]],
      allowReplayable: true
    })

    expect(parseAcceptSignatureHeader(header)).toEqual([
      {
        label: "sig1",
        components: [
          ...identifiers([
            "@scheme",
            "@authority",
            "@method",
            "@path",
            "@query"
          ]),
          { name: "x-context", params: { sf: true, key: "tenant" } }
        ],
        requiredParams: ["keyid", "created", "expires", "tag", "nonce"],
        acceptSignatureValue:
          '("@scheme" "@authority" "@method" "@path" "@query" "x-context";sf;key="tenant");keyid;created;expires;tag;nonce'
      },
      {
        label: "sig2",
        components: identifiers(["@authority", "x-tenant"]),
        requiredParams: ["keyid", "created", "expires", "tag"],
        acceptSignatureValue:
          '("@authority" "x-tenant");keyid;created;expires;tag'
      }
    ])
  })

  test("rejects offers without the mandatory tag parameter", () => {
    expect(() =>
      parseAcceptSignatureHeader(
        'sig1=("@authority");keyid;created;expires;nonce'
      )
    ).toThrow(Erc8128Error)
  })

  test("derives request and class bound retry options", () => {
    const requestBound = acceptSignatureMemberToSignOptions(
      {
        components: identifiers([
          "@scheme",
          "@authority",
          "@method",
          "@path",
          "@query",
          "x-trace-id"
        ]),
        requiredParams: ["keyid", "created", "expires", "tag", "nonce"]
      },
      { hasQuery: false, hasBody: false }
    )
    expect(requestBound).toEqual({
      binding: "request-bound",
      replay: "non-replayable",
      components: [{ name: "x-trace-id" }]
    })

    const classBound = acceptSignatureMemberToSignOptions(
      {
        components: identifiers(["@authority", "x-tenant"]),
        requiredParams: ["keyid", "created", "expires", "tag"]
      },
      { hasQuery: false, hasBody: false }
    )
    expect(classBound).toEqual({
      binding: "class-bound",
      replay: "replayable",
      components: [{ name: "x-tenant" }]
    })
  })

  test("deduplicates normalized options and skips attempted postures", () => {
    expect(
      normalizeAcceptSignatureSignOptions({
        binding: "class-bound",
        replay: "replayable",
        components: ["x-tenant", "@authority", "x-tenant"]
      })
    ).toEqual({
      binding: "class-bound",
      replay: "replayable",
      components: [{ name: "x-tenant" }]
    })

    expect(
      selectAcceptSignatureRetryOptions({
        members: [
          {
            components: identifiers(["@authority", "x-tenant"]),
            requiredParams: ["keyid", "created", "expires", "tag"]
          }
        ],
        requestShape: { hasQuery: false, hasBody: false },
        attemptedOptions: [
          {
            binding: "class-bound",
            replay: "replayable",
            components: ["x-tenant"]
          }
        ]
      })
    ).toBeNull()
  })
})
