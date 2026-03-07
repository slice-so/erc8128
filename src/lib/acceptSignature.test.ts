import { describe, expect, test } from "bun:test"
import {
  acceptSignatureMemberToSignOptions,
  buildAcceptSignatureHeader,
  normalizeAcceptSignatureSignOptions,
  parseAcceptSignatureHeader,
  selectAcceptSignatureRetryOptions
} from "./acceptSignature"
import { Erc8128Error } from "./types"

describe("parseAcceptSignatureHeader", () => {
  test("parses verifier-built Accept-Signature headers", () => {
    const header = buildAcceptSignatureHeader({
      requestBoundRequired: ["@authority", "@method", "@path"],
      classBoundPolicies: [["@authority", "x-tenant"]],
      requireNonce: true
    })

    const parsed = parseAcceptSignatureHeader(header)
    expect(parsed).toHaveLength(2)
    expect(parsed[0]).toEqual({
      label: "sig1",
      components: ["@authority", "@method", "@path"],
      requiredParams: ["keyid", "created", "expires", "nonce"],
      acceptSignatureValue:
        '("@authority" "@method" "@path");keyid;created;expires;nonce'
    })
    expect(parsed[1]).toEqual({
      label: "sig2",
      components: ["@authority", "x-tenant"],
      requiredParams: ["keyid", "created", "expires", "nonce"],
      acceptSignatureValue:
        '("@authority" "x-tenant");keyid;created;expires;nonce'
    })
  })

  test("derives signRequest options when request shape is provided", () => {
    const parsed = parseAcceptSignatureHeader(
      'sig1=("@authority" "@method" "@path" "x-request-id");keyid;created;expires;nonce, sig2=("@authority" "x-tenant");keyid;created;expires',
      new Request("https://example.com/resource", { method: "POST" })
    )

    expect(parsed[0].signOptions).toEqual({
      binding: "request-bound",
      replay: "non-replayable",
      components: ["x-request-id"]
    })
    expect(parsed[1].signOptions).toEqual({
      binding: "class-bound",
      replay: "replayable",
      components: ["x-tenant"]
    })
  })

  test("allows nonce to be omitted", () => {
    const parsed = parseAcceptSignatureHeader(
      'sig1=("@authority");keyid;created;expires'
    )
    expect(parsed[0].requiredParams).toEqual(["keyid", "created", "expires"])
  })

  test("throws when required params are missing", () => {
    expect(() =>
      parseAcceptSignatureHeader('sig1=("@authority");keyid;created')
    ).toThrow(Erc8128Error)
  })

  test("throws when params are not bare tokens", () => {
    expect(() =>
      parseAcceptSignatureHeader(
        'sig1=("@authority");keyid="k";created;expires'
      )
    ).toThrow(Erc8128Error)
  })
})

describe("acceptSignatureMemberToSignOptions", () => {
  test("maps request-bound members to signRequest extras", () => {
    const signOptions = acceptSignatureMemberToSignOptions(
      {
        components: ["@authority", "@method", "@path", "@query", "x-trace-id"],
        requiredParams: ["keyid", "created", "expires", "nonce"]
      },
      { hasQuery: true, hasBody: false }
    )

    expect(signOptions).toEqual({
      binding: "request-bound",
      replay: "non-replayable",
      components: ["x-trace-id"]
    })
  })

  test("strips @authority from class-bound signer output", () => {
    const signOptions = acceptSignatureMemberToSignOptions(
      {
        components: ["@authority", "x-tenant"],
        requiredParams: ["keyid", "created", "expires"]
      },
      { hasQuery: false, hasBody: false }
    )

    expect(signOptions).toEqual({
      binding: "class-bound",
      replay: "replayable",
      components: ["x-tenant"]
    })
  })

  test("returns empty components for authority-only class-bound members", () => {
    const signOptions = acceptSignatureMemberToSignOptions(
      {
        components: ["@authority"],
        requiredParams: ["keyid", "created", "expires"]
      },
      { hasQuery: true, hasBody: false }
    )

    expect(signOptions).toEqual({
      binding: "class-bound",
      replay: "replayable",
      components: []
    })
  })
})

describe("normalizeAcceptSignatureSignOptions", () => {
  test("normalizes semantically equivalent class-bound options", () => {
    const normalized = normalizeAcceptSignatureSignOptions({
      binding: "class-bound",
      replay: "replayable",
      components: ["x-tenant", "@authority", "x-tenant"]
    })

    expect(normalized).toEqual({
      binding: "class-bound",
      replay: "replayable",
      components: ["x-tenant"]
    })
  })

  test("fills signing defaults for omitted fields", () => {
    const normalized = normalizeAcceptSignatureSignOptions()
    expect(normalized).toEqual({
      binding: "request-bound",
      replay: "non-replayable",
      components: []
    })
  })
})

describe("selectAcceptSignatureRetryOptions", () => {
  test("selects the first untried normalized retry posture", () => {
    const next = selectAcceptSignatureRetryOptions({
      members: [
        {
          components: ["@authority", "x-tenant"],
          requiredParams: ["keyid", "created", "expires"]
        },
        {
          components: ["@authority", "@method", "@path", "x-trace-id"],
          requiredParams: ["keyid", "created", "expires", "nonce"]
        }
      ],
      requestShape: { hasQuery: false, hasBody: false },
      attemptedOptions: [
        {
          binding: "class-bound",
          replay: "replayable",
          components: ["@authority", "x-tenant"]
        }
      ]
    })

    expect(next).toEqual({
      binding: "request-bound",
      replay: "non-replayable",
      components: ["x-trace-id"]
    })
  })

  test("returns null when all retry postures have been attempted", () => {
    const next = selectAcceptSignatureRetryOptions({
      members: [
        {
          components: ["@authority"],
          requiredParams: ["keyid", "created", "expires"]
        }
      ],
      requestShape: { hasQuery: false, hasBody: false },
      attemptedOptions: [
        {
          binding: "class-bound",
          replay: "replayable",
          components: []
        }
      ]
    })

    expect(next).toBeNull()
  })
})
