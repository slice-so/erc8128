import { describe, expect, test } from "bun:test"
import { recoverAddress } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { signRequest } from "../../sign"
import type {
  Delegation,
  DelegationChain,
  DelegationGrantCache,
  DelegationLink,
  VerifyFailReason
} from "../../types"
import { verifyRequest } from "../../verify"
import { formatErc8128ProblemDetails } from "../problemDetails"
import { bytesToHex } from "../utilities"
import { completeDelegationGrant } from "./createDelegationGrant"
import { createDelegatedSignerClient } from "./delegatedSignerClient"
import {
  formatDelegationField,
  getDelegationTypedData,
  hashDelegation
} from "./delegationField"

const root = privateKeyToAccount(`0x${"31".repeat(32)}`)
const delegate = privateKeyToAccount(`0x${"32".repeat(32)}`)
const leaf = privateKeyToAccount(`0x${"33".repeat(32)}`)
const now = 1_700_000_000
const rootId = `eip155:1:${root.address.toLowerCase()}`
const delegateId = `eip155:1:${delegate.address.toLowerCase()}`
const leafId = `eip155:1:${leaf.address.toLowerCase()}`

const baseGrant: Delegation = {
  root: rootId,
  delegate: delegateId,
  aud: ["https://api.example", "https://backup.example"],
  id: `0x${"41".repeat(32)}`,
  epoch: 7,
  created: now - 100,
  expires: now + 600,
  maxAge: 60,
  delegateIsEOA: true,
  allowReplayable: false,
  components: [],
  scope: ["resource:read", "resource:write"],
  parent: `0x${"00".repeat(32)}`
}

const signer = (account: typeof delegate) => ({
  address: account.address,
  chainId: 1,
  signMessage: (message: Uint8Array) =>
    account.signMessage({ message: { raw: bytesToHex(message) } })
})

const makeLink = async (
  grant: Delegation,
  account: typeof root | typeof delegate = root
): Promise<DelegationLink> => {
  const prepared = {
    digest: hashDelegation(grant),
    grant,
    typedData: getDelegationTypedData(grant)
  }
  return completeDelegationGrant(
    prepared,
    await account.signTypedData(prepared.typedData)
  )
}

const makeRequest = async ({
  account = delegate,
  chain,
  created = now,
  expires = now + 60,
  label,
  nonce = "negative-vector-nonce",
  url = "https://api.example/resource"
}: {
  account?: typeof delegate
  chain?: DelegationChain
  created?: number
  expires?: number
  label?: string
  nonce?: string | null
  url?: string
} = {}) => {
  const resolvedChain = chain ?? { links: [await makeLink(baseGrant)] }
  return createDelegatedSignerClient(
    signer(account),
    resolvedChain
  ).signRequest(url, {
    created,
    expires,
    ...(label === undefined ? {} : { label }),
    nonce
  })
}

const replaceHeader = (
  request: Request,
  name: string,
  value: string | null
) => {
  const headers = new Headers(request.headers)
  if (value === null) headers.delete(name)
  else headers.set(name, value)
  return new Request(request, { headers })
}

type VerifyOptions = {
  accountBudget?: number
  cache?: DelegationGrantCache
  delegation?: boolean
  digest?: "unavailable" | "valid" | "invalid"
  maxGrantValiditySec?: number
  now?: number
  scopeSupported?: boolean
  status?: "valid" | "revoked" | "epoch-mismatch" | "unavailable"
}

const evaluate = async (request: Request, options: VerifyOptions = {}) => {
  let nonceConsumes = 0
  let digestCalls = 0
  const result = await verifyRequest({
    request,
    nonceStore: {
      consume: async () => {
        nonceConsumes += 1
        return true
      }
    },
    policy: {
      now: () => options.now ?? now,
      clockSkewSec: 0,
      maxAccountVerificationCalls: options.accountBudget,
      principal: "delegated",
      ...(options.delegation === false
        ? {}
        : {
            delegation: {
              grantCache: options.cache,
              maxGrantValiditySec: options.maxGrantValiditySec,
              requiredScopes: ["resource:read"],
              scopeSupported: options.scopeSupported,
              verifyStatus: () => options.status ?? "valid"
            }
          })
    },
    verifyDigest:
      options.digest === "unavailable"
        ? undefined
        : async ({ address, digest, signature }) => {
            digestCalls += 1
            if (options.digest === "invalid") return false
            return (
              (
                await recoverAddress({ hash: digest, signature })
              ).toLowerCase() === address.toLowerCase()
            )
          },
    verifyMessage: () => false
  })
  return { digestCalls, nonceConsumes, result }
}

const expectFailure = async (
  request: Request,
  reason: VerifyFailReason,
  status: 400 | 401 | 403 | 503,
  options: VerifyOptions = {}
) => {
  const outcome = await evaluate(request, options)
  expect(outcome.result).toMatchObject({ ok: false, reason })
  if (outcome.result.ok) throw new Error("Expected verification failure.")
  expect(formatErc8128ProblemDetails(outcome.result).status).toBe(status)
  expect(outcome.nonceConsumes).toBe(0)
  return outcome
}

describe("delegated negative and classification vectors", () => {
  test("classifies malformed, oversized, and uncovered delegation fields", async () => {
    const request = await makeRequest()
    for (const malformed of [
      replaceHeader(request, "erc-8128-delegation", null),
      replaceHeader(request, "erc-8128-delegation", "g1=:AA==:"),
      replaceHeader(
        request,
        "erc-8128-delegation",
        (request.headers.get("erc-8128-delegation") ?? "").replace(
          "g0=",
          "g01="
        )
      ),
      replaceHeader(request, "erc-8128-delegation", "g0=token")
    ]) {
      await expectFailure(malformed, "bad_delegation_field", 401)
    }
    await expectFailure(
      replaceHeader(
        request,
        "erc-8128-delegation",
        `g0=:${"A".repeat(16_400)}:`
      ),
      "delegation_too_large",
      400
    )
    await expectFailure(
      replaceHeader(
        request,
        "signature-input",
        (request.headers.get("signature-input") ?? "").replace(
          ' "erc-8128-delegation";sf',
          ""
        )
      ),
      "delegation_not_covered",
      401
    )
  })

  test("classifies delegate and recursive continuity failures", async () => {
    const request = await makeRequest()
    await expectFailure(
      replaceHeader(
        request,
        "signature-input",
        (request.headers.get("signature-input") ?? "").replace(
          `keyid="${delegateId}"`,
          `keyid="${rootId}"`
        )
      ),
      "delegate_mismatch",
      401
    )

    const badRoot = await makeLink({
      ...baseGrant,
      parent: `0x${"99".repeat(32)}`
    })
    await expectFailure(
      replaceHeader(
        request,
        "erc-8128-delegation",
        formatDelegationField({ links: [badRoot] })
      ),
      "delegation_chain_discontinuous",
      401
    )

    const parent = await makeLink(baseGrant)
    const validChild = await makeLink(
      {
        ...baseGrant,
        root: delegateId,
        delegate: leafId,
        aud: ["https://api.example"],
        id: `0x${"42".repeat(32)}`,
        created: now - 50,
        expires: now + 300,
        scope: ["resource:read"],
        parent: hashDelegation(baseGrant)
      },
      delegate
    )
    const depthTwo = await makeRequest({
      account: leaf,
      chain: { links: [parent, validChild] }
    })
    const invalidChild = await makeLink(
      { ...validChild.grant, parent: `0x${"98".repeat(32)}` },
      delegate
    )
    await expectFailure(
      replaceHeader(
        depthTwo,
        "erc-8128-delegation",
        formatDelegationField({ links: [parent, invalidChild] })
      ),
      "delegation_chain_discontinuous",
      401
    )
  })

  test("rejects audience, scope, window, and max-age attenuation", async () => {
    const parent = await makeLink(baseGrant)
    const childBase: Delegation = {
      ...baseGrant,
      root: delegateId,
      delegate: leafId,
      aud: ["https://api.example"],
      id: `0x${"43".repeat(32)}`,
      created: now - 50,
      expires: now + 300,
      scope: ["resource:read"],
      parent: hashDelegation(baseGrant)
    }
    const validChild = await makeLink(childBase, delegate)
    const request = await makeRequest({
      account: leaf,
      chain: { links: [parent, validChild] }
    })
    const broadenings: Delegation[] = [
      { ...childBase, aud: ["https://outside.example"] },
      { ...childBase, scope: ["outside:scope"] },
      { ...childBase, created: baseGrant.created - 1 },
      { ...childBase, expires: baseGrant.expires + 1 },
      { ...childBase, maxAge: baseGrant.maxAge + 1 }
    ]
    for (const broadened of broadenings) {
      await expectFailure(
        replaceHeader(
          request,
          "erc-8128-delegation",
          formatDelegationField({
            links: [parent, await makeLink(broadened, delegate)]
          })
        ),
        "delegation_attenuation_violation",
        401
      )
    }
  })

  test("classifies grant and request window failures", async () => {
    const request = await makeRequest()
    const cases: readonly [
      Partial<Delegation>,
      VerifyFailReason,
      VerifyOptions
    ][] = [
      [{ created: now + 1, expires: now + 601 }, "grant_not_yet_valid", {}],
      [{ created: now - 700, expires: now - 1 }, "grant_expired", {}],
      [{}, "grant_validity_too_long", { maxGrantValiditySec: 100 }],
      [{ maxAge: 30 }, "delegation_max_age_exceeded", {}]
    ]
    for (const [changes, reason, options] of cases) {
      const changed = await makeLink({ ...baseGrant, ...changes })
      await expectFailure(
        replaceHeader(
          request,
          "erc-8128-delegation",
          formatDelegationField({ links: [changed] })
        ),
        reason,
        401,
        options
      )
    }

    const earlyRequest = await makeRequest({
      created: now - 1,
      expires: now + 59,
      nonce: "outside-grant-window"
    })
    await expectFailure(
      replaceHeader(
        earlyRequest,
        "erc-8128-delegation",
        formatDelegationField({
          links: [await makeLink({ ...baseGrant, created: now })]
        })
      ),
      "request_outside_grant_window",
      401
    )
  })

  test("classifies component, replay, extension, scope, and status failures", async () => {
    const request = await makeRequest()
    for (const [components, reason] of [
      [["@status"], "delegation_components_unsupported"],
      [["x-required"], "delegation_components_uncovered"]
    ] as const) {
      await expectFailure(
        replaceHeader(
          request,
          "erc-8128-delegation",
          formatDelegationField({
            links: [
              await makeLink({ ...baseGrant, components: [...components] })
            ]
          })
        ),
        reason,
        401
      )
    }

    const replayableGrant = { ...baseGrant, allowReplayable: true }
    const replayableRequest = await makeRequest({
      chain: { links: [await makeLink(replayableGrant)] },
      nonce: null
    })
    await expectFailure(
      replaceHeader(
        replayableRequest,
        "erc-8128-delegation",
        formatDelegationField({ links: [await makeLink(baseGrant)] })
      ),
      "delegation_nonce_required",
      401
    )
    await expectFailure(
      new Request("https://outside.example/resource", {
        headers: request.headers,
        method: request.method
      }),
      "audience_mismatch",
      401
    )
    await expectFailure(request, "unsupported_delegation", 401, {
      delegation: false
    })
    await expectFailure(request, "unsupported_scope", 401, {
      scopeSupported: false
    })
    await expectFailure(request, "authorization_epoch_mismatch", 401, {
      status: "epoch-mismatch"
    })
    await expectFailure(request, "revocation_unavailable", 503, {
      status: "unavailable"
    })
    await expectFailure(request, "grant_verification_unavailable", 503, {
      digest: "unavailable"
    })
  })

  test("expires positive grant-cache entries and budgets delegated candidates", async () => {
    let currentTime = now
    let cacheExpiry = 0
    const cache: DelegationGrantCache = {
      get: () => (cacheExpiry > currentTime ? true : undefined),
      set: (_key, expiresAt) => {
        cacheExpiry = expiresAt
      }
    }
    const first = await makeRequest({ nonce: "cache-first-nonce" })
    expect((await evaluate(first, { cache, now: currentTime })).result.ok).toBe(
      true
    )
    currentTime += 61
    const second = await makeRequest({
      created: currentTime,
      expires: currentTime + 60,
      nonce: "cache-second-nonce"
    })
    expect(
      (await evaluate(second, { cache, now: currentTime })).digestCalls
    ).toBe(1)

    const invalidOne = await makeRequest({
      label: "first",
      nonce: "budget-first-nonce"
    })
    const invalidTwo = await makeRequest({
      label: "second",
      nonce: "budget-second-nonce"
    })
    const headers = new Headers(invalidOne.headers)
    headers.set(
      "signature-input",
      `${invalidOne.headers.get("signature-input")}, ${invalidTwo.headers.get("signature-input")}`
    )
    headers.set(
      "signature",
      `${invalidOne.headers.get("signature")}, ${invalidTwo.headers.get("signature")}`
    )
    const budgeted = await expectFailure(
      new Request(invalidOne, { headers }),
      "grant_verification_unavailable",
      503,
      { accountBudget: 1, digest: "invalid" }
    )
    expect(budgeted.digestCalls).toBe(1)
  })

  test("shares the eight-candidate limit across direct and delegated tags", async () => {
    const delegated = await makeRequest({ label: "delegated" })
    const direct = await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        signRequest("https://api.example/resource", signer(root), {
          created: now,
          expires: now + 60,
          label: `direct${index}`,
          nonce: `mixed-candidate-${index}`
        })
      )
    )
    const headers = new Headers(delegated.headers)
    headers.set(
      "signature-input",
      [delegated, ...direct]
        .map((request) => request.headers.get("signature-input"))
        .join(", ")
    )
    headers.set(
      "signature",
      [delegated, ...direct]
        .map((request) => request.headers.get("signature"))
        .join(", ")
    )
    await expectFailure(
      new Request(delegated, { headers }),
      "signature_too_large",
      400
    )
  })
})
