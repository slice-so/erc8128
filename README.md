# `@slicekit/erc8128`

Sign and verify ERC-8128 Ethereum HTTP requests, including recursive delegated
authentication, using RFC 9421, RFC 9530, and RFC 9651.

```sh
npm install @slicekit/erc8128
```

```ts
import {
  createSignerClient,
  createUniversalAccountVerifier,
  createVerifierClient
} from "@slicekit/erc8128"

const signerClient = createSignerClient(signer)
const signed = await signerClient.signRequest("https://api.example/orders")

const verifyMessage = createUniversalAccountVerifier({
  getCode: ({ address }) => publicClient.getCode({ address }),
  // This callback verifies ERC-6492 or ERC-1271 only; it must not ECDSA-fallback.
  verifySmartAccount
})
const verifier = createVerifierClient({ nonceStore, verifyMessage })
const result = await verifier.verifyRequest({ request: signed })
if (result.ok) console.log(result.principal, result.signer, result.delegated)
```

Base-profile request signatures always use `tag="erc8128"` and CAIP-10 key identifiers. The
request-bound floor covers `@scheme`, `@authority`, `@method`, `@path`, and
`@query`; received content additionally requires a verified Content-Digest and
received Content-Type coverage.

Universal Account verification is the default: ERC-6492, code-bearing ERC-1271
accounts, then strict code-free EOA recovery. Routes that intentionally accept
only EOAs can set `accountVerification: "eoa-only"`.

Delegation uses `buildDelegationGrant`, `completeDelegationGrant`, and
`createDelegatedSignerClient`. Each link is an exact EIP-712 `Delegation` value
and its embedded proof, transported as a deterministic 14-element CBOR array.
The `ERC-8128-Delegation` Dictionary contains only ordered `g0` through `gN`
Byte Sequences, while `Signature-Input` and `Signature` contain exactly one leaf
request proof tagged
`erc8128-delegated`. Verifiers opt in with `policy.delegation`, validate the
canonical revocation status of every link, and receive the root as `principal`,
the leaf as `signer`, and the ordered `delegationIds`.

Replay posture is inferred only from `nonce`: the signer generates one by
default, while `{ nonce: null }` deliberately creates a Replayable request.
The SDK defaults to a 60-second validity window for interoperability, while
signers should choose the shortest window their delivery path and clock
uncertainty allow. Route verifiers document their own maximum.

Verification-unavailable failures are distinct from invalid authentication and
can be serialized as RFC 9457 problem details. `Accept-Signature` advertises
repairable signing posture including mandatory tags.

Universal Account classification and proof calls share a per-request budget
across base-profile and delegated candidates. Configure it with
`maxAccountVerificationCalls`; the default is `2 + maxChainDepth` (6 with the
default maximum delegation depth of 4). Budget exhaustion fails with the
applicable verification-unavailable reason.
