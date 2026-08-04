# `@slicekit/erc8128`

Sign and verify direct or delegated Ethereum HTTP requests using RFC 9421,
RFC 9530, RFC 9651, and ERC-8128.

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

Direct signatures always use `tag="erc8128"` and CAIP-10 key identifiers. The
request-bound floor covers `@scheme`, `@authority`, `@method`, `@path`, and
`@query`; received content additionally requires a verified Content-Digest and
received Content-Type coverage.

Universal direct verification is the default: ERC-6492, code-bearing ERC-1271
accounts, then strict code-free EOA recovery. Routes that intentionally accept
only EOAs can set `accountVerification: "eoa-only"`.

Delegation uses `buildDelegationGrant`, `completeDelegationGrant`, and
`createDelegatedSignerClient`. A `DelegationGrant` stores the canonical
delegation field, complete grant Signature-Input Inner List, and root signature.
Verifiers opt in with `policy.delegation`, configure exact audiences and
a trusted revocation authority/callback, and receive separate `principal` and
`signer` identities plus standard scopes. Delegation fields are closed: unknown
members fail authentication instead of being ignored.

Verification-unavailable failures are distinct from invalid authentication and
can be serialized as RFC 9457 problem details. `Accept-Signature` advertises
repairable signing posture including mandatory tags.
