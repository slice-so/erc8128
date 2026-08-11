# @slicekit/erc8128

Sign and verify HTTP requests with Ethereum accounts using [ERC-8128](https://github.com/slice-so/ERCs/blob/1ef11c99d1740393a1ad705c46c0fd2b2b37c3b8/ERCS/erc-8128.md). The package implements the base profile and supports the companion [delegated-authentication draft](https://github.com/slice-so/ERCs/blob/erc8128-delegated/ERCS/erc-xxxx.md) on top of RFC 9421, RFC 9530, and RFC 9651.

## Features

- **Fetch-native** — Works with standard `Request`, `Response`, and `fetch` APIs in browsers, workers, Node.js, Bun, and Deno.
- **Secure defaults** — Request-bound, non-replayable signatures with a generated nonce and a 60-second validity window.
- **Universal accounts** — Supports EOAs, deployed ERC-1271 accounts, and counterfactual ERC-6492 accounts.
- **Delegated principals** — Supports the draft recursive, attenuated EIP-712 delegation chain with audience, validity, permission, and revocation constraints.
- **Standards-compliant HTTP** — Uses HTTP Message Signatures, Content-Digest, and Structured Fields.

## Installation

```sh
npm install @slicekit/erc8128
```

## Quick start

### Sign a request

Create an `EthHttpSigner` from an Ethereum account and use the signer client to sign or send requests.

```ts
import { createSignerClient } from "@slicekit/erc8128"
import { privateKeyToAccount } from "viem/accounts"

const account = privateKeyToAccount("0x...")
const signer = {
  address: account.address,
  chainId: 1,
  signMessage: (message: Uint8Array) =>
    account.signMessage({ message: { raw: message } })
}

const client = createSignerClient(signer)

const signed = await client.signRequest("https://api.example.com/orders", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ amount: "100" })
})

// Or sign and send in one operation:
const response = await client.fetch("https://api.example.com/orders", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ amount: "100" })
})
```

The signer adds `Signature-Input`, `Signature`, and, when the request has content, a verified `Content-Digest` header.

### Verify a request

Bind a message verifier and an atomic nonce store once, then verify each incoming request.

```ts
import {
  BoundedMemoryNonceStore,
  createVerifierClient
} from "@slicekit/erc8128"
import { createPublicClient, http } from "viem"
import { mainnet } from "viem/chains"

const publicClient = createPublicClient({
  chain: mainnet,
  transport: http()
})

const verifier = createVerifierClient({
  nonceStore: new BoundedMemoryNonceStore(),
  verifyMessage: ({ address, message, signature }) =>
    publicClient.verifyMessage({ address, message, signature })
})

const result = await verifier.verifyRequest({ request })

if (result.ok) {
  console.log(result.principal.address, result.principal.chainId)
} else {
  console.error(result.reason)
}
```

`BoundedMemoryNonceStore` is intended for bounded single-process use. Use `createRedisNonceStore`, `createUniqueInsertNonceStore`, or another atomic persistent implementation in distributed production deployments.

## Core API

### `createSignerClient(signer, options?)`

Creates a reusable signing client.

```ts
const client = createSignerClient(signer, {
  ttlSeconds: 30,
  contentDigest: "auto"
})

await client.signRequest(input, init, options)
await client.fetch(input, init, options)
client.setServerConfig(origin, discoveryDocument)
```

### `createVerifierClient(config)`

Creates a reusable verifier with bound cryptographic and replay-protection dependencies.

```ts
const verifier = createVerifierClient({
  verifyMessage,
  verifyDigest,
  nonceStore,
  defaults: {
    maxValiditySec: 120,
    replayable: false
  }
})
```

`verifyDigest` is required when accepting delegated EIP-712 grant proofs.

### `verifyRequest(args)`

Verifies one signed request. A successful direct result identifies the same account as `principal` and `signer`; a delegated result identifies the initial issuer as `principal`, the leaf delegate as `signer`, and includes the ordered `delegationIds`.

```ts
type VerifyResult =
  | {
      ok: true
      principal: { address: Address; chainId: number }
      signer: { address: Address; chainId: number }
      delegated: boolean
      replay: "non-replayable" | "replayable"
      binding: "request-bound" | "class-bound"
    }
  | { ok: false; reason: VerifyFailReason; detail?: string }
```

### Universal account verification

`createUniversalAccountVerifier` and `createUniversalAccountDigestVerifier` classify an account by its onchain code:

1. ERC-6492 signatures are sent to the supplied smart-account verifier.
2. Code-bearing accounts are verified through ERC-1271.
3. Code-free accounts use strict EOA recovery.

The built-in EOA path requires canonical secp256k1 public-key recovery and Keccak-256, which are not available through WebCrypto's `SubtleCrypto` API.

### Delegated requests

Build and sign an EIP-712 grant, create a chain, then give the leaf signer a delegated client.

```ts
import {
  buildDelegationGrant,
  completeDelegationGrant,
  createDelegatedSignerClient,
  createDelegationChain
} from "@slicekit/erc8128"

const prepared = buildDelegationGrant({
  issuer,
  delegate,
  audiences: ["https://api.example.com"],
  id,
  epoch: 0,
  validUntil,
  maxRequestValiditySeconds: 60,
  delegateIsEOA: true,
  requireNonReplayable: true,
  permissions: ["orders:read"]
})

const link = completeDelegationGrant(
  prepared,
  await issuerSigner.signTypedData(prepared.typedData)
)
const chain = createDelegationChain([link])
const delegated = createDelegatedSignerClient(delegateSigner, chain)

const request = await delegated.signRequest(
  "https://api.example.com/orders"
)
```

Delegated support tracks the companion draft, whose canonical registry address and runtime code hash are still unassigned. This package pins the Slice reference-deployment candidate and must not be presented as conforming to the delegated extension until the draft assigns those values.

The delegated draft currently says clients must reconstruct and re-sign redirects. This package intentionally does not automatically sign a redirect target because a server-controlled redirect must not authorize a new wallet signature over a different origin, method, path, or body. The signer signs only the caller-supplied request; callers may explicitly inspect a redirect and construct a separate signed request.

Verifiers opt in through `policy.delegation`, supply a batch `verifyStatuses` callback, and may require permissions. HTTP loopback audiences are rejected by default; local development must opt in at grant creation and at the parsing, signing, or verification boundary that consumes the grant. Deterministic EIP-712 hashing and CBOR serialization are independent of that runtime transport policy.

## Options

### Signing options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `binding` | `"request-bound" \| "class-bound"` | `"request-bound"` | Select the component coverage posture. |
| `nonce` | `string \| function \| null` | generated | A nonce makes the request non-replayable; `null` deliberately omits it. |
| `ttlSeconds` | `number` | `60` | Maximum interval between `created` and `expires`. |
| `created` / `expires` | `number` | current time / TTL | Explicit Unix timestamps. |
| `label` | `string` | `"request"` | HTTP Message Signature label. |
| `contentDigest` | `"auto" \| "recompute" \| "require" \| "off"` | `"auto"` | Content-Digest handling. |
| `components` | `CoveredComponent[]` | profile floor | Additional or explicit covered components. |

The request-bound floor always covers `@scheme`, `@authority`, `@method`, `@path`, and `@query`; `@query` has the value `?` when the request has no query. Non-empty content requires `Content-Digest`; whenever `Content-Digest` or `Content-Type` is present, it must be covered, and a received `Content-Digest` must be verified.

### Verification policy

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `principal` | `"direct" \| "delegated" \| "either"` | `"either"` | Accepted principal class. |
| `accountVerification` | `"universal" \| "eoa-only"` | `"universal"` | Base-profile account verification mode. |
| `maxValiditySec` | `number` | `300` | Maximum accepted signature validity window. |
| `clockSkewSec` | `number` | `30` | Allowed clock uncertainty in seconds. |
| `replayable` | `boolean` | `false` | Whether nonce-less signatures are accepted. |
| `additionalRequestBoundComponents` | `CoveredComponent[]` | none | Unconditional coverage requirements added to request-bound and class-bound policies. |
| `requiredCoveredHeadersWhenPresent` | `CoveredComponent[]` | none | Request headers that must be covered whenever they are present. |
| `classBoundPolicies` | `CoveredComponent[] \| CoveredComponent[][]` | disabled | Accepted class-bound component policies. |
| `delegation` | `DelegationPolicy` | disabled | Delegation, permissions, proof-cache, and revocation policy. |

## Nonce stores

Non-replayable verification requires an atomic consume operation:

```ts
interface NonceStore {
  consume(key: string, ttlSeconds: number): Promise<boolean>
}
```

It must return `true` exactly once for a new key and `false` for every reuse until the TTL expires.

## Documentation

Full guides, API reference, protocol details, and the CLI are available at [erc8128.org](https://erc8128.org).

## License

MIT
