# @slicekit/erc8128

Sign and verify HTTP requests with Ethereum wallets using [ERC-8128](https://github.com/slice-so/ERCs/blob/d9c6f41183008285a0e9f1af1d2aeac72e7a8fdc/ERCS/erc-8128.md).

## Features

- **Fetch-native** — Works in browsers, workers, Node.js 18+, Bun, Deno
- **RFC 9421 compliant** — HTTP Message Signatures with Ethereum extension
- **Request binding** — Sign URL, method, headers, and body
- **Replay protection** — Optional nonce handling

## Installation

```bash
npm install @slicekit/erc8128
```

## Quick Start

### Sign a request

```typescript
import { createSignerClient } from '@slicekit/erc8128'
import { privateKeyToAccount } from 'viem/accounts'

const account = privateKeyToAccount('0x...')

const signer = {
  chainId: 1,
  address: account.address,
  signMessage: (message) => account.signMessage({ message: { raw: message } }),
}

const client = createSignerClient(signer)

const response = await client.fetch('https://api.example.com/orders', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ amount: '100' }),
})
```

### Verify a request

```typescript
import { createVerifierClient } from '@slicekit/erc8128'
import { createPublicClient, http } from 'viem'
import { mainnet } from 'viem/chains'

const publicClient = createPublicClient({ chain: mainnet, transport: http() })

const verifier = createVerifierClient(publicClient.verifyMessage, nonceStore)

const result = await verifier.verifyRequest(request)

if (result.ok) {
  console.log(`Authenticated: ${result.address}`)
}
```

## Core API

### `createSignerClient(signer, options?)`

Creates a client with a configured signer.

```typescript
const client = createSignerClient(signer)

client.fetch(input, init?)       // Sign and send
client.signRequest(input, init?) // Sign only
```

### `createVerifierClient(verifyMessage, nonceStore, policy?)`

Creates a client with verification dependencies.

```typescript
const verifier = createVerifierClient(verifyMessage, nonceStore)

verifier.verifyRequest(request, policy?, setHeaders?)
```

### `verifyRequest(request, verifyMessage, nonceStore, policy?, setHeaders?)`

Verifies a signed request.

```typescript
type VerifyResult =
  | {
      ok: true
      address: Address
      chainId: number
      label: string
      components: string[]
      params: SignatureParams
      replayable: boolean
      binding: "request-bound" | "class-bound"
    }
  | { ok: false; reason: VerifyFailReason }
```

### `signRequest(input, init?, signer, options?)`

Signs a fetch `Request` and returns a new `Request` with signature headers.

### `signedFetch(input, init?, signer, options?)`

Signs and sends a request in one call.

## Options

### Sign options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `binding` | `"request-bound"` \| `"class-bound"` | `"request-bound"` | Components to sign |
| `replay` | `"non-replayable"` \| `"replayable"` | `"non-replayable"` | Include nonce |
| `ttlSeconds` | `number` | `60` | Signature validity window |
| `label` | `string` | `"eth"` | Signature label |
| `components` | `string[]` | — | Override signed components |

### Verify policy

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxValiditySec` | `number` | `300` | Max allowed validity window |
| `clockSkewSec` | `number` | `0` | Allowed clock drift |
| `label` | `string` | — | Preferred signature label |
| `strictLabel` | `boolean` | `false` | Require exact label match |
| `replayable` | `boolean` | `false` | Allow replayable (nonce-less) signatures |
| `additionalRequestBoundComponents` | `string[]` | — | Extra components required for request-bound |
| `classBoundPolicies` | `string[] \| string[][]` | — | Acceptable class-bound component policies |

## Nonce store

To enable replay protection, implement `NonceStore`:

```typescript
interface NonceStore {
  consume(key: string, ttlSeconds: number): Promise<boolean>
}
```

## Documentation

Full documentation: [erc8128.slice.so](https://erc8128.slice.so)

## License

MIT
