# @slicekit/erc8128

Sign and verify HTTP requests with Ethereum wallets using [ERC-8128](https://github.com/slice-so/ERCs/blob/d9c6f41183008285a0e9f1af1d2aeac72e7a8fdc/ERCS/erc-8128.md).

## Features

- **Fetch-native** — Works in browsers, workers, Node.js 18+, Bun, Deno
- **Full RFC 9421 compliance** — HTTP Message Signatures with Ethereum extension
- **Request binding** — Sign URL, method, headers, and body
- **Replay protection** — Built-in nonce handling

## Installation

```bash
npm install @slicekit/erc8128
```

## Quick Start

### Sign a Request

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

const response = await client.fetch(
  'https://api.example.com/orders',
  {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: '100' }),
  }
)
```

### Verify a Request

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

## API

### `createSignerClient(signer, options?)`

Creates a client with pre-configured signer.

```typescript
const client = createSignerClient(signer)

client.fetch(input, init?)      // Sign and send
client.signRequest(input, init?) // Sign only
```

### `createVerifierClient(verifyMessage, nonceStore, policy?)`

Creates a client with pre-configured verification dependencies.

```typescript
const verifier = createVerifierClient(verifyMessage, nonceStore)

verifier.verifyRequest(request, policy?)
```

### `verifyRequest(request, verifyMessage, nonceStore, policy?)`

Verifies a signed request.

**Returns:** `Promise<VerifyResult>`

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

Signs a fetch Request and returns a new Request with signature headers.

**Returns:** `Promise<Request>`

### `signedFetch(input, init?, signer, options?)`

Signs and sends a request in one call.

**Returns:** `Promise<Response>`

## Sign Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `binding` | `"request-bound"` \| `"minimal"` | `"request-bound"` | Components to sign |
| `replay` | `"non-replayable"` \| `"replayable"` | `"non-replayable"` | Include nonce |
| `ttlSeconds` | `number` | `60` | Signature validity window |
| `label` | `string` | `"eth"` | Signature label |
| `components` | `string[]` | — | Override signed components |

## Verify Policy

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxValiditySec` | `number` | `300` | Max allowed validity window |
| `clockSkewSec` | `number` | `0` | Allowed clock drift |
| `label` | `string` | — | Preferred signature label |
| `strictLabel` | `boolean` | `false` | Require exact label match |
| `replayable` | `boolean` | `false` | Allow replayable (nonce-less) signatures |
| `additionalRequestBoundComponents` | `string[]` | — | Extra components required for request-bound |
| `classBoundPolicies` | `string[] \| string[][]` | — | Acceptable class-bound component policies |

## Nonce Store

For replay protection, implement `NonceStore`:

```typescript
interface NonceStore {
  consume(key: string, ttlSeconds: number): Promise<boolean>
}
```

**In-memory (development):**

```typescript
const nonceStore = {
  seen: new Map(),
  async consume(key, ttl) {
    if (this.seen.has(key)) return false
    this.seen.set(key, Date.now() + ttl * 1000)
    return true
  },
}
```

**Redis (production):**

```typescript
const nonceStore = {
  async consume(key, ttl) {
    return (await redis.set(`nonce:${key}`, '1', 'EX', ttl, 'NX')) === 'OK'
  },
}
```

## Documentation

Full documentation: [erc8128.slice.so](https://erc8128.slice.so)

- [Quick Start](https://erc8128.slice.so/getting-started/quick-start)
- [Signing Requests](https://erc8128.slice.so/guides/signing-requests)
- [Verifying Requests](https://erc8128.slice.so/guides/verifying-requests)
- [API Reference](https://erc8128.slice.so/api)

## License

MIT
