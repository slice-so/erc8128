---
name: erc8128
description: Sign and verify HTTP requests with Ethereum wallets using ERC-8128. Use when building authenticated APIs that need wallet-based auth, making signed requests to ERC-8128 endpoints, implementing request verification in servers, or working with agent-to-server authentication. Covers both the @slicekit/erc8128 JS library and the erc8128 CLI.
---

# ERC-8128: Ethereum HTTP Signatures

ERC-8128 extends RFC 9421 (HTTP Message Signatures) with Ethereum wallet signing. It enables HTTP authentication using existing Ethereum keys—no new credentials needed.

📚 **Full documentation:** [erc8128.slice.so](https://erc8128.slice.so)

## When to Use

- **API authentication** — Wallets already onchain can authenticate to your backend
- **Agent auth** — Bots and agents sign requests with their operational keys
- **Replay protection** — Signatures include nonces and expiration
- **Request integrity** — Sign URL, method, headers, and body

## Packages

| Package | Purpose |
|---------|---------|
| `@slicekit/erc8128` | JS library for signing and verifying |
| `@slicekit/erc8128-cli` | CLI for signed requests (`erc8128 curl`) |

## Library: @slicekit/erc8128

### Sign requests

```typescript
import { createSignerClient } from '@slicekit/erc8128'
import type { EthHttpSigner } from '@slicekit/erc8128'
import { privateKeyToAccount } from 'viem/accounts'

const account = privateKeyToAccount('0x...')

const signer: EthHttpSigner = {
  chainId: 1,
  address: account.address,
  signMessage: async (msg) => account.signMessage({ message: { raw: msg } }),
}

const client = createSignerClient(signer)

// Sign and send
const response = await client.fetch('https://api.example.com/orders', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ amount: '100' }),
})

// Sign only (returns new Request with signature headers)
const signedRequest = await client.signRequest('https://api.example.com/orders')
```

### Verify requests

```typescript
import { createVerifierClient } from '@slicekit/erc8128'
import type { NonceStore } from '@slicekit/erc8128'
import { createPublicClient, http } from 'viem'
import { mainnet } from 'viem/chains'

// NonceStore interface for replay protection
const nonceStore: NonceStore = {
  consume: async (key: string, ttlSeconds: number): Promise<boolean> => {
    // Return true if nonce was successfully consumed (first use)
    // Return false if nonce was already used (replay attempt)
  }
}

const publicClient = createPublicClient({ chain: mainnet, transport: http() })
const verifier = createVerifierClient(publicClient.verifyMessage, nonceStore)

const result = await verifier.verifyRequest(request)

if (result.ok) {
  console.log(`Authenticated: ${result.address} on chain ${result.chainId}`)
} else {
  console.log(`Failed: ${result.reason}`)
}
```

### Sign options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `binding` | `"request-bound"` \| `"class-bound"` | `"request-bound"` | What to sign |
| `replay` | `"non-replayable"` \| `"replayable"` | `"non-replayable"` | Include nonce |
| `ttlSeconds` | `number` | `60` | Signature validity |
| `components` | `string[]` | — | Additional components to sign |
| `contentDigest` | `"auto"` \| `"recompute"` \| `"require"` \| `"off"` | `"auto"` | Content-Digest handling |

**request-bound**: Signs `@authority`, `@method`, `@path`, `@query` (if present), and `content-digest` (if body present). Each request is unique.

**class-bound**: Signs only the components you explicitly specify. Reusable across similar requests. Requires `components` array.

📖 See [Request Binding](https://erc8128.slice.so/concepts/request-binding) for details.

### Verify policy

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxValiditySec` | `number` | `300` | Max allowed TTL |
| `clockSkewSec` | `number` | `0` | Allowed clock drift |
| `replayable` | `boolean` | `false` | Allow nonce-less signatures |
| `classBoundPolicies` | `string[]` \| `string[][]` | — | Accepted class-bound component sets |

📖 See [Verifying Requests](https://erc8128.slice.so/guides/verifying-requests) and [VerifyPolicy](https://erc8128.slice.so/api/types#verifypolicy) for full options.

## CLI: erc8128 curl

For CLI usage, see [references/cli.md](references/cli.md).

Quick examples:

```bash
# GET with keystore
erc8128 curl --keystore ./key.json https://api.example.com/data

# POST with JSON
erc8128 curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"foo":"bar"}' \
  --keyfile ~/.keys/bot.key \
  https://api.example.com/submit

# Dry run (sign only)
erc8128 curl --dry-run -d @body.json --keyfile ~/.keys/bot.key https://api.example.com
```

📖 See [CLI Guide](https://erc8128.slice.so/guides/cli) for full documentation.

## Common Patterns

### Express middleware

```typescript
import { verifyRequest } from '@slicekit/erc8128'
import type { NonceStore } from '@slicekit/erc8128'
import { createPublicClient, http } from 'viem'
import { mainnet } from 'viem/chains'

const publicClient = createPublicClient({ chain: mainnet, transport: http() })

// Implement NonceStore (Redis example)
const nonceStore: NonceStore = {
  consume: async (key, ttlSeconds) => {
    const result = await redis.set(key, '1', 'EX', ttlSeconds, 'NX')
    return result === 'OK'
  }
}

async function erc8128Auth(req, res, next) {
  const result = await verifyRequest(
    toFetchRequest(req), // Convert Express req to Fetch Request
    publicClient.verifyMessage,
    nonceStore
  )

  if (!result.ok) {
    return res.status(401).json({ error: result.reason })
  }

  req.auth = { address: result.address, chainId: result.chainId }
  next()
}
```

### Agent signing (with key file)

```typescript
import { createSignerClient } from '@slicekit/erc8128'
import type { EthHttpSigner } from '@slicekit/erc8128'
import { privateKeyToAccount } from 'viem/accounts'
import { readFileSync } from 'fs'

const key = readFileSync(process.env.KEYFILE, 'utf8').trim()
const account = privateKeyToAccount(key as `0x${string}`)

const signer: EthHttpSigner = {
  chainId: Number(process.env.CHAIN_ID) || 1,
  address: account.address,
  signMessage: async (msg) => account.signMessage({ message: { raw: msg } }),
}

const client = createSignerClient(signer)

// Use client.fetch() for all authenticated requests
```

### Verify failure reasons

```typescript
type VerifyFailReason =
  | 'missing_headers'
  | 'label_not_found'
  | 'bad_signature_input'
  | 'bad_signature'
  | 'bad_keyid'
  | 'bad_time'
  | 'not_yet_valid'
  | 'expired'
  | 'validity_too_long'
  | 'nonce_required'
  | 'replayable_not_allowed'
  | 'replayable_invalidation_required'
  | 'replayable_not_before'
  | 'replayable_invalidated'
  | 'class_bound_not_allowed'
  | 'not_request_bound'
  | 'nonce_window_too_long'
  | 'replay'
  | 'digest_mismatch'
  | 'digest_required'
  | 'alg_not_allowed'
  | 'bad_signature_bytes'
  | 'bad_signature_check'
```

📖 See [VerifyFailReason](https://erc8128.slice.so/api/types#verifyfailreason) for descriptions.

## Key Management

For agents and automated systems:

| Method | Security | Use Case |
|--------|----------|----------|
| `--keyfile` | Medium | Unencrypted key file, file permissions for protection |
| `--keystore` | High | Encrypted JSON keystore, password required |
| `ETH_PRIVATE_KEY` | Low | Environment variable, avoid in production |
| Signing service | High | Delegate to external service (SIWA, AWAL) |

## Documentation

- **Full docs:** [erc8128.slice.so](https://erc8128.slice.so)
- **Quick Start:** [erc8128.slice.so/getting-started/quick-start](https://erc8128.slice.so/getting-started/quick-start)
- **Concepts:** [erc8128.slice.so/concepts/overview](https://erc8128.slice.so/concepts/overview)
- **API Reference:** [erc8128.slice.so/api/signRequest](https://erc8128.slice.so/api/signRequest)
- **ERC-8128 Spec:** [GitHub](https://github.com/slice-so/ERCs/blob/d9c6f41183008285a0e9f1af1d2aeac72e7a8fdc/ERCS/erc-8128.md)
