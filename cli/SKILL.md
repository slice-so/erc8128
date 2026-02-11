---
name: erc8128-cli
description: Sign HTTP requests with ERC-8128 using eth-fetch CLI. Use when making authenticated HTTP requests with Ethereum signatures.
---

# eth-fetch CLI

Command-line tool for signing HTTP requests with ERC-8128 (Ethereum HTTP signatures). It extends curl-like functionality with Ethereum-based authentication.

## Usage

```bash
eth-fetch [options] <url>
```

## HTTP Options

```
-X, --request <method>    HTTP method (GET, POST, etc.) [default: GET]
-H, --header <header>     Add header (repeatable)
-d, --data <data>         Request body
-o, --output <file>       Write response to file
-i, --include             Include response headers in output
-v, --verbose             Show request details
```

## Wallet Options

```
--private-key <key>       Raw private key (⚠️  insecure)
--keystore <path>         Path to encrypted keystore file
--password <pass>         Keystore password (or prompts interactively)
--ledger                  Use Ledger hardware wallet (not yet implemented)
--trezor                  Use Trezor hardware wallet (not yet implemented)
```

**Environment Variable:** Set `ETH_PRIVATE_KEY` to provide a private key.

⚠️ **Security:** Using `--private-key` or `ETH_PRIVATE_KEY` is insecure. Use `--keystore` for production.

## ERC-8128 Options

```
--chain-id <id>           Chain ID [default: 1]
--binding <mode>          request-bound | class-bound [default: request-bound]
--replay <mode>           non-replayable | replayable [default: non-replayable]
--ttl <seconds>           Signature TTL in seconds [default: 60]
```

## Examples

### Simple GET request

```bash
eth-fetch --private-key 0x... https://api.example.com/data
```

### POST with JSON data

```bash
eth-fetch -X POST \
  -H "Content-Type: application/json" \
  -d '{"foo":"bar"}' \
  --private-key 0x... \
  https://api.example.com/submit
```

### Using environment variable

```bash
export ETH_PRIVATE_KEY=0x...
eth-fetch https://api.example.com/data
```

### Verbose output with custom chain ID

```bash
eth-fetch -v --chain-id 137 --ttl 300 \
  --private-key 0x... \
  https://api.example.com/data
```

### Save response to file

```bash
eth-fetch -o response.json \
  --private-key 0x... \
  https://api.example.com/data
```

### Include response headers

```bash
eth-fetch -i --private-key 0x... https://api.example.com/data
```

### Replayable signature

```bash
eth-fetch --replay replayable \
  --private-key 0x... \
  https://api.example.com/data
```

## How It Works

The CLI:
1. Creates an Ethereum signer from your wallet
2. Builds the HTTP request with specified options
3. Signs the request according to ERC-8128 standard
4. Adds `Signature` and `Signature-Input` headers
5. Sends the signed request and displays the response

## Technical Details

- Uses [ERC-8128](https://eips.ethereum.org/EIPS/eip-8128) for Ethereum HTTP signatures
- Implements [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) HTTP Message Signatures
- Supports both request-bound and class-bound signatures
- Provides replay protection with nonces by default
- Uses EIP-191 personal_sign for message signing

## Installation

```bash
cd /Users/jacobot/clawd-projects/slice/monorepo/packages/erc8128/cli
bun install
bun run build
```

## Running

From source:
```bash
cd /Users/jacobot/clawd-projects/slice/monorepo/packages/erc8128/cli
bun run src/index.ts [options] <url>
```

From built dist:
```bash
cd /Users/jacobot/clawd-projects/slice/monorepo/packages/erc8128/cli
./dist/index.js [options] <url>
```

## Common Use Cases

1. **Testing ERC-8128 endpoints**: Quickly test API endpoints that require Ethereum signatures
2. **Authenticated API calls**: Make authenticated requests to web3 APIs
3. **Scripting**: Automate signed HTTP requests in shell scripts
4. **Development**: Test signature verification during development

## Limitations

- Keystore decryption not yet implemented (use --private-key for now)
- Hardware wallet support (Ledger/Trezor) not yet implemented
- No signature verification (client-side only, for making signed requests)
