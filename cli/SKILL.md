---
name: erc8128-cli
description: Sign HTTP requests with ERC-8128 using erc8128 curl. Use when making authenticated HTTP requests with Ethereum signatures.
---

# erc8128 curl

Command-line tool for signing HTTP requests with ERC-8128 (Ethereum HTTP signatures). It extends curl-like functionality with Ethereum-based authentication.

## Usage

```bash
erc8128 curl [options] <url>
```

### Minimal usage with config

If you have `.erc8128rc.json` set up, the minimal command is just:

```bash
erc8128 curl https://api.example.com/orders
```

## HTTP Options

```
-X, --request <method>    HTTP method (GET, POST, etc.) [default: GET]
-H, --header <header>     Add header (repeatable)
-d, --data <data>         Request body (use @file or @- for stdin)
-o, --output <file>       Write response to file
-i, --include             Include response headers in output
-v, --verbose             Show request details
--json                    Output response as JSON
--dry-run                 Sign only, do not send the request
--fail                    Exit non-zero for non-2xx responses
--config <path>           Path to .erc8128rc.json
```

## Wallet Options

```
--private-key <key>       Raw private key (⚠️  insecure)
--keyfile <path>          Path to a raw private key file (use - for stdin)
--keyid <keyid>           Expected key id (eip155:chainId:address)
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
--components <component>  Additional components to sign (repeatable)
```

## Examples

### Simple GET request

```bash
erc8128 curl --private-key 0x... https://api.example.com/data
```

### POST with JSON data

```bash
erc8128 curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"foo":"bar"}' \
  --private-key 0x... \
  https://api.example.com/submit
```

### Using environment variable

```bash
export ETH_PRIVATE_KEY=0x...
erc8128 curl https://api.example.com/data
```

### Verbose output with custom chain ID

```bash
erc8128 curl -v --chain-id 137 --ttl 300 \
  --private-key 0x... \
  https://api.example.com/data
```

### Save response to file

```bash
erc8128 curl -o response.json \
  --private-key 0x... \
  https://api.example.com/data
```

### Include response headers

```bash
erc8128 curl -i --private-key 0x... https://api.example.com/data
```

### Replayable signature

```bash
erc8128 curl --replay replayable \
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
./dist/index.js curl [options] <url>
```

## Common Use Cases

1. **Testing ERC-8128 endpoints**: Quickly test API endpoints that require Ethereum signatures
2. **Authenticated API calls**: Make authenticated requests to web3 APIs
3. **Scripting**: Automate signed HTTP requests in shell scripts
4. **Development**: Test signature verification during development

### Dry run (sign only)

```bash
erc8128 curl --dry-run https://api.example.com/orders \
  -X POST -d @body.json \
  --keyfile ~/.keys/bot.key
```

## Config

Defaults can be stored in `.erc8128rc.json` (current directory or home). You can also pass `--config <path>`.

Example:

```json
{
  "chainId": 8453,
  "binding": "request-bound",
  "replay": "non-replayable",
  "ttl": 120,
  "keyfile": "/Users/you/.keys/bot.key",
  "keyid": "eip155:8453:0xabc...",
  "headers": ["Content-Type: application/json"]
}
```

## Limitations

- Keystore decryption not yet implemented (use --private-key for now)
- Hardware wallet support (Ledger/Trezor) not yet implemented
- No signature verification (client-side only, for making signed requests)
