# CLI Reference: erc8128 curl

Command-line tool for signing HTTP requests with ERC-8128. Think of it as curl with built-in Ethereum authentication.

📚 **Full CLI guide:** [erc8128.slice.so/guides/cli](https://erc8128.slice.so/guides/cli)

## Install

```bash
# Global install
npm install -g @slicekit/erc8128-cli

# Or use directly with npx
npx @slicekit/erc8128-cli curl <url>
```

## Usage

```bash
erc8128 curl [options] <url>
```

## Options

### HTTP

| Option | Description |
|--------|-------------|
| `-X, --request <method>` | HTTP method (default: GET) |
| `-H, --header <header>` | Add header (repeatable) |
| `-d, --data <data>` | Request body (`@file` or `@-` for stdin) |
| `-o, --output <file>` | Write response to file |
| `-i, --include` | Include response headers |
| `-v, --verbose` | Show request details |
| `--json` | Output response as JSON |
| `--dry-run` | Sign only, don't send |
| `--fail` | Exit non-zero for non-2xx |
| `--config <path>` | Path to config file |

### Wallet

| Option | Description |
|--------|-------------|
| `--keystore <path>` | Encrypted keystore file |
| `--password <pass>` | Keystore password (or prompts) |
| `--keyfile <path>` | Raw private key file (`-` for stdin) |
| `--private-key <key>` | Raw private key (⚠️ insecure) |
| `--ledger` | Use Ledger hardware wallet (not yet implemented) |
| `--trezor` | Use Trezor hardware wallet (not yet implemented) |

`ETH_PRIVATE_KEY` env var also supported.

### ERC-8128

| Option | Description |
|--------|-------------|
| `--chain-id <id>` | Chain ID (default: 1) |
| `--binding <mode>` | `request-bound` \| `class-bound` |
| `--replay <mode>` | `non-replayable` \| `replayable` |
| `--ttl <seconds>` | Signature TTL (default: 60) |
| `--components <comp>` | Components to sign (repeatable, comma-separated) |
| `--keyid <keyid>` | Expected keyid (`erc8128:<chainId>:<address>`) |

## Examples

### Basic GET

```bash
erc8128 curl --keystore ./key.json https://api.example.com/data
```

### POST with JSON

```bash
erc8128 curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"foo":"bar"}' \
  --keystore ./key.json \
  https://api.example.com/submit
```

### Using keyfile

```bash
erc8128 curl -X POST \
  -d @body.json \
  --keyfile ~/.keys/bot.key \
  --keyid erc8128:8453:0xabc... \
  https://api.example.com/orders
```

### Dry run

```bash
erc8128 curl -X POST \
  -d @body.json \
  --keyfile ~/.keys/bot.key \
  --dry-run \
  https://api.example.com/orders
```

### Custom options

```bash
erc8128 curl \
  --keystore ./key.json \
  --chain-id 137 \
  --binding class-bound \
  --components "@authority,x-custom-header" \
  --replay replayable \
  --ttl 300 \
  https://api.example.com/data
```

### Piped input

```bash
echo '{"data":"value"}' | erc8128 curl -X POST \
  -H "Content-Type: application/json" \
  -d @- \
  --keyfile ~/.keys/bot.key \
  https://api.example.com/submit
```

### Environment variable

```bash
export ETH_PRIVATE_KEY=0x...
erc8128 curl https://api.example.com/data
```

## Config File

Store defaults in `.erc8128rc.json` (cwd, home, or `--config`):

```json
{
  "chainId": 8453,
  "binding": "request-bound",
  "replay": "non-replayable",
  "ttl": 120,
  "keyfile": "~/.keys/bot.key",
  "keyid": "erc8128:8453:0xabc...",
  "headers": ["Content-Type: application/json"],
  "components": ["x-idempotency-key"]
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | HTTP error (with --fail) |
| 2 | Invalid arguments |
| 3 | Signing error |
| 4 | Network error |

## Security Best Practices

- **Use keystore files** — Encrypted at rest, only decrypted in memory
- **Clear shell history** — If you used `--private-key`, clear it from history
- **Avoid scripts with raw keys** — Use environment variables injected at runtime
- **Use short TTLs** — Default 60s is good; shorter is better for sensitive operations

📖 See [CLI Guide](https://erc8128.slice.so/guides/cli) for more details.
