---
name: erc8128-cli
description: Sign HTTP requests with ERC-8128 using erc8128 curl. Use when making authenticated HTTP requests with Ethereum signatures.
---

# erc8128 curl

CLI for signing HTTP requests with ERC-8128 (Ethereum HTTP signatures).

```bash
erc8128 curl [options] <url>
```

## Options

### HTTP

```
-X, --request <method>    HTTP method (GET, POST, etc.) [default: GET]
-H, --header <header>...  Add header (can be specified multiple times)
-d, --data <data>         Request body (use @file or @- for stdin)
-o, --output <file>       Write response to file
-i, --include             Include response headers in output
-v, --verbose             Show request details
--json                    Output response as JSON
--dry-run                 Sign only, do not send the request
--fail                    Exit non-zero for non-2xx responses
--config <path>           Path to .erc8128rc.json
```

### Wallet

```
--keystore <path>         Path to encrypted keystore file
--password <pass>         Keystore password (or prompts interactively)
--keyfile <path>          Path to a raw private key file (use - for stdin)
--private-key <key>       Raw private key (⚠️ insecure, prefer --keystore)
```

`ETH_PRIVATE_KEY` env var is also supported.

### ERC-8128

```
--chain-id <id>               Chain ID [default: 1]
--binding <mode>              request-bound | class-bound [default: request-bound]
--replay <mode>               non-replayable | replayable [default: non-replayable]
--ttl <seconds>               Signature TTL in seconds [default: 60]
--components <component>...   Components to sign (can be specified multiple times)
--keyid <keyid>               Expected key id (erc8128:chainId:address)
```

## Parameter order convention

HTTP flags → headers/data → wallet → ERC-8128 options → URL (always last).

## Examples

### With config file (minimal)

```bash
erc8128 curl https://api.example.com/orders
```

### GET with keystore

```bash
erc8128 curl --keystore ./keyfile.json https://api.example.com/data
```

### POST with JSON data

```bash
erc8128 curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"foo":"bar"}' \
  --keystore ./keyfile.json \
  https://api.example.com/submit
```

### Using keyfile + keyid

```bash
erc8128 curl -X POST \
  -d @body.json \
  --keyfile ~/.keys/bot.key \
  --keyid erc8128:8453:0xabc... \
  https://api.example.com/orders
```

### Dry run (sign only, do not send)

```bash
erc8128 curl -X POST \
  -d @body.json \
  --keyfile ~/.keys/bot.key \
  --dry-run \
  https://api.example.com/orders
```

### Custom chain ID and signature options

```bash
erc8128 curl \
  --keystore ./keyfile.json \
  --chain-id 137 \
  --binding class-bound \
  --replay replayable \
  --ttl 300 \
  https://api.example.com/data
```

## Config

Defaults can be stored in `.erc8128rc.json` (current directory, home, or via `--config <path>`).

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
