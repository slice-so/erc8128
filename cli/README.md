# erc8128 curl

CLI tool for signing HTTP requests with ERC-8128 (Ethereum HTTP signatures). Think of it as a curl extension that adds Ethereum-based authentication.

## Installation

```bash
npm install -g @slicekit/erc8128-cli
```

Or use directly with npx:

```bash
npx @slicekit/erc8128-cli curl <url>
```

## Usage

```bash
erc8128 curl [options] <url>
```

### Minimal usage with config

If you have `.erc8128rc.json` set up, the minimal command is just:

```bash
erc8128 curl https://api.example.com/orders
```

### HTTP Options

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

### Wallet Options

You can use the following options to provide a wallet:

```
--keystore <path>         Path to encrypted keystore file
--password <pass>         Keystore password (or prompts interactively)
--keyfile <path>          Path to a raw private key file (use - for stdin) (⚠️ insecure)
--private-key <key>       Raw private key (⚠️ insecure)
```

**Environment Variable:** You can also set `ETH_PRIVATE_KEY` to provide a private key.

⚠️ **Security Warning:** Using `--private-key` or `ETH_PRIVATE_KEY` is insecure as the key may be visible in shell history. Use `--keystore` for better security.

### ERC-8128 Options

You can use the following options to configure the ERC-8128 signature:

```
--chain-id <id>               Chain ID [default: 1]
--binding <mode>              request-bound | class-bound [default: request-bound]
--replay <mode>               non-replayable | replayable [default: non-replayable]
--ttl <seconds>               Signature TTL in seconds [default: 60]
--components <component>...   Components to sign (can be specified multiple times)
                                - Additional components for request-bound signatures
                                - Required Components for class-bound signatures
--keyid <keyid>               Expected key id (erc8128:chainId:address)
```

## Examples

### Simple GET request

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

### Dry run (sign only)

```bash
erc8128 curl -X POST \
  -d @body.json \
  --keyfile ~/.keys/bot.key \
  --dry-run \
  https://api.example.com/orders
```

### Using private key 

```bash
erc8128 curl --private-key 0x... https://api.example.com/data
```

## Config

You can set defaults in `.erc8128rc.json`. The CLI looks for:

1. `--config <path>` if provided
2. `./.erc8128rc.json` in the current working directory
3. `~/.erc8128rc.json`

Example:

```json
{
  "chainId": 8453,
  "binding": "request-bound",
  "replay": "non-replayable",
  "ttl": 120,
  "keyfile": "/Users/you/.keys/bot.key",
  "keyid": "erc8128:8453:0xabc...",
  "headers": ["Content-Type: application/json"],
  "components": ["x-idempotency-key"]
}
```

### With environment variable

```bash
export ETH_PRIVATE_KEY=0x...
erc8128 curl https://api.example.com/data
```

### Verbose output

```bash
erc8128 curl -v \
  --keystore ./keyfile.json \
  https://api.example.com/data
```

### Save response to file

```bash
erc8128 curl -o response.json \
  --keystore ./keyfile.json \
  https://api.example.com/data
```

### Include response headers

```bash
erc8128 curl -i \
  --keystore ./keyfile.json \
  https://api.example.com/data
```

### Custom chain ID and signature options

```bash
erc8128 curl \
  --chain-id 137 \
  --binding class-bound \
  --replay replayable \
  --ttl 300 \
  --keystore ./keyfile.json \
  https://api.example.com/data
```

## How It Works

`erc8128 curl` uses the [ERC-8128](https://eips.ethereum.org/EIPS/eip-8128) standard to sign HTTP requests with Ethereum accounts. The signature is added to the request headers using the HTTP Message Signatures standard (RFC 9421).

The tool:
1. Creates an Ethereum signer from your wallet
2. Builds the HTTP request with your specified options
3. Signs the request according to ERC-8128
4. Sends the signed request and displays the response

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run locally
node dist/index.js --help
```

## License

MIT
