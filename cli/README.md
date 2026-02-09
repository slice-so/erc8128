# eth-fetch

CLI tool for signing HTTP requests with ERC-8128 (Ethereum HTTP signatures). Think of it as a curl extension that adds Ethereum-based authentication.

## Installation

```bash
npm install -g @slicekit/erc8128-cli
```

Or use directly with npx:

```bash
npx @slicekit/erc8128-cli <url>
```

## Usage

```bash
eth-fetch [options] <url>
```

### HTTP Options

```
-X, --request <method>    HTTP method (GET, POST, etc.) [default: GET]
-H, --header <header>     Add header (repeatable)
-d, --data <data>         Request body
-o, --output <file>       Write response to file
-i, --include             Include response headers in output
-v, --verbose             Show request details
```

### Wallet Options

```
--private-key <key>       Raw private key (⚠️  insecure)
--keystore <path>         Path to encrypted keystore file
--password <pass>         Keystore password (or prompts interactively)
--ledger                  Use Ledger hardware wallet (not yet implemented)
--trezor                  Use Trezor hardware wallet (not yet implemented)
```

**Environment Variable:** You can also set `ETH_PRIVATE_KEY` to provide a private key.

⚠️ **Security Warning:** Using `--private-key` or `ETH_PRIVATE_KEY` is insecure as the key may be visible in shell history. Use `--keystore` for better security.

### ERC-8128 Options

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

### Using keystore file

```bash
eth-fetch --keystore ./keyfile.json https://api.example.com/data
```

### With environment variable

```bash
export ETH_PRIVATE_KEY=0x...
eth-fetch https://api.example.com/data
```

### Verbose output

```bash
eth-fetch -v --private-key 0x... https://api.example.com/data
```

### Save response to file

```bash
eth-fetch -o response.json --private-key 0x... https://api.example.com/data
```

### Include response headers

```bash
eth-fetch -i --private-key 0x... https://api.example.com/data
```

### Custom chain ID and signature options

```bash
eth-fetch \
  --chain-id 137 \
  --binding class-bound \
  --replay replayable \
  --ttl 300 \
  --private-key 0x... \
  https://api.example.com/data
```

## How It Works

`eth-fetch` uses the [ERC-8128](https://eips.ethereum.org/EIPS/eip-8128) standard to sign HTTP requests with Ethereum accounts. The signature is added to the request headers using the HTTP Message Signatures standard (RFC 9421).

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
