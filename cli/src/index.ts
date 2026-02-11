import { signedFetch } from "@slicekit/erc8128"
import { parseArgs } from "./args.js"
import { handleResponse, logVerbose } from "./output.js"
import { createSigner } from "./wallet.js"

async function main(): Promise<void> {
  try {
    const opts = parseArgs()

    // Create signer
    logVerbose("Creating signer...", opts.verbose)
    const signer = await createSigner({
      privateKey: opts.privateKey,
      keystore: opts.keystore,
      password: opts.password,
      ledger: opts.ledger,
      trezor: opts.trezor,
      chainId: opts.chainId
    })

    if (opts.verbose) {
      console.error(`✓ Using address: ${signer.address}`)
      console.error(`✓ Chain ID: ${signer.chainId}`)
      console.error(
        `✓ Signature mode: ${opts.binding}, ${opts.replay} (TTL: ${opts.ttl}s)`
      )
    }

    // Prepare request headers
    const headers = new Headers()
    for (const header of opts.headers) {
      const colonIndex = header.indexOf(":")
      if (colonIndex === -1) {
        throw new Error(
          `Invalid header format: ${header}. Expected 'Key: Value'`
        )
      }
      const key = header.slice(0, colonIndex).trim()
      const value = header.slice(colonIndex + 1).trim()
      headers.set(key, value)
    }

    // Prepare request init
    const init: RequestInit = {
      method: opts.method,
      headers
    }

    // Add body if provided
    if (opts.data) {
      init.body = opts.data
      // Set Content-Type if not already set
      if (!headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json")
      }
    }

    // Make signed request
    logVerbose("\nSigning request...", opts.verbose)
    const response = await signedFetch(opts.url, init, signer, {
      binding: opts.binding,
      replay: opts.replay,
      ttlSeconds: opts.ttl
    })

    logVerbose("✓ Request signed and sent\n", opts.verbose)

    // Handle response
    await handleResponse(response, {
      include: opts.include,
      output: opts.output,
      verbose: opts.verbose
    })

    process.exit(0)
  } catch (error) {
    if (error instanceof Error) {
      console.error(`Error: ${error.message}`)
      if (process.env.DEBUG) {
        console.error(error.stack)
      }
    } else {
      console.error("An unknown error occurred")
    }
    process.exit(1)
  }
}

main()
