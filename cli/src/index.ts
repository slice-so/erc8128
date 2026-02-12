import { readFile, writeFile } from "node:fs/promises"
import { signedFetch, signRequest } from "@slicekit/erc8128"
import { type CliOptions, parseArgs } from "./args.js"
import { handleResponse, logVerbose } from "./output.js"
import { createSigner } from "./wallet.js"

async function main(): Promise<void> {
  try {
    const opts = parseArgs()

    // Create signer
    logVerbose("Creating signer...", opts.verbose)
    const signer = await createSigner({
      privateKey: opts.privateKey,
      keyfile: opts.keyfile,
      keystore: opts.keystore,
      password: opts.password,
      chainId: opts.chainId
    })

    if (opts.keyIdAddress) {
      if (signer.address.toLowerCase() !== opts.keyIdAddress) {
        throw new Error(
          `Key ID address (${opts.keyIdAddress}) does not match signer address (${signer.address}).`
        )
      }
    }

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
      init.body = await resolveData(opts.data)
    }

    if (opts.dryRun) {
      logVerbose("\nSigning request (dry-run)...", opts.verbose)
      const signedRequest = await signRequest(opts.url, init, signer, {
        binding: opts.binding,
        replay: opts.replay,
        ttlSeconds: opts.ttl,
        components: opts.components
      })
      await outputDryRun(signedRequest, opts)
      process.exit(0)
    } else {
      // Make signed request
      logVerbose("\nSigning request...", opts.verbose)
      const response = await signedFetch(opts.url, init, signer, {
        binding: opts.binding,
        replay: opts.replay,
        ttlSeconds: opts.ttl,
        components: opts.components
      })

      logVerbose("✓ Request signed and sent\n", opts.verbose)

      // Handle response
      await handleResponse(response, {
        include: opts.include,
        output: opts.output,
        verbose: opts.verbose,
        json: opts.json
      })

      if (opts.fail && !response.ok) {
        process.exit(1)
      }
    }

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

async function resolveData(data: string): Promise<string> {
  if (!data.startsWith("@")) return data

  const target = data.slice(1)
  if (target === "-") {
    return readStdin()
  }

  return readFile(target, "utf-8")
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  }
  return Buffer.concat(chunks).toString("utf-8")
}

async function outputDryRun(
  signedRequest: Request,
  opts: CliOptions
): Promise<void> {
  if (opts.json) {
    const payload = {
      url: signedRequest.url,
      method: signedRequest.method,
      headers: Object.fromEntries(signedRequest.headers.entries())
    }
    const output = JSON.stringify(payload)
    await writeOutput(output, opts)
    return
  }

  const lines: string[] = []
  const signatureInput = signedRequest.headers.get("Signature-Input")
  const signature = signedRequest.headers.get("Signature")
  const contentDigest = signedRequest.headers.get("Content-Digest")

  if (signatureInput) lines.push(`Signature-Input: ${signatureInput}`)
  if (signature) lines.push(`Signature: ${signature}`)
  if (contentDigest) lines.push(`Content-Digest: ${contentDigest}`)

  await writeOutput(lines.join("\n"), opts)
}

async function writeOutput(output: string, opts: CliOptions): Promise<void> {
  if (opts.output) {
    await writeFile(opts.output, output, "utf-8")
    return
  }

  console.log(output)
}
