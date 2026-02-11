import { writeFile } from "node:fs/promises"

export interface OutputOptions {
  include: boolean
  output?: string
  verbose: boolean
  json?: boolean
}

export async function handleResponse(
  response: Response,
  opts: OutputOptions
): Promise<void> {
  let output = ""

  if (opts.json) {
    const body = await response.text()
    const headers = Object.fromEntries(response.headers.entries())
    const payload = {
      ok: response.ok,
      status: response.status,
      statusText: response.statusText,
      headers,
      body
    }
    output = JSON.stringify(payload)
    await writeOutput(output, opts)
    return
  }

  // Include response headers if requested
  if (opts.include) {
    output += `HTTP/${response.status} ${response.statusText}\n`
    for (const [key, value] of response.headers.entries()) {
      output += `${key}: ${value}\n`
    }
    output += "\n"
  }

  // Get response body
  const body = await response.text()
  output += body

  await writeOutput(output, opts)
}

export function logVerbose(message: string, verbose: boolean): void {
  if (verbose) {
    console.error(message)
  }
}

async function writeOutput(output: string, opts: OutputOptions): Promise<void> {
  if (opts.output) {
    await writeFile(opts.output, output, "utf-8")
    if (opts.verbose) {
      console.error(`✓ Response written to ${opts.output}`)
    }
    return
  }

  console.log(output)
}
