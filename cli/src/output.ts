import { writeFile } from "node:fs/promises"

export interface OutputOptions {
  include: boolean
  output?: string
  verbose: boolean
}

export async function handleResponse(
  response: Response,
  opts: OutputOptions
): Promise<void> {
  let output = ""

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

  // Write to file or stdout
  if (opts.output) {
    await writeFile(opts.output, output, "utf-8")
    if (opts.verbose) {
      console.error(`✓ Response written to ${opts.output}`)
    }
  } else {
    console.log(output)
  }
}

export function logVerbose(message: string, verbose: boolean): void {
  if (verbose) {
    console.error(message)
  }
}
