import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test"
import type { BindingMode, ReplayMode } from "@slicekit/erc8128"
import { Command } from "commander"

// We test the validation and parsing logic by creating a new Command instance
// with the same options as parseArgs, but calling parse() with explicit argv

interface CliOptions {
  method: string
  headers: string[]
  data?: string
  output?: string
  include: boolean
  verbose: boolean
  privateKey?: string
  keystore?: string
  password?: string
  ledger: boolean
  trezor: boolean
  chainId: number
  binding: BindingMode
  replay: ReplayMode
  ttl: number
  url: string
}

function collect(value: string, previous: string[]): string[] {
  return previous.concat([value])
}

function parseIntOption(value: string): number {
  const parsed = Number.parseInt(value, 10)
  if (Number.isNaN(parsed)) {
    throw new Error(`Invalid number: ${value}`)
  }
  return parsed
}

function validateBinding(value: string): BindingMode {
  if (value !== "request-bound" && value !== "class-bound") {
    throw new Error(
      `Invalid binding mode: ${value}. Must be 'request-bound' or 'class-bound'.`
    )
  }
  return value as BindingMode
}

function validateReplay(value: string): ReplayMode {
  if (value !== "non-replayable" && value !== "replayable") {
    throw new Error(
      `Invalid replay mode: ${value}. Must be 'non-replayable' or 'replayable'.`
    )
  }
  return value as ReplayMode
}

function createProgram(): Command {
  const program = new Command()

  program
    .name("eth-fetch")
    .description("Sign HTTP requests with ERC-8128 (Ethereum HTTP signatures)")
    .version("0.1.0")
    .argument("<url>", "URL to fetch")
    .option("-X, --request <method>", "HTTP method", "GET")
    .option("-H, --header <header>", "Add header (repeatable)", collect, [])
    .option("-d, --data <data>", "Request body")
    .option("-o, --output <file>", "Write response to file")
    .option("-i, --include", "Include response headers in output", false)
    .option("-v, --verbose", "Show request details", false)
    .option("--private-key <key>", "Raw private key (⚠️  insecure)")
    .option("--keystore <path>", "Path to encrypted keystore file")
    .option("--password <pass>", "Keystore password (or prompts interactively)")
    .option(
      "--ledger",
      "Use Ledger hardware wallet (not yet implemented)",
      false
    )
    .option(
      "--trezor",
      "Use Trezor hardware wallet (not yet implemented)",
      false
    )
    .option("--chain-id <id>", "Chain ID", parseIntOption, 1)
    .option(
      "--binding <mode>",
      "Binding mode: request-bound | class-bound",
      validateBinding,
      "request-bound"
    )
    .option(
      "--replay <mode>",
      "Replay mode: non-replayable | replayable",
      validateReplay,
      "non-replayable"
    )
    .option("--ttl <seconds>", "Signature TTL in seconds", parseIntOption, 60)
    .exitOverride() // Throw instead of process.exit

  return program
}

function parseTestArgs(argv: string[]): CliOptions {
  const program = createProgram()
  program.parse(["node", "eth-fetch", ...argv])

  const url = program.args[0]
  const opts = program.opts()

  return {
    method: opts.request.toUpperCase(),
    headers: opts.header,
    data: opts.data,
    output: opts.output,
    include: opts.include,
    verbose: opts.verbose,
    privateKey: opts.privateKey,
    keystore: opts.keystore,
    password: opts.password,
    ledger: opts.ledger,
    trezor: opts.trezor,
    chainId: opts.chainId,
    binding: opts.binding,
    replay: opts.replay,
    ttl: opts.ttl,
    url
  }
}

describe("CLI argument parsing", () => {
  describe("default values", () => {
    test("uses GET method by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.method).toBe("GET")
    })

    test("uses chain-id 1 by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.chainId).toBe(1)
    })

    test("uses request-bound binding by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.binding).toBe("request-bound")
    })

    test("uses non-replayable replay mode by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.replay).toBe("non-replayable")
    })

    test("uses 60 second TTL by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.ttl).toBe(60)
    })

    test("has empty headers by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.headers).toEqual([])
    })

    test("include is false by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.include).toBe(false)
    })

    test("verbose is false by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.verbose).toBe(false)
    })

    test("hardware wallets are disabled by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.ledger).toBe(false)
      expect(opts.trezor).toBe(false)
    })
  })

  describe("method parsing", () => {
    test("parses -X POST", () => {
      const opts = parseTestArgs(["-X", "POST", "https://example.com"])
      expect(opts.method).toBe("POST")
    })

    test("parses --request PUT", () => {
      const opts = parseTestArgs(["--request", "put", "https://example.com"])
      expect(opts.method).toBe("PUT")
    })

    test("uppercases method", () => {
      const opts = parseTestArgs(["-X", "patch", "https://example.com"])
      expect(opts.method).toBe("PATCH")
    })

    test("supports DELETE method", () => {
      const opts = parseTestArgs(["-X", "DELETE", "https://example.com"])
      expect(opts.method).toBe("DELETE")
    })
  })

  describe("header collection", () => {
    test("collects single header", () => {
      const opts = parseTestArgs([
        "-H",
        "Content-Type: application/json",
        "https://example.com"
      ])
      expect(opts.headers).toEqual(["Content-Type: application/json"])
    })

    test("collects multiple headers", () => {
      const opts = parseTestArgs([
        "-H",
        "Content-Type: application/json",
        "-H",
        "Authorization: Bearer token",
        "-H",
        "X-Custom: value",
        "https://example.com"
      ])
      expect(opts.headers).toEqual([
        "Content-Type: application/json",
        "Authorization: Bearer token",
        "X-Custom: value"
      ])
    })

    test("supports --header long form", () => {
      const opts = parseTestArgs([
        "--header",
        "Accept: text/plain",
        "https://example.com"
      ])
      expect(opts.headers).toEqual(["Accept: text/plain"])
    })
  })

  describe("binding mode validation", () => {
    test("accepts request-bound", () => {
      const opts = parseTestArgs([
        "--binding",
        "request-bound",
        "https://example.com"
      ])
      expect(opts.binding).toBe("request-bound")
    })

    test("accepts class-bound", () => {
      const opts = parseTestArgs([
        "--binding",
        "class-bound",
        "https://example.com"
      ])
      expect(opts.binding).toBe("class-bound")
    })

    test("rejects invalid binding mode", () => {
      expect(() =>
        parseTestArgs(["--binding", "invalid", "https://example.com"])
      ).toThrow("Invalid binding mode: invalid")
    })
  })

  describe("replay mode validation", () => {
    test("accepts non-replayable", () => {
      const opts = parseTestArgs([
        "--replay",
        "non-replayable",
        "https://example.com"
      ])
      expect(opts.replay).toBe("non-replayable")
    })

    test("accepts replayable", () => {
      const opts = parseTestArgs([
        "--replay",
        "replayable",
        "https://example.com"
      ])
      expect(opts.replay).toBe("replayable")
    })

    test("rejects invalid replay mode", () => {
      expect(() =>
        parseTestArgs(["--replay", "maybe", "https://example.com"])
      ).toThrow("Invalid replay mode: maybe")
    })
  })

  describe("integer parsing", () => {
    test("parses chain-id as integer", () => {
      const opts = parseTestArgs(["--chain-id", "137", "https://example.com"])
      expect(opts.chainId).toBe(137)
    })

    test("parses ttl as integer", () => {
      const opts = parseTestArgs(["--ttl", "300", "https://example.com"])
      expect(opts.ttl).toBe(300)
    })

    test("rejects non-numeric chain-id", () => {
      expect(() =>
        parseTestArgs(["--chain-id", "mainnet", "https://example.com"])
      ).toThrow("Invalid number: mainnet")
    })

    test("rejects non-numeric ttl", () => {
      // Note: parseInt("1m") returns 1, so we test with fully non-numeric value
      expect(() =>
        parseTestArgs(["--ttl", "forever", "https://example.com"])
      ).toThrow("Invalid number: forever")
    })

    test("parses decimal as integer (truncates)", () => {
      const opts = parseTestArgs(["--chain-id", "10.5", "https://example.com"])
      expect(opts.chainId).toBe(10)
    })
  })

  describe("data and output options", () => {
    test("parses --data", () => {
      const opts = parseTestArgs([
        "-d",
        '{"key":"value"}',
        "https://example.com"
      ])
      expect(opts.data).toBe('{"key":"value"}')
    })

    test("parses --output", () => {
      const opts = parseTestArgs(["-o", "response.json", "https://example.com"])
      expect(opts.output).toBe("response.json")
    })

    test("parses -i flag", () => {
      const opts = parseTestArgs(["-i", "https://example.com"])
      expect(opts.include).toBe(true)
    })

    test("parses -v flag", () => {
      const opts = parseTestArgs(["-v", "https://example.com"])
      expect(opts.verbose).toBe(true)
    })
  })

  describe("wallet options", () => {
    test("parses --private-key", () => {
      const opts = parseTestArgs([
        "--private-key",
        "0xabc123",
        "https://example.com"
      ])
      expect(opts.privateKey).toBe("0xabc123")
    })

    test("parses --keystore", () => {
      const opts = parseTestArgs([
        "--keystore",
        "/path/to/keystore.json",
        "https://example.com"
      ])
      expect(opts.keystore).toBe("/path/to/keystore.json")
    })

    test("parses --password", () => {
      const opts = parseTestArgs([
        "--keystore",
        "/path/to/keystore.json",
        "--password",
        "secret",
        "https://example.com"
      ])
      expect(opts.password).toBe("secret")
    })

    test("parses --ledger flag", () => {
      const opts = parseTestArgs(["--ledger", "https://example.com"])
      expect(opts.ledger).toBe(true)
    })

    test("parses --trezor flag", () => {
      const opts = parseTestArgs(["--trezor", "https://example.com"])
      expect(opts.trezor).toBe(true)
    })
  })

  describe("URL parsing", () => {
    test("captures URL as positional argument", () => {
      const opts = parseTestArgs(["https://api.example.com/v1/resource"])
      expect(opts.url).toBe("https://api.example.com/v1/resource")
    })

    test("URL can have query params", () => {
      const opts = parseTestArgs(["https://example.com/api?foo=bar&baz=qux"])
      expect(opts.url).toBe("https://example.com/api?foo=bar&baz=qux")
    })
  })

  describe("combined options", () => {
    test("parses full curl-like command", () => {
      const opts = parseTestArgs([
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "-H",
        "Authorization: Bearer token",
        "-d",
        '{"name":"test"}',
        "--chain-id",
        "137",
        "--binding",
        "request-bound",
        "--replay",
        "non-replayable",
        "--ttl",
        "120",
        "--private-key",
        "0x1234",
        "-i",
        "-v",
        "https://api.example.com/submit"
      ])

      expect(opts.method).toBe("POST")
      expect(opts.headers).toEqual([
        "Content-Type: application/json",
        "Authorization: Bearer token"
      ])
      expect(opts.data).toBe('{"name":"test"}')
      expect(opts.chainId).toBe(137)
      expect(opts.binding).toBe("request-bound")
      expect(opts.replay).toBe("non-replayable")
      expect(opts.ttl).toBe(120)
      expect(opts.privateKey).toBe("0x1234")
      expect(opts.include).toBe(true)
      expect(opts.verbose).toBe(true)
      expect(opts.url).toBe("https://api.example.com/submit")
    })
  })
})
