import { describe, expect, test } from "bun:test"
import { parseArgs } from "./args.js"

function parseTestArgs(argv: string[]) {
  return parseArgs(["node", "erc8128", "curl", ...argv], {
    exitOverride: true
  })
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

    test("json is false by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.json).toBe(false)
    })

    test("fail is false by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.fail).toBe(false)
    })

    test("dryRun is false by default", () => {
      const opts = parseTestArgs(["https://example.com"])
      expect(opts.dryRun).toBe(false)
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
        "--components",
        "@authority",
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

    test("parses --json flag", () => {
      const opts = parseTestArgs(["--json", "https://example.com"])
      expect(opts.json).toBe(true)
    })

    test("parses --fail flag", () => {
      const opts = parseTestArgs(["--fail", "https://example.com"])
      expect(opts.fail).toBe(true)
    })

    test("parses --dry-run flag", () => {
      const opts = parseTestArgs(["--dry-run", "https://example.com"])
      expect(opts.dryRun).toBe(true)
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

    test("parses --keyfile", () => {
      const opts = parseTestArgs([
        "--keyfile",
        "/path/to/key",
        "https://example.com"
      ])
      expect(opts.keyfile).toBe("/path/to/key")
    })

    test("parses --keyid", () => {
      const opts = parseTestArgs([
        "--keyid",
        "erc8128:1:0x14791697260E4c9A71f18484C9f997B308e59325",
        "https://example.com"
      ])
      expect(opts.keyid).toBe(
        "erc8128:1:0x14791697260E4c9A71f18484C9f997B308e59325"
      )
      expect(opts.keyIdAddress).toBe(
        "0x14791697260e4c9a71f18484c9f997b308e59325"
      )
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

  describe("components parsing", () => {
    test("parses --components as repeatable", () => {
      const opts = parseTestArgs([
        "--components",
        "x-api-key",
        "--components",
        "x-request-id",
        "https://example.com"
      ])
      expect(opts.components).toEqual(["x-api-key", "x-request-id"])
    })

    test("parses --components with comma-separated values", () => {
      const opts = parseTestArgs([
        "--components",
        "x-api-key,x-request-id",
        "https://example.com"
      ])
      expect(opts.components).toEqual(["x-api-key", "x-request-id"])
    })

    test("requires components for class-bound", () => {
      expect(() =>
        parseTestArgs(["--binding", "class-bound", "https://example.com"])
      ).toThrow("components are required for class-bound signatures.")
    })
  })

  describe("config file defaults", () => {
    test("uses config defaults when flags are omitted", () => {
      const configPath = "/tmp/erc8128-config.json"
      Bun.write(
        configPath,
        JSON.stringify({
          chainId: 8453,
          binding: "request-bound",
          replay: "replayable",
          ttl: 120,
          headers: ["X-From-Config: true"],
          components: ["x-idempotency-key"]
        })
      )

      const opts = parseTestArgs([
        "--config",
        configPath,
        "https://example.com"
      ])

      expect(opts.chainId).toBe(8453)
      expect(opts.replay).toBe("replayable")
      expect(opts.ttl).toBe(120)
      expect(opts.headers).toEqual(["X-From-Config: true"])
      expect(opts.components).toEqual(["x-idempotency-key"])
    })

    test("CLI flags override config defaults", () => {
      const configPath = "/tmp/erc8128-config-override.json"
      Bun.write(
        configPath,
        JSON.stringify({
          method: "POST",
          chainId: 1,
          ttl: 60,
          headers: ["X-From-Config: true"]
        })
      )

      const opts = parseTestArgs([
        "--config",
        configPath,
        "-X",
        "GET",
        "--chain-id",
        "137",
        "-H",
        "X-From-CLI: true",
        "https://example.com"
      ])

      expect(opts.method).toBe("GET")
      expect(opts.chainId).toBe(137)
      expect(opts.headers).toEqual(["X-From-Config: true", "X-From-CLI: true"])
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
        "--components",
        "x-idempotency-key",
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
      expect(opts.components).toEqual(["x-idempotency-key"])
      expect(opts.privateKey).toBe("0x1234")
      expect(opts.include).toBe(true)
      expect(opts.verbose).toBe(true)
      expect(opts.url).toBe("https://api.example.com/submit")
    })
  })
})
