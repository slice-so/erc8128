import { describe, expect, test } from "bun:test"
import { createSignerClient } from "./index.js"
import type { Address, Hex } from "./lib/types.js"

function makeSigner() {
  return {
    chainId: 1,
    address: "0x0000000000000000000000000000000000000001" as Address,
    signMessage: async () => "0x11" as Hex
  }
}

describe("ERC-8128 client", () => {
  test("signRequest merges defaults with per-call options", async () => {
    const signer = makeSigner()
    const client = createSignerClient(signer, {
      created: 1_700_000_000,
      expires: 1_700_000_060,
      nonce: "nonce-default"
    })

    const signed = await client.signRequest("https://example.com", {
      nonce: "nonce-override"
    })

    const sigInput = signed.headers.get("Signature-Input")
    expect(sigInput).toBeTruthy()
    if (!sigInput) throw new Error("unreachable")
    expect(sigInput).toContain('nonce="nonce-override"')
    expect(sigInput).toContain("created=1700000000")
    expect(sigInput).toContain("expires=1700000060")
  })

  test("fetch uses defaults.fetch and supports init/opts overloads", async () => {
    const signer = makeSigner()
    type RecordedRequest = { headers: Headers }
    const makeRecorder = () => {
      let resolve!: (request: RecordedRequest) => void
      const promise = new Promise<RecordedRequest>((res) => {
        resolve = res
      })
      return { promise, resolve }
    }

    let recorder = makeRecorder()
    const fetchStub = Object.assign(
      (async (input: RequestInfo | URL, init?: RequestInit) => {
        const req = input instanceof Request ? input : new Request(input, init)
        recorder.resolve({ headers: req.headers })
        return new Response("ok")
      }) as typeof fetch,
      { preconnect: () => undefined }
    )

    const client = createSignerClient(signer, {
      fetch: fetchStub,
      created: 1_700_000_000,
      expires: 1_700_000_060,
      nonce: "nonce-default"
    })

    await client.fetch(
      "https://example.com",
      { method: "GET" },
      {
        nonce: "nonce-call"
      }
    )

    const firstRequest = await recorder.promise
    expect(firstRequest.headers.get("Signature-Input")).toContain(
      'nonce="nonce-call"'
    )

    recorder = makeRecorder()
    await client.fetch("https://example.com/opts-only", { nonce: "nonce-only" })
    const secondRequest = await recorder.promise
    expect(secondRequest.headers.get("Signature-Input")).toContain(
      'nonce="nonce-only"'
    )
  })
})
