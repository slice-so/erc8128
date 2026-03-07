import { describe, expect, test } from "bun:test"
import { prepareVerifyRequest } from "./playground-forwarding"

describe("prepareVerifyRequest", () => {
  test("drops empty JSON bodies before forwarding", async () => {
    const source = new Request("https://erc8128.org/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: ""
    })

    const prepared = await prepareVerifyRequest(
      source,
      new URL("https://erc8128.org/api/auth/verify")
    )

    expect(prepared.ok).toBe(true)
    if (!prepared.ok) {
      throw new Error("Expected prepared request")
    }

    expect(prepared.request.headers.get("content-type")).toBeNull()
    expect(prepared.request.body).toBeNull()
  })

  test("rejects invalid JSON payloads", async () => {
    const source = new Request("https://erc8128.org/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{"
    })

    const prepared = await prepareVerifyRequest(
      source,
      new URL("https://erc8128.org/api/auth/verify")
    )

    expect(prepared).toEqual({
      ok: false,
      error: "invalid_json",
      detail: "Request body is not valid JSON"
    })
  })

  test("preserves valid JSON payloads", async () => {
    const source = new Request("https://erc8128.org/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ok: true })
    })

    const prepared = await prepareVerifyRequest(
      source,
      new URL("https://erc8128.org/api/auth/verify")
    )

    expect(prepared.ok).toBe(true)
    if (!prepared.ok) {
      throw new Error("Expected prepared request")
    }

    expect(prepared.request.headers.get("content-type")).toBe(
      "application/json"
    )
    expect(await prepared.request.clone().text()).toBe('{"ok":true}')
  })
})
