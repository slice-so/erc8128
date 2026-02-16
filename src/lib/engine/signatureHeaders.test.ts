import { describe, expect, test } from "bun:test"
import { selectSignatureFromHeaders } from "./signatureHeaders.js"

function makeHeaders(label: string, keyid: string, sigB64 = "AAAA") {
  const sigInput = `${label}=("@authority");created=100;expires=200;keyid="${keyid}"`
  const sig = `${label}=:${sigB64}:`
  return { sigInput, sig }
}

const EIP_KEYID = "erc8128:1:0x0000000000000000000000000000000000000001"
const NON_EIP_KEYID = "not-erc8128:1:0x0000000000000000000000000000000000000001"

describe("selectSignatureFromHeaders", () => {
  test("selects by preferred label", () => {
    const { sigInput, sig } = makeHeaders("eth", EIP_KEYID)
    const result = selectSignatureFromHeaders({
      signatureInputHeader: sigInput,
      signatureHeader: sig,
      policy: { label: "eth" }
    })
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error("unreachable")
    expect(result.selected[0].label).toBe("eth")
    expect(result.selected[0].sigB64).toBe("AAAA")
  })

  test("falls back to first member with a matching Signature entry", () => {
    const bad = makeHeaders("bad", NON_EIP_KEYID, "BBBB")
    const good = makeHeaders("good", EIP_KEYID, "GGGG")
    const result = selectSignatureFromHeaders({
      signatureInputHeader: `${bad.sigInput}, ${good.sigInput}`,
      signatureHeader: `${bad.sig}, ${good.sig}`,
      policy: {}
    })
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error("unreachable")
    expect(result.selected[0].label).toBe("bad")
  })

  test("strictLabel returns label_not_found when label not present", () => {
    const { sigInput, sig } = makeHeaders("foo", EIP_KEYID)
    const result = selectSignatureFromHeaders({
      signatureInputHeader: sigInput,
      signatureHeader: sig,
      policy: { label: "eth", strictLabel: true }
    })
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error("unreachable")
    expect(result.result).toEqual({ ok: false, reason: "label_not_found" })
  })

  test("returns label_not_found when no member has matching Signature entry", () => {
    const { sigInput } = makeHeaders("eth", NON_EIP_KEYID)
    const result = selectSignatureFromHeaders({
      signatureInputHeader: sigInput,
      signatureHeader: "other=:AAAA:",
      policy: {}
    })
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error("unreachable")
    expect(result.result).toEqual({ ok: false, reason: "label_not_found" })
  })

  test("strictLabel enforces preferred label has a Signature entry", () => {
    const sigInput = `eth=("@authority");created=100;expires=200;keyid="${EIP_KEYID}", other=("@authority");created=100;expires=200;keyid="${EIP_KEYID}"`
    const sig = "other=:AAAA:"
    const result = selectSignatureFromHeaders({
      signatureInputHeader: sigInput,
      signatureHeader: sig,
      policy: { label: "eth", strictLabel: true }
    })
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error("unreachable")
    expect(result.result).toEqual({ ok: false, reason: "label_not_found" })
  })

  test("returns bad_signature_input for malformed Signature-Input", () => {
    const result = selectSignatureFromHeaders({
      signatureInputHeader: "not-a-dictionary",
      signatureHeader: "eth=:AAAA:",
      policy: {}
    })
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error("unreachable")
    expect(result.result.ok).toBe(false)
    if (result.result.ok) throw new Error("unreachable")
    expect(result.result.reason).toBe("bad_signature_input")
  })

  test("returns bad_signature_input for malformed Signature", () => {
    const sigInput = `eth=("@authority");created=100;expires=200;keyid="${EIP_KEYID}"`
    const result = selectSignatureFromHeaders({
      signatureInputHeader: sigInput,
      signatureHeader: "not-a-dictionary",
      policy: {}
    })
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error("unreachable")
    expect(result.result.ok).toBe(false)
    if (result.result.ok) throw new Error("unreachable")
    expect(result.result.reason).toBe("bad_signature_input")
  })

  test("selects preferred label even with non-compliant keyid", () => {
    const { sigInput, sig } = makeHeaders("eth", NON_EIP_KEYID)
    const result = selectSignatureFromHeaders({
      signatureInputHeader: sigInput,
      signatureHeader: sig,
      policy: { label: "eth" }
    })
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error("unreachable")
    expect(result.selected[0].label).toBe("eth")
  })

  test("returns components and params from selected member", () => {
    const sigInput = `eth=("@authority" "@method" "@path");created=1700000000;expires=1700000060;nonce="abc";keyid="${EIP_KEYID}"`
    const sig = "eth=:dGVzdA==:"
    const result = selectSignatureFromHeaders({
      signatureInputHeader: sigInput,
      signatureHeader: sig,
      policy: { label: "eth" }
    })
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error("unreachable")
    expect(result.selected[0].components).toEqual([
      "@authority",
      "@method",
      "@path"
    ])
    expect(result.selected[0].params.created).toBe(1700000000)
    expect(result.selected[0].params.expires).toBe(1700000060)
    expect(result.selected[0].params.nonce).toBe("abc")
    expect(result.selected[0].sigB64).toBe("dGVzdA==")
  })

  test("selects first member when multiple exist and no label pref", () => {
    const first = makeHeaders("alpha", EIP_KEYID, "FIRST")
    const second = makeHeaders("beta", EIP_KEYID, "SECOND")
    const result = selectSignatureFromHeaders({
      signatureInputHeader: `${first.sigInput}, ${second.sigInput}`,
      signatureHeader: `${first.sig}, ${second.sig}`,
      policy: {}
    })
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error("unreachable")
    expect(result.selected[0].label).toBe("alpha")
  })
})
