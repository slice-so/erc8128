import { describe, expect, test } from "bun:test"
import { selectSignatureFromHeaders } from "./signatureHeaders"

function makeHeaders(label: string, keyid: string, sigB64 = "AAAA") {
  const sigInput = `${label}=("@authority");created=100;expires=200;keyid="${keyid}"`
  const sig = `${label}=:${sigB64}:`
  return { sigInput, sig }
}

const EIP_KEYID = "eip155:1:0x0000000000000000000000000000000000000001"
const NON_EIP_KEYID = "legacy:1:0x0000000000000000000000000000000000000001"

describe("selectSignatureFromHeaders", () => {
  test("correlates the two fields by their transport label", () => {
    const { sigInput, sig } = makeHeaders("eth", EIP_KEYID)
    const result = selectSignatureFromHeaders({
      signatureInputHeader: sigInput,
      signatureHeader: sig
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
      signatureHeader: `${bad.sig}, ${good.sig}`
    })
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error("unreachable")
    expect(result.selected[0].label).toBe("bad")
  })

  test("returns signature_input_invalid without a correlated member", () => {
    const { sigInput } = makeHeaders("eth", NON_EIP_KEYID)
    const result = selectSignatureFromHeaders({
      signatureInputHeader: sigInput,
      signatureHeader: "other=:AAAA:"
    })
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error("unreachable")
    expect(result.result).toEqual({
      ok: false,
      reason: "signature_input_invalid"
    })
  })

  test("returns signature_input_invalid for malformed Signature-Input", () => {
    const result = selectSignatureFromHeaders({
      signatureInputHeader: "not-a-dictionary",
      signatureHeader: "eth=:AAAA:"
    })
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error("unreachable")
    expect(result.result.ok).toBe(false)
    if (result.result.ok) throw new Error("unreachable")
    expect(result.result.reason).toBe("signature_input_invalid")
  })

  test("returns signature_input_invalid for malformed Signature", () => {
    const sigInput = `eth=("@authority");created=100;expires=200;keyid="${EIP_KEYID}"`
    const result = selectSignatureFromHeaders({
      signatureInputHeader: sigInput,
      signatureHeader: "not-a-dictionary"
    })
    expect(result.ok).toBe(false)
    if (result.ok) throw new Error("unreachable")
    expect(result.result.ok).toBe(false)
    if (result.result.ok) throw new Error("unreachable")
    expect(result.result.reason).toBe("signature_input_invalid")
  })

  test("leaves key identifier validation to profile candidate evaluation", () => {
    const { sigInput, sig } = makeHeaders("eth", NON_EIP_KEYID)
    const result = selectSignatureFromHeaders({
      signatureInputHeader: sigInput,
      signatureHeader: sig
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
      signatureHeader: sig
    })
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error("unreachable")
    expect(result.selected[0].components.map(({ name }) => name)).toEqual([
      "@authority",
      "@method",
      "@path"
    ])
    expect(result.selected[0].params.created).toBe(1700000000)
    expect(result.selected[0].params.expires).toBe(1700000060)
    expect(result.selected[0].params.nonce).toBe("abc")
    expect(result.selected[0].sigB64).toBe("dGVzdA==")
  })

  test("preserves wire order when multiple members exist", () => {
    const first = makeHeaders("alpha", EIP_KEYID, "RklSU1Q=")
    const second = makeHeaders("beta", EIP_KEYID, "U0VDT05E")
    const result = selectSignatureFromHeaders({
      signatureInputHeader: `${first.sigInput}, ${second.sigInput}`,
      signatureHeader: `${first.sig}, ${second.sig}`
    })
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error("unreachable")
    expect(result.selected[0].label).toBe("alpha")
  })

  test("skips a malformed candidate before a later valid member", () => {
    const good = makeHeaders("good", EIP_KEYID)
    const result = selectSignatureFromHeaders({
      signatureInputHeader: `broken=not-an-inner-list, ${good.sigInput}`,
      signatureHeader: `broken=:!!!!:, ${good.sig}`
    })
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error("unreachable")
    expect(result.selected.map(({ label }) => label)).toEqual(["good"])
  })
})
