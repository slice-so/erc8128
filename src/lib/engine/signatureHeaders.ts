import { parseKeyId } from "../keyId.js"
import { Eip8128Error, type VerifyPolicy, type VerifyResult } from "../types.js"
import {
  parseSignatureDictionary,
  parseSignatureInputDictionary
} from "./createSignatureInput.js"

export type SelectedSignature = {
  label: string
  components: string[]
  params: {
    keyid: string
    created: number
    expires: number
    nonce?: string
    tag?: string
  }
  signatureParamsValue: string
  sigB64: string
}

/**
 * Parse `Signature-Input` + `Signature` headers and select which signature member to verify.
 *
 * Selection rules:
 * - If `policy.label` is provided: prefer that label (fail if `strictLabel=true` and missing).
 * - Otherwise: pick the first `Signature-Input` member whose `keyid` is EIP-8128 compliant
 *   and which has a matching `Signature` entry.
 *
 * Never throws for parse errors; returns `{ ok: false, reason: "bad_signature_input" }` instead.
 */
export function selectSignatureFromHeaders(args: {
  signatureInputHeader: string
  signatureHeader: string
  policy: Pick<VerifyPolicy, "label" | "strictLabel">
}):
  | { ok: true; selected: SelectedSignature }
  | { ok: false; result: VerifyResult } {
  const { signatureInputHeader, signatureHeader, policy } = args
  const labelPref = policy.label
  const strictLabel = policy.strictLabel ?? false

  try {
    const parsedInputs = parseSignatureInputDictionary(signatureInputHeader)
    const parsedSigs = parseSignatureDictionary(signatureHeader)

    let chosen: (typeof parsedInputs)[number] | undefined
    let sigB64: string | undefined
    let fallback:
      | { member: (typeof parsedInputs)[number]; sigB64: string }
      | undefined
    let sawCompliantKeyid = false

    for (const cand of parsedInputs) {
      if (labelPref != null && cand.label === labelPref) {
        const s = parsedSigs.get(cand.label)
        if (!s)
          return { ok: false, result: { ok: false, reason: "label_not_found" } }
        chosen = cand
        sigB64 = s
        break
      }

      const key = parseKeyId(cand.params.keyid)
      if (!key) continue
      sawCompliantKeyid = true
      if (fallback) continue
      const s = parsedSigs.get(cand.label)
      if (!s) continue
      fallback = { member: cand, sigB64: s }
    }

    if (!chosen) {
      if (labelPref != null && strictLabel)
        return { ok: false, result: { ok: false, reason: "label_not_found" } }

      if (fallback) {
        chosen = fallback.member
        sigB64 = fallback.sigB64
      } else {
        return {
          ok: false,
          result: sawCompliantKeyid
            ? { ok: false, reason: "label_not_found" }
            : { ok: false, reason: "bad_keyid" }
        }
      }
    }

    if (!sigB64)
      return { ok: false, result: { ok: false, reason: "label_not_found" } }

    return {
      ok: true,
      selected: {
        label: chosen.label,
        components: chosen.components,
        params: chosen.params,
        signatureParamsValue: chosen.signatureParamsValue,
        sigB64
      }
    }
  } catch (err) {
    const detail =
      err instanceof Error ? err.message : "Failed to parse signature headers."
    if (err instanceof Eip8128Error && err.code === "PARSE_ERROR")
      return {
        ok: false,
        result: { ok: false, reason: "bad_signature_input", detail }
      }
    return {
      ok: false,
      result: { ok: false, reason: "bad_signature_input", detail }
    }
  }
}
