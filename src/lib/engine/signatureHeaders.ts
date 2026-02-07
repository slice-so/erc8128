import { Erc8128Error, type VerifyPolicy, type VerifyResult } from "../types.js"
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
 * Parse `Signature-Input` + `Signature` headers and select candidate signatures to verify.
 *
 * Selection rules:
 * - Include all members that have a matching Signature entry in header order.
 * - If `strictLabel=true` and the label is missing (or has no Signature entry), return label_not_found.
 * - If `strictLabel=true` and the label exists, only return members for that label.
 *
 * Never throws for parse errors; returns `{ ok: false, reason: "bad_signature_input" }` instead.
 */
export function selectSignatureFromHeaders(args: {
  signatureInputHeader: string
  signatureHeader: string
  policy: Pick<VerifyPolicy, "label" | "strictLabel">
}):
  | { ok: true; selected: SelectedSignature[] }
  | { ok: false; result: VerifyResult } {
  const { signatureInputHeader, signatureHeader, policy } = args
  const labelPref = policy.label
  const strictLabel = policy.strictLabel ?? false

  try {
    const parsedInputs = parseSignatureInputDictionary(signatureInputHeader)
    const parsedSigs = parseSignatureDictionary(signatureHeader)

    const candidates: SelectedSignature[] = []

    for (const cand of parsedInputs) {
      const s = parsedSigs.get(cand.label)
      if (!s) continue
      candidates.push({
        label: cand.label,
        components: cand.components,
        params: cand.params,
        signatureParamsValue: cand.signatureParamsValue,
        sigB64: s
      })
    }

    if (candidates.length === 0) {
      return { ok: false, result: { ok: false, reason: "label_not_found" } }
    }

    if (labelPref != null && strictLabel) {
      const strictCandidates = candidates.filter(
        (candidate) => candidate.label === labelPref
      )
      if (strictCandidates.length === 0) {
        return { ok: false, result: { ok: false, reason: "label_not_found" } }
      }
      return { ok: true, selected: strictCandidates }
    }

    return { ok: true, selected: candidates }
  } catch (err) {
    const detail =
      err instanceof Error ? err.message : "Failed to parse signature headers."
    if (err instanceof Erc8128Error && err.code === "PARSE_ERROR")
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
