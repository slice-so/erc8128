import type { SelectedSignature, VerifyPolicy, VerifyResult } from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import {
  parseSignatureDictionary,
  parseSignatureInputDictionary,
  splitTopLevelCommas
} from "./createSignatureInput"

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
    const parsedSigs = new Map<string, string>()
    const ambiguousSignatures = new Set<string>()
    for (const member of splitTopLevelCommas(signatureHeader)) {
      try {
        const parsed = parseSignatureDictionary(member)
        for (const [label, signature] of parsed) {
          if (parsedSigs.has(label)) ambiguousSignatures.add(label)
          else parsedSigs.set(label, signature)
        }
      } catch {
        // A malformed unrelated member must not block a later valid candidate.
      }
    }

    const candidates: SelectedSignature[] = []
    const seenInputs = new Set<string>()
    let parsedInputCount = 0
    for (const member of splitTopLevelCommas(signatureInputHeader)) {
      try {
        const parsed = parseSignatureInputDictionary(member)
        const candidate = parsed[0]
        if (candidate === undefined) continue
        parsedInputCount += 1
        if (seenInputs.has(candidate.label)) {
          const existingIndex = candidates.findIndex(
            ({ label }) => label === candidate.label
          )
          if (existingIndex >= 0) candidates.splice(existingIndex, 1)
          continue
        }
        seenInputs.add(candidate.label)
        const signature = parsedSigs.get(candidate.label)
        if (!signature || ambiguousSignatures.has(candidate.label)) continue
        candidates.push({
          label: candidate.label,
          components: candidate.components,
          params: candidate.params,
          signatureParamsValue: candidate.signatureParamsValue,
          sigB64: signature
        })
      } catch {
        // Continue in header order so one bad candidate cannot cause downgrade
        // or denial when a later independent candidate is valid.
      }
    }

    if (candidates.length === 0) {
      return {
        ok: false,
        result: {
          ok: false,
          reason:
            parsedInputCount === 0 || parsedSigs.size === 0
              ? "bad_signature_input"
              : "label_not_found"
        }
      }
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
