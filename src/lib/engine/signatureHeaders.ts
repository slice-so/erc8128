import type { SelectedSignature, VerifyResult } from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import {
  parseSignatureDictionary,
  parseSignatureInputDictionary
} from "./createSignatureInput"

/** Parse both complete RFC 9651 Dictionaries before candidate evaluation. */
export function selectSignatureFromHeaders(args: {
  signatureInputHeader: string
  signatureHeader: string
}):
  | { ok: true; selected: SelectedSignature[] }
  | { ok: false; result: VerifyResult } {
  const encoder = new TextEncoder()
  if (
    encoder.encode(args.signatureInputHeader).length > 16_384 ||
    encoder.encode(args.signatureHeader).length > 16_384
  ) {
    return { ok: false, result: { ok: false, reason: "signature_too_large" } }
  }
  try {
    const inputs = parseSignatureInputDictionary(args.signatureInputHeader)
    const signatures = parseSignatureDictionary(args.signatureHeader)
    for (const signature of signatures.values()) {
      const bytes = base64Bytes(signature)
      if (bytes > 8_192) {
        return {
          ok: false,
          result: { ok: false, reason: "signature_too_large" }
        }
      }
    }
    return {
      ok: true,
      selected: inputs.map((candidate) => ({
        label: candidate.label,
        components: candidate.components,
        params: candidate.params,
        signatureParamsValue: candidate.signatureParamsValue,
        ...(signatures.get(candidate.label) === undefined
          ? {}
          : { sigB64: signatures.get(candidate.label) })
      }))
    }
  } catch (error) {
    return {
      ok: false,
      result: {
        ok: false,
        reason:
          error instanceof Erc8128Error && error.code === "LIMIT_EXCEEDED"
            ? "signature_too_large"
            : "signature_input_invalid",
        ...(error instanceof Error ? { detail: error.message } : {})
      }
    }
  }
}

function base64Bytes(value: string): number {
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0
  return (value.length / 4) * 3 - padding
}
