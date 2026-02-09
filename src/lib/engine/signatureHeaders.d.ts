import { type VerifyPolicy, type VerifyResult } from "../types.js"
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
export declare function selectSignatureFromHeaders(args: {
  signatureInputHeader: string
  signatureHeader: string
  policy: Pick<VerifyPolicy, "label" | "strictLabel">
}):
  | {
      ok: true
      selected: SelectedSignature[]
    }
  | {
      ok: false
      result: VerifyResult
    }
//# sourceMappingURL=signatureHeaders.d.ts.map
