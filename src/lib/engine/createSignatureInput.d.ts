import { type SignatureParams } from "../types.js"
type ParsedSignatureInputMember = {
  label: string
  components: string[]
  params: SignatureParams
  signatureParamsValue: string
}
export declare function parseSignatureInputDictionary(
  headerValue: string
): ParsedSignatureInputMember[]
export declare function parseSignatureDictionary(
  headerValue: string
): Map<string, string>
export declare function assertLabel(label: string): void
//# sourceMappingURL=createSignatureInput.d.ts.map
