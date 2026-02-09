import { type BindingMode, type SignatureParams } from "../types.js"
export declare function serializeSignatureParamsInnerList(
  components: string[],
  params: SignatureParams
): string
/**
 * Validation helper kept separate from formatting so other call-sites can reuse it.
 * (Still throws the same error codes/messages as before.)
 */
export declare function assertSignatureParamsForSerialization(
  params: SignatureParams
): void
export declare function serializeSignatureInputHeader(
  label: string,
  signatureParamsValue: string
): string
export declare function serializeSignatureHeader(
  label: string,
  signatureB64: string
): string
export declare function appendDictionaryMember(
  existing: string | null,
  member: string
): string
export declare function quoteSfString(value: string): string
export declare function normalizeComponents(components: string[]): string[]
export declare function defaultComponents(args: {
  binding: BindingMode
  hasQuery: boolean
  hasBody: boolean
}): string[]
export declare function resolveComponents(args: {
  binding: BindingMode
  hasQuery: boolean
  hasBody: boolean
  providedComponents?: string[]
}): string[]
//# sourceMappingURL=serializations.d.ts.map
