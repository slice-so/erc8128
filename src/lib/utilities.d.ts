import type { EthHttpSigner, Hex } from "./types.js"
export declare function toRequest(
  input: RequestInfo,
  init?: RequestInit
): Request
export declare function isEthHttpSigner(value: unknown): value is EthHttpSigner
export declare function sanitizeUrl(url: string): URL
export declare function unixNow(): number
export declare function utf8Encode(s: string): Uint8Array
export declare function randomBytes(n: number): Uint8Array
export declare function readBodyBytes(request: Request): Promise<Uint8Array>
export declare function sha256(bytes: Uint8Array): Promise<Uint8Array>
export declare function base64Encode(bytes: Uint8Array): string
export declare function base64Decode(b64: string): Uint8Array | null
export declare function base64UrlEncode(bytes: Uint8Array): string
export declare function hexToBytes(hex: Hex): Uint8Array
export declare function bytesToHex(bytes: Uint8Array): Hex
//# sourceMappingURL=utilities.d.ts.map
