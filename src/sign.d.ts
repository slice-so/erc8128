import { type EthHttpSigner, type SignOptions } from "./lib/types.js"
/**
 *   Minimal ERC-8128 signing
 * - Fetch-first: works in browsers, workers, Node 18+.
 * - Minimal RFC 9421 engine: message to sign is an ERFC9421 compliant signature base.
 * - Minimal Structured Fields serialization: enough to serialize Signature-Input + Signature for one label.
 *
 *   IMPORTANT:
 * - This is "signing side" only. Verification is not included here.
 * - For Request-Bound with body: we compute Content-Digest using SHA-256 and include it when required.
 * - SHA-256 requires WebCrypto (crypto.subtle) or Node 'node:crypto'. The library will throw CRYPTO_UNAVAILABLE if neither is available.
 */
/**
 * Sign a fetch Request (or RequestInfo+RequestInit) and return a NEW Request with:
 * - Signature-Input
 * - Signature
 * - Content-Digest (if required)
 */
export declare function signRequest(
  input: RequestInfo,
  signer: EthHttpSigner,
  opts?: SignOptions
): Promise<Request>
export declare function signRequest(
  input: RequestInfo,
  init: RequestInit | undefined,
  signer: EthHttpSigner,
  opts?: SignOptions
): Promise<Request>
export declare function signedFetch(
  input: RequestInfo,
  signer: EthHttpSigner,
  opts?: SignOptions & {
    fetch?: typeof fetch
  }
): Promise<Response>
export declare function signedFetch(
  input: RequestInfo,
  init: RequestInit | undefined,
  signer: EthHttpSigner,
  opts?: SignOptions & {
    fetch?: typeof fetch
  }
): Promise<Response>
//# sourceMappingURL=sign.d.ts.map
