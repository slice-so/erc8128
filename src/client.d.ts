import type { EthHttpSigner, SignOptions } from "./lib/types.js"
export type ClientOptions = SignOptions & {
  fetch?: typeof fetch
}
export type Client = {
  signRequest: {
    (input: RequestInfo, opts?: SignOptions): Promise<Request>
    (
      input: RequestInfo,
      init: RequestInit | undefined,
      opts?: SignOptions
    ): Promise<Request>
  }
  signedFetch: {
    (input: RequestInfo, opts?: ClientOptions): Promise<Response>
    (
      input: RequestInfo,
      init: RequestInit | undefined,
      opts?: ClientOptions
    ): Promise<Response>
  }
  fetch: {
    (input: RequestInfo, opts?: ClientOptions): Promise<Response>
    (
      input: RequestInfo,
      init: RequestInit | undefined,
      opts?: ClientOptions
    ): Promise<Response>
  }
}
export declare function createSignerClient(
  signer: EthHttpSigner,
  defaults?: ClientOptions
): Client
//# sourceMappingURL=client.d.ts.map
