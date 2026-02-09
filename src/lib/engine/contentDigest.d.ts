import { type ContentDigestMode } from "../types.js"
/**
 * Sets or validates the Content-Digest header on the request.
 *
 * @param mode - How to handle the Content-Digest header:
 *   - "auto": Use existing header if present, otherwise compute from body (default)
 *   - "recompute": Always recompute and overwrite existing header
 *   - "require": Require header to exist, throw if missing (does not compute)
 *   - "off": Disabled (throws if content-digest is in components)
 */
export declare function setContentDigestHeader(
  request: Request,
  mode: ContentDigestMode
): Promise<Request>
export declare function verifyContentDigest(request: Request): Promise<boolean>
export declare function parseContentDigest(v: string): {
  alg: string
  b64: string
} | null
//# sourceMappingURL=contentDigest.d.ts.map
