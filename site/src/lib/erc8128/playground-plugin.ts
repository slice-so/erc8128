/**
 * Minimal better-auth plugin that registers a /verify endpoint for the playground.
 *
 * The erc8128 plugin's middleware intercepts this endpoint (it's NOT in the
 * plugin's own pluginPaths skiplist). After verification succeeds, the
 * middleware falls through and this handler returns parsed metadata.
 * If verification fails, the middleware short-circuits with 401 before
 * this handler ever executes.
 *
 * The middleware does not expose its verification result downstream, so the
 * handler derives display metadata from the already-verified signature
 * headers on the request.
 */

import { createAuthEndpoint } from "@slicekit/better-auth/api"
import { parsePlaygroundSignature } from "./playground-signature"

export function createPlaygroundPlugin() {
  return {
    id: "playground",
    endpoints: {
      playgroundVerify: createAuthEndpoint(
        "/verify",
        {
          method: ["GET", "POST", "PUT", "PATCH", "DELETE"],
          requireRequest: true,
          cloneRequest: true
        },
        async (ctx) => {
          const req = ctx.request as Request
          const meta = await parsePlaygroundSignature(req)

          return ctx.json({
            ok: true,
            address: meta?.address ?? "",
            chainId: meta?.chainId ?? 1,
            label: meta?.label ?? "eth",
            components: meta?.components ?? [],
            binding: meta?.binding ?? "class-bound",
            replayable: meta?.replayable ?? true,
            params: meta?.params ?? { created: 0, expires: 0, keyid: "" }
          })
        }
      )
    }
  }
}
