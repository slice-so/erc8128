/**
 * Minimal better-auth plugin that registers a /verify endpoint for the playground.
 *
 * The erc8128 plugin's middleware intercepts this endpoint (it's NOT in the
 * plugin's own pluginPaths skiplist). After verification succeeds, the
 * middleware falls through and this handler returns parsed metadata.
 * If verification fails, the middleware short-circuits with 401 before
 * this handler ever executes.
 *
 * parseSignatureInput is a workaround: the erc8128 middleware does not
 * expose its verification result to downstream handlers. If the middleware
 * is updated to pass results via context, this re-parsing can be removed.
 */

import { createAuthEndpoint } from "@slicekit/better-auth/api"
import { parseKeyId } from "@slicekit/erc8128"

function parseSignatureInput(sigInput: string) {
  const keyidMatch = sigInput.match(/keyid="([^"]+)"/)
  const keyid = keyidMatch?.[1] || ""
  const keyParts = parseKeyId(keyid)
  const address = keyParts?.address || ""
  const chainId = keyParts?.chainId || 1

  const componentsMatch = sigInput.match(/\(([^)]*)\)/)
  const components = componentsMatch
    ? (componentsMatch[1].match(/"([^"]+)"/g) || []).map((s) =>
        s.replace(/"/g, "")
      )
    : []

  const created = parseInt(sigInput.match(/;created=(\d+)/)?.[1] || "0", 10)
  const expires = parseInt(sigInput.match(/;expires=(\d+)/)?.[1] || "0", 10)

  return { address, chainId, keyid, components, created, expires }
}

export function createPlaygroundPlugin() {
  return {
    id: "playground",
    endpoints: {
      playgroundVerify: createAuthEndpoint(
        "/verify",
        {
          method: ["GET", "POST", "PUT", "DELETE"],
          requireRequest: true
        },
        async (ctx) => {
          const req = ctx.request as Request
          const sigInput = req.headers.get("signature-input") || ""
          const meta = parseSignatureInput(sigInput)

          const isDelete = req.method.toUpperCase() === "DELETE"
          const hasMethod = meta.components.includes("@method")
          const hasPath =
            meta.components.includes("@path") ||
            meta.components.includes("@target-uri")

          return ctx.json({
            ok: true,
            address: meta.address,
            chainId: meta.chainId,
            label: "eth",
            components: meta.components,
            binding: hasMethod && hasPath ? "request-bound" : "class-bound",
            replayable: !isDelete,
            params: {
              created: meta.created,
              expires: meta.expires,
              keyid: meta.keyid.toLowerCase()
            }
          })
        }
      )
    }
  }
}
