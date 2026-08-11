import type { ContentDigestMode } from "../types"

const CONTENT_DIGEST_STRENGTH: Record<ContentDigestMode, number> = {
  off: 0,
  auto: 1,
  recompute: 2,
  require: 2
}

export function resolveContentDigestMode(
  requested: ContentDigestMode | undefined,
  routeMode: ContentDigestMode | undefined
): ContentDigestMode | undefined {
  const required = signingModeForRoutePolicy(routeMode)
  if (requested === undefined) return required
  if (required === undefined) return requested
  return CONTENT_DIGEST_STRENGTH[required] >= CONTENT_DIGEST_STRENGTH[requested]
    ? required
    : requested
}

function signingModeForRoutePolicy(
  mode: ContentDigestMode | undefined
): ContentDigestMode | undefined {
  if (mode === "require") return "recompute"
  if (mode === "off") return "auto"
  return mode
}
