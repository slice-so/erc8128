import type { BindingMode, ContentDigestMode, ReplayMode } from "../types"

export const bindingModeValues = [
  "request-bound",
  "class-bound"
] as const satisfies readonly BindingMode[]

export const replayModeValues = [
  "non-replayable",
  "replayable"
] as const satisfies readonly ReplayMode[]

export const contentDigestModeValues = [
  "auto",
  "recompute",
  "require",
  "off"
] as const satisfies readonly ContentDigestMode[]

const bindingModes = new Set<string>(bindingModeValues)
const replayModes = new Set<string>(replayModeValues)
const contentDigestModes = new Set<string>(contentDigestModeValues)

export const isBindingMode = (value: string): value is BindingMode =>
  bindingModes.has(value)

export const isReplayMode = (value: string): value is ReplayMode =>
  replayModes.has(value)

export const isContentDigestMode = (
  value: string
): value is ContentDigestMode => contentDigestModes.has(value)

/**
 * RFC 9421 derived components or canonical lower-case HTTP field names.
 * Parameters and structured-field selectors are intentionally outside v1.
 */
export const isHttpFieldName = (value: string) =>
  /^[a-z0-9][a-z0-9!#$%&'*+.^_`|~-]*$/.test(value)

export const isCoveredComponent = (value: string) =>
  /^@[a-z][a-z0-9_-]*$/.test(value) || isHttpFieldName(value)
