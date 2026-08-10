import type {
  AcceptSignatureRequestShape,
  AcceptSignatureSignOptions,
  ParsedAcceptSignatureMember,
  ReplayMode,
  SelectAcceptSignatureRetryOptionsArgs
} from "../types"
import { Erc8128Error } from "./Erc8128Error"
import {
  componentIdentifierEquals,
  normalizeComponentIdentifiers,
  serializeComponentIdentifier
} from "./engine/componentIdentifier"
import {
  assertLabel,
  parseInnerListWithBareParams,
  splitTopLevelCommas
} from "./engine/createSignatureInput"
import { requiredRequestBoundComponents } from "./policies/isRequestBound"
import { sanitizeUrl } from "./utilities"

function serializeAcceptSignatureValue(
  components: import("../types").CoveredComponent[],
  requireNonce: boolean
) {
  const items = components
    .map((component) =>
      serializeComponentIdentifier(
        typeof component === "string" ? { name: component } : component
      )
    )
    .join(" ")
  let out = `(${items})`
  out += `;keyid;created;expires;tag`
  if (requireNonce) out += `;nonce`
  return out
}

export function buildAcceptSignatureHeader(args: {
  requestBoundRequired: import("../types").CoveredComponent[]
  classBoundPolicies: import("../types").CoveredComponent[][]
  allowReplayable: boolean
}): string {
  const { requestBoundRequired, classBoundPolicies, allowReplayable } = args
  const entries: string[] = []
  const seen = new Set<string>()
  let index = 1

  const addEntry = (
    components: import("../types").CoveredComponent[],
    requireNonce: boolean
  ) => {
    const key = `${components
      .map((component) =>
        serializeComponentIdentifier(
          typeof component === "string" ? { name: component } : component
        )
      )
      .join("\u0000")}\u0000${requireNonce ? "nonce" : "replayable"}`
    if (seen.has(key)) return
    seen.add(key)
    const value = serializeAcceptSignatureValue(components, requireNonce)
    entries.push(`sig${index}=${value}`)
    index++
  }

  // Advertise one canonical signature shape per policy:
  // - request-bound uses the nonce-bearing baseline
  // - class-bound uses replayable when allowed, otherwise nonce-bearing
  addEntry(requestBoundRequired, true)
  for (const policy of classBoundPolicies) addEntry(policy, !allowReplayable)

  return entries.join(", ")
}

export function parseAcceptSignatureHeader(
  headerValue: string,
  requestShape?: AcceptSignatureRequestShape,
  minimumOptions?: Partial<AcceptSignatureSignOptions>
): ParsedAcceptSignatureMember[] {
  const out: ParsedAcceptSignatureMember[] = []
  const resolvedRequestShape = requestShape
    ? toRequestShape(requestShape)
    : undefined

  for (const raw of splitTopLevelCommas(headerValue)) {
    const member = raw.trim()
    if (!member) continue

    const eq = member.indexOf("=")
    if (eq <= 0)
      throw new Erc8128Error(
        "PARSE_ERROR",
        "Invalid Accept-Signature member (missing '=')."
      )

    const label = member.slice(0, eq).trim()
    assertLabel(label)

    const acceptSignatureValue = member.slice(eq + 1).trim()
    const parsed = parseInnerListWithBareParams(acceptSignatureValue)
    const components = parsed.items
    const requiredParams = Array.from(new Set(parsed.bareParams))

    if (
      !requiredParams.includes("keyid") ||
      !requiredParams.includes("created") ||
      !requiredParams.includes("expires") ||
      !requiredParams.includes("tag")
    ) {
      throw new Erc8128Error(
        "PARSE_ERROR",
        "Missing required keyid/created/expires/tag params in Accept-Signature."
      )
    }

    out.push({
      label,
      components,
      requiredParams,
      acceptSignatureValue,
      ...(resolvedRequestShape
        ? {
            ...withSafeSignOptions(
              deriveAcceptSignatureSignOptions(
                { components, requiredParams },
                resolvedRequestShape
              ),
              minimumOptions
            )
          }
        : {})
    })
  }

  return out
}

export function acceptSignatureMemberToSignOptions(
  member: Pick<ParsedAcceptSignatureMember, "components" | "requiredParams">,
  requestShape: AcceptSignatureRequestShape,
  minimumOptions?: Partial<AcceptSignatureSignOptions>
): AcceptSignatureSignOptions {
  const candidate = deriveAcceptSignatureSignOptions(member, requestShape)
  if (!meetsMinimumPosture(candidate, minimumOptions)) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Accept-Signature would weaken the client's minimum signing posture."
    )
  }
  return candidate
}

function deriveAcceptSignatureSignOptions(
  member: Pick<ParsedAcceptSignatureMember, "components" | "requiredParams">,
  requestShape: AcceptSignatureRequestShape
): AcceptSignatureSignOptions {
  const shape = toRequestShape(requestShape)
  const requestBoundComponents = requiredRequestBoundComponents(shape)
  const replay: ReplayMode = member.requiredParams.includes("nonce")
    ? "non-replayable"
    : "replayable"

  if (includesAllComponents(requestBoundComponents, member.components)) {
    const extraComponents = member.components.filter(
      (component) =>
        !requestBoundComponents.some((required) =>
          componentIdentifierEquals(required, component)
        )
    )
    return normalizeAcceptSignatureSignOptions({
      binding: "request-bound",
      replay,
      components: extraComponents
    })
  }

  return normalizeAcceptSignatureSignOptions({
    binding: "class-bound",
    replay,
    components: member.components
  })
}

export function normalizeAcceptSignatureSignOptions(
  options?: Partial<AcceptSignatureSignOptions>
): AcceptSignatureSignOptions {
  const binding = options?.binding ?? "request-bound"
  const replay = options?.replay ?? "non-replayable"
  const seen = new Set<string>()
  const normalizedComponents: import("../types").ComponentIdentifier[] = []

  for (const raw of options?.components ?? []) {
    const component = normalizeComponentIdentifiers([raw])[0]
    if (!component) continue
    if (binding === "class-bound" && component.name === "@authority") continue
    const key = serializeComponentIdentifier(component)
    if (seen.has(key)) continue
    seen.add(key)
    normalizedComponents.push(component)
  }

  normalizedComponents.sort((left, right) =>
    serializeComponentIdentifier(left).localeCompare(
      serializeComponentIdentifier(right)
    )
  )

  return {
    binding,
    replay,
    components: normalizedComponents
  }
}

export function selectAcceptSignatureRetryOptions(
  args: SelectAcceptSignatureRetryOptionsArgs
): AcceptSignatureSignOptions | null {
  const { members, requestShape, attemptedOptions = [], minimumOptions } = args
  const attempted = new Set(
    attemptedOptions.map((options) =>
      serializeNormalizedSignOptions(
        normalizeAcceptSignatureSignOptions(options)
      )
    )
  )

  for (const member of members) {
    const candidate = deriveAcceptSignatureSignOptions(member, requestShape)
    if (!meetsMinimumPosture(candidate, minimumOptions)) continue
    const key = serializeNormalizedSignOptions(candidate)
    if (!attempted.has(key)) return candidate
  }

  return null
}

function withSafeSignOptions(
  candidate: AcceptSignatureSignOptions,
  minimumOptions: Partial<AcceptSignatureSignOptions> | undefined
): { signOptions?: AcceptSignatureSignOptions } {
  return meetsMinimumPosture(candidate, minimumOptions)
    ? { signOptions: candidate }
    : {}
}

function meetsMinimumPosture(
  candidate: AcceptSignatureSignOptions,
  minimumOptions: Partial<AcceptSignatureSignOptions> | undefined
): boolean {
  const minimum = normalizeAcceptSignatureSignOptions(minimumOptions)
  if (
    minimum.binding === "request-bound" &&
    candidate.binding !== "request-bound"
  ) {
    return false
  }
  if (
    minimum.replay === "non-replayable" &&
    candidate.replay !== "non-replayable"
  ) {
    return false
  }
  return includesAllComponents(minimum.components, candidate.components)
}

function toRequestShape(requestShape: AcceptSignatureRequestShape): {
  hasQuery: boolean
  hasBody: boolean
} {
  if (requestShape instanceof Request) {
    const url = sanitizeUrl(requestShape.url)
    return {
      hasQuery: url.search.length > 0,
      hasBody: requestShape.body != null
    }
  }

  return requestShape
}

function includesAllComponents(
  required: import("../types").CoveredComponent[],
  components: import("../types").CoveredComponent[]
): boolean {
  for (const component of required) {
    if (
      !components.some((candidate) =>
        componentIdentifierEquals(candidate, component)
      )
    )
      return false
  }
  return true
}

function serializeNormalizedSignOptions(
  options: AcceptSignatureSignOptions
): string {
  return `${options.binding}\u0000${options.replay}\u0000${options.components
    .map((component) =>
      serializeComponentIdentifier(
        typeof component === "string" ? { name: component } : component
      )
    )
    .join("\u0000")}`
}
