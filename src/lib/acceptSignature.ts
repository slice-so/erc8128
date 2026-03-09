import {
  assertLabel,
  parseInnerListWithBareParams,
  splitTopLevelCommas
} from "./engine/createSignatureInput"
import { quoteSfString } from "./engine/serializations"
import { requiredRequestBoundComponents } from "./policies/isRequestBound"
import type { BindingMode, ReplayMode } from "./types"
import { Erc8128Error } from "./types"
import { sanitizeUrl } from "./utilities"

export type AcceptSignatureRequestShape =
  | Request
  | {
      hasQuery: boolean
      hasBody: boolean
    }

export type AcceptSignatureSignOptions = {
  binding: BindingMode
  replay: ReplayMode
  components: string[]
}

export type ParsedAcceptSignatureMember = {
  label: string
  components: string[]
  requiredParams: string[]
  acceptSignatureValue: string
  signOptions?: AcceptSignatureSignOptions
}

export type SelectAcceptSignatureRetryOptionsArgs = {
  members: Pick<ParsedAcceptSignatureMember, "components" | "requiredParams">[]
  requestShape: AcceptSignatureRequestShape
  attemptedOptions?: Array<Partial<AcceptSignatureSignOptions> | undefined>
}

function serializeAcceptSignatureValue(
  components: string[],
  requireNonce: boolean
) {
  const items = components.map((c) => quoteSfString(c)).join(" ")
  let out = `(${items})`
  out += `;keyid;created;expires`
  if (requireNonce) out += `;nonce`
  return out
}

export function buildAcceptSignatureHeader(args: {
  requestBoundRequired: string[]
  classBoundPolicies: string[][]
  allowReplayable: boolean
}): string {
  const { requestBoundRequired, classBoundPolicies, allowReplayable } = args
  const entries: string[] = []
  const seen = new Set<string>()
  let index = 1

  const addEntry = (components: string[], requireNonce: boolean) => {
    const key = `${components.join("\u0000")}\u0000${requireNonce ? "nonce" : "replayable"}`
    if (seen.has(key)) return
    seen.add(key)
    const value = serializeAcceptSignatureValue(components, requireNonce)
    entries.push(`sig${index}=${value}`)
    index++
  }

  const addPolicyEntries = (components: string[]) => {
    addEntry(components, true)
    if (allowReplayable) addEntry(components, false)
  }

  addPolicyEntries(requestBoundRequired)
  for (const policy of classBoundPolicies) addPolicyEntries(policy)

  return entries.join(", ")
}

export function parseAcceptSignatureHeader(
  headerValue: string,
  requestShape?: AcceptSignatureRequestShape
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
    const requiredParams = Array.from(new Set(parsed.bareParams))

    if (
      !requiredParams.includes("keyid") ||
      !requiredParams.includes("created") ||
      !requiredParams.includes("expires")
    ) {
      throw new Erc8128Error(
        "PARSE_ERROR",
        "Missing required keyid/created/expires params in Accept-Signature."
      )
    }

    out.push({
      label,
      components: parsed.items,
      requiredParams,
      acceptSignatureValue,
      ...(resolvedRequestShape
        ? {
            signOptions: acceptSignatureMemberToSignOptions(
              {
                components: parsed.items,
                requiredParams
              },
              resolvedRequestShape
            )
          }
        : {})
    })
  }

  return out
}

export function acceptSignatureMemberToSignOptions(
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
      (component) => !requestBoundComponents.includes(component)
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
  const normalizedComponents: string[] = []

  for (const raw of options?.components ?? []) {
    const component = raw.trim()
    if (!component) continue
    if (binding === "class-bound" && component === "@authority") continue
    if (seen.has(component)) continue
    seen.add(component)
    normalizedComponents.push(component)
  }

  normalizedComponents.sort()

  return {
    binding,
    replay,
    components: normalizedComponents
  }
}

export function selectAcceptSignatureRetryOptions(
  args: SelectAcceptSignatureRetryOptionsArgs
): AcceptSignatureSignOptions | null {
  const { members, requestShape, attemptedOptions = [] } = args
  const attempted = new Set(
    attemptedOptions.map((options) =>
      serializeNormalizedSignOptions(
        normalizeAcceptSignatureSignOptions(options)
      )
    )
  )

  for (const member of members) {
    const candidate = acceptSignatureMemberToSignOptions(member, requestShape)
    const key = serializeNormalizedSignOptions(candidate)
    if (!attempted.has(key)) return candidate
  }

  return null
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
  required: string[],
  components: string[]
): boolean {
  const available = new Set(components)
  for (const component of required) {
    if (!available.has(component)) return false
  }
  return true
}

function serializeNormalizedSignOptions(
  options: AcceptSignatureSignOptions
): string {
  return `${options.binding}\u0000${options.replay}\u0000${options.components.join("\u0000")}`
}
