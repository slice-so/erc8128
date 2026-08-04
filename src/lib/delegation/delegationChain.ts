import type {
  ComponentIdentifier,
  ParsedDelegationField,
  ResolvedDelegationChain
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import {
  hashDelegation,
  parseDelegationComponent,
  ZERO_DELEGATION_PARENT
} from "./delegationField"

export const DEFAULT_MAX_DELEGATION_CHAIN_DEPTH = 4

export function resolveDelegationChain(
  parsed: ParsedDelegationField,
  maximumDepth = DEFAULT_MAX_DELEGATION_CHAIN_DEPTH
): ResolvedDelegationChain {
  if (
    !Number.isSafeInteger(maximumDepth) ||
    maximumDepth <= 0 ||
    parsed.chain.links.length > maximumDepth
  ) {
    throw new Erc8128Error(
      "DELEGATION_CHAIN_TOO_LONG",
      "Delegation Chain exceeds the configured depth."
    )
  }
  const first = parsed.chain.links[0]
  if (first === undefined) {
    throw new Erc8128Error("PARSE_ERROR", "Delegation Chain is empty.")
  }
  if (first.grant.parent !== ZERO_DELEGATION_PARENT) discontinuous()

  let effectiveAudience = [...first.grant.aud]
  let effectiveComponents = first.grant.components.map(parseDelegationComponent)
  let effectiveMaxAge = first.grant.maxAge
  let effectiveReplayable = first.grant.allowReplayable
  let effectiveScope = [...first.grant.scope]

  for (let index = 1; index < parsed.chain.links.length; index += 1) {
    const parent = parsed.chain.links[index - 1]
    const child = parsed.chain.links[index]
    if (parent === undefined || child === undefined) discontinuous()
    if (
      child.grant.root !== parent.grant.delegate ||
      child.grant.parent !== hashDelegation(parent.grant)
    ) {
      discontinuous()
    }
    if (
      !isSubset(child.grant.aud, effectiveAudience) ||
      (child.grant.scope.length > 0 &&
        !isSubset(child.grant.scope, effectiveScope)) ||
      child.grant.created < parent.grant.created ||
      child.grant.expires > parent.grant.expires ||
      child.grant.maxAge > effectiveMaxAge
    ) {
      attenuation()
    }
    effectiveAudience = [...child.grant.aud]
    effectiveMaxAge = child.grant.maxAge
    effectiveReplayable = effectiveReplayable && child.grant.allowReplayable
    if (child.grant.scope.length > 0) effectiveScope = [...child.grant.scope]
    effectiveComponents = unionComponents(
      effectiveComponents,
      child.grant.components.map(parseDelegationComponent)
    )
  }

  return {
    ...parsed,
    effectiveAudience,
    effectiveComponents,
    effectiveMaxAge,
    effectiveReplayable,
    effectiveScope
  }
}

function isSubset(
  child: readonly string[],
  parent: readonly string[]
): boolean {
  const allowed = new Set(parent)
  return child.every((value) => allowed.has(value))
}

function unionComponents(
  left: readonly ComponentIdentifier[],
  right: readonly ComponentIdentifier[]
): ComponentIdentifier[] {
  const result = [...left]
  const serialized = new Set(left.map((component) => JSON.stringify(component)))
  for (const component of right) {
    const key = JSON.stringify(component)
    if (!serialized.has(key)) {
      result.push(component)
      serialized.add(key)
    }
  }
  return result
}

function discontinuous(): never {
  throw new Erc8128Error(
    "DELEGATION_CHAIN_DISCONTINUOUS",
    "Delegation Chain continuity is invalid."
  )
}

function attenuation(): never {
  throw new Erc8128Error(
    "DELEGATION_ATTENUATION_VIOLATION",
    "Delegation child broadens its parent authority."
  )
}
