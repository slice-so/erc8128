export type ClassBoundPolicy = string[]

export function normalizeComponentsList(components?: string[]): string[] {
  if (!components) return []
  const out: string[] = []
  const seen = new Set<string>()
  for (const raw of components) {
    const c = raw.trim()
    if (!c || seen.has(c)) continue
    seen.add(c)
    out.push(c)
  }
  return out
}

export function normalizeClassBoundPolicies(
  policies?: string[] | string[][]
): ClassBoundPolicy[] {
  if (!policies || policies.length === 0) return []
  if (typeof policies[0] === "string") {
    return [normalizeComponentsList(policies as string[])]
  }
  return (policies as string[][]).map((policy) =>
    normalizeComponentsList(policy)
  )
}

export function ensureAuthority(policy: ClassBoundPolicy): ClassBoundPolicy {
  if (policy.includes("@authority")) return policy
  return ["@authority", ...policy]
}
