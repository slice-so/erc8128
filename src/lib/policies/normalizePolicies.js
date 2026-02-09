export function normalizeComponentsList(components) {
  if (!components) return []
  const out = []
  const seen = new Set()
  for (const raw of components) {
    const c = raw.trim()
    if (!c || seen.has(c)) continue
    seen.add(c)
    out.push(c)
  }
  return out
}
export function normalizeClassBoundPolicies(policies) {
  if (!policies || policies.length === 0) return []
  if (typeof policies[0] === "string") {
    return [normalizeComponentsList(policies)]
  }
  return policies.map((policy) => normalizeComponentsList(policy))
}
export function ensureAuthority(policy) {
  if (policy.includes("@authority")) return policy
  return ["@authority", ...policy]
}
//# sourceMappingURL=normalizePolicies.js.map
