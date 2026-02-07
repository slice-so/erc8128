export function isRequestBoundForThisRequest(
  components: string[],
  reqShape: { hasQuery: boolean; hasBody: boolean },
  extraComponents?: string[]
): boolean {
  const needed = requiredRequestBoundComponents(reqShape, extraComponents)
  return includesAllComponents(needed, components)
}

export function requiredRequestBoundComponents(
  reqShape: { hasQuery: boolean; hasBody: boolean },
  extraComponents?: string[]
): string[] {
  // Must include @authority, @method, @path
  const needed = ["@authority", "@method", "@path"]
  // If query present, must include @query
  if (reqShape.hasQuery) needed.push("@query")
  // If body present, must include content-digest
  if (reqShape.hasBody) needed.push("content-digest")

  if (extraComponents) {
    for (const raw of extraComponents) {
      const c = raw.trim()
      if (!c) continue
      if (!needed.includes(c)) needed.push(c)
    }
  }

  return needed
}

export function includesAllComponents(
  required: string[],
  components: string[]
): boolean {
  const have = new Set(components)
  for (const req of required) {
    if (!have.has(req)) return false
  }
  return true
}
