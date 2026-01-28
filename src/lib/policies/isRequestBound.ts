export function isRequestBoundForThisRequest(
  components: string[],
  reqShape: { hasQuery: boolean; hasBody: boolean }
): boolean {
  // Must include @authority, @method, @path
  const needed = ["@authority", "@method", "@path"]
  // If query present, must include @query
  if (reqShape.hasQuery) needed.push("@query")
  // If body present, must include content-digest
  if (reqShape.hasBody) needed.push("content-digest")

  // Must appear as an ordered subsequence (allows extra covered components too)
  return isOrderedSubsequence(needed, components)
}

export function isOrderedSubsequence(need: string[], have: string[]): boolean {
  let j = 0
  for (let i = 0; i < have.length && j < need.length; i++) {
    if (have[i] === need[j]) j++
  }
  return j === need.length
}
