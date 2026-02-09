export declare function isRequestBoundForThisRequest(
  components: string[],
  reqShape: {
    hasQuery: boolean
    hasBody: boolean
  },
  extraComponents?: string[]
): boolean
export declare function requiredRequestBoundComponents(
  reqShape: {
    hasQuery: boolean
    hasBody: boolean
  },
  extraComponents?: string[]
): string[]
export declare function includesAllComponents(
  required: string[],
  components: string[]
): boolean
//# sourceMappingURL=isRequestBound.d.ts.map
