import { describe, expect, test } from "bun:test"
import {
  includesAllComponents,
  isRequestBoundForThisRequest
} from "./isRequestBound"

const identifiers = (names: readonly string[]) =>
  names.map((name) => ({ name }))
const includes = (required: readonly string[], components: readonly string[]) =>
  includesAllComponents([...required], identifiers(components))
const isBound = (
  components: readonly string[],
  shape: { hasQuery: boolean; hasBody: boolean; hasContentType?: boolean }
) => isRequestBoundForThisRequest(identifiers(components), shape)

describe("includesAllComponents", () => {
  test("returns true when required is empty", () => {
    expect(includes([], ["a", "b"])).toBe(true)
  })

  test("returns true when required equals components", () => {
    expect(includes(["a", "b"], ["a", "b"])).toBe(true)
  })

  test("ignores order", () => {
    expect(includes(["b", "a"], ["a", "b"])).toBe(true)
  })

  test("returns false when required has elements not in components", () => {
    expect(includes(["x"], ["a", "b"])).toBe(false)
  })

  test("returns true when both are empty", () => {
    expect(includes([], [])).toBe(true)
  })

  test("returns false when components are empty but required is not", () => {
    expect(includes(["a"], [])).toBe(false)
  })
})

describe("isRequestBoundForThisRequest", () => {
  test("minimal GET requires the full received-request component floor", () => {
    const components = ["@scheme", "@authority", "@method", "@path", "@query"]
    expect(
      isBound(components, {
        hasQuery: false,
        hasBody: false
      })
    ).toBe(true)
  })

  test("GET with query requires @query", () => {
    expect(
      isBound(["@scheme", "@authority", "@method", "@path"], {
        hasQuery: true,
        hasBody: false
      })
    ).toBe(false)

    expect(
      isBound(["@scheme", "@authority", "@method", "@path", "@query"], {
        hasQuery: true,
        hasBody: false
      })
    ).toBe(true)
  })

  test("POST with body requires content-digest", () => {
    expect(
      isBound(["@scheme", "@authority", "@method", "@path", "@query"], {
        hasQuery: false,
        hasBody: true
      })
    ).toBe(false)

    expect(
      isBound(
        [
          "@scheme",
          "@authority",
          "@method",
          "@path",
          "@query",
          "content-digest"
        ],
        { hasQuery: false, hasBody: true }
      )
    ).toBe(true)
  })

  test("POST with query and body requires both @query and content-digest", () => {
    expect(
      isBound(
        [
          "@scheme",
          "@authority",
          "@method",
          "@path",
          "@query",
          "content-digest"
        ],
        { hasQuery: true, hasBody: true }
      )
    ).toBe(true)

    expect(
      isBound(["@scheme", "@authority", "@method", "@path", "content-digest"], {
        hasQuery: true,
        hasBody: true
      })
    ).toBe(false)
  })

  test("allows extra components beyond the required set", () => {
    expect(
      isBound(
        [
          "@scheme",
          "@authority",
          "@method",
          "@path",
          "@query",
          "x-custom",
          "content-type"
        ],
        { hasQuery: false, hasBody: false }
      )
    ).toBe(true)
  })

  test("fails when @authority is missing", () => {
    expect(
      isBound(["@scheme", "@method", "@path", "@query"], {
        hasQuery: false,
        hasBody: false
      })
    ).toBe(false)
  })

  test("fails when @method is missing", () => {
    expect(
      isBound(["@scheme", "@authority", "@path", "@query"], {
        hasQuery: false,
        hasBody: false
      })
    ).toBe(false)
  })

  test("fails when @path is missing", () => {
    expect(
      isBound(["@scheme", "@authority", "@method", "@query"], {
        hasQuery: false,
        hasBody: false
      })
    ).toBe(false)
  })

  test("ignores component order", () => {
    expect(
      isBound(["@query", "@path", "@method", "@authority", "@scheme"], {
        hasQuery: false,
        hasBody: false
      })
    ).toBe(true)
  })
})
