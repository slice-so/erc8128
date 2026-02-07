import { describe, expect, test } from "bun:test"
import {
  includesAllComponents,
  isRequestBoundForThisRequest
} from "./isRequestBound.js"

describe("includesAllComponents", () => {
  test("returns true when required is empty", () => {
    expect(includesAllComponents([], ["a", "b"])).toBe(true)
  })

  test("returns true when required equals components", () => {
    expect(includesAllComponents(["a", "b"], ["a", "b"])).toBe(true)
  })

  test("ignores order", () => {
    expect(includesAllComponents(["b", "a"], ["a", "b"])).toBe(true)
  })

  test("returns false when required has elements not in components", () => {
    expect(includesAllComponents(["x"], ["a", "b"])).toBe(false)
  })

  test("returns true when both are empty", () => {
    expect(includesAllComponents([], [])).toBe(true)
  })

  test("returns false when components are empty but required is not", () => {
    expect(includesAllComponents(["a"], [])).toBe(false)
  })
})

describe("isRequestBoundForThisRequest", () => {
  test("minimal GET (no query, no body) requires @authority, @method, @path", () => {
    const components = ["@authority", "@method", "@path"]
    expect(
      isRequestBoundForThisRequest(components, {
        hasQuery: false,
        hasBody: false
      })
    ).toBe(true)
  })

  test("GET with query requires @query", () => {
    expect(
      isRequestBoundForThisRequest(["@authority", "@method", "@path"], {
        hasQuery: true,
        hasBody: false
      })
    ).toBe(false)

    expect(
      isRequestBoundForThisRequest(
        ["@authority", "@method", "@path", "@query"],
        { hasQuery: true, hasBody: false }
      )
    ).toBe(true)
  })

  test("POST with body requires content-digest", () => {
    expect(
      isRequestBoundForThisRequest(["@authority", "@method", "@path"], {
        hasQuery: false,
        hasBody: true
      })
    ).toBe(false)

    expect(
      isRequestBoundForThisRequest(
        ["@authority", "@method", "@path", "content-digest"],
        { hasQuery: false, hasBody: true }
      )
    ).toBe(true)
  })

  test("POST with query and body requires both @query and content-digest", () => {
    expect(
      isRequestBoundForThisRequest(
        ["@authority", "@method", "@path", "@query", "content-digest"],
        { hasQuery: true, hasBody: true }
      )
    ).toBe(true)

    expect(
      isRequestBoundForThisRequest(
        ["@authority", "@method", "@path", "content-digest"],
        { hasQuery: true, hasBody: true }
      )
    ).toBe(false)
  })

  test("allows extra components beyond the required set", () => {
    expect(
      isRequestBoundForThisRequest(
        ["@authority", "@method", "@path", "x-custom", "content-type"],
        { hasQuery: false, hasBody: false }
      )
    ).toBe(true)
  })

  test("fails when @authority is missing", () => {
    expect(
      isRequestBoundForThisRequest(["@method", "@path"], {
        hasQuery: false,
        hasBody: false
      })
    ).toBe(false)
  })

  test("fails when @method is missing", () => {
    expect(
      isRequestBoundForThisRequest(["@authority", "@path"], {
        hasQuery: false,
        hasBody: false
      })
    ).toBe(false)
  })

  test("fails when @path is missing", () => {
    expect(
      isRequestBoundForThisRequest(["@authority", "@method"], {
        hasQuery: false,
        hasBody: false
      })
    ).toBe(false)
  })

  test("ignores component order", () => {
    expect(
      isRequestBoundForThisRequest(["@path", "@method", "@authority"], {
        hasQuery: false,
        hasBody: false
      })
    ).toBe(true)
  })
})
