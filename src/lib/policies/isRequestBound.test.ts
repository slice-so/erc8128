import { describe, expect, test } from "bun:test"
import {
  isOrderedSubsequence,
  isRequestBoundForThisRequest
} from "./isRequestBound.js"

describe("isOrderedSubsequence", () => {
  test("returns true when need is empty", () => {
    expect(isOrderedSubsequence([], ["a", "b"])).toBe(true)
  })

  test("returns true when need equals have", () => {
    expect(isOrderedSubsequence(["a", "b"], ["a", "b"])).toBe(true)
  })

  test("returns true when need is a strict ordered subset", () => {
    expect(isOrderedSubsequence(["a", "c"], ["a", "b", "c"])).toBe(true)
  })

  test("returns false when order is wrong", () => {
    expect(isOrderedSubsequence(["b", "a"], ["a", "b"])).toBe(false)
  })

  test("returns false when need has elements not in have", () => {
    expect(isOrderedSubsequence(["x"], ["a", "b"])).toBe(false)
  })

  test("returns true when both are empty", () => {
    expect(isOrderedSubsequence([], [])).toBe(true)
  })

  test("returns false when have is empty but need is not", () => {
    expect(isOrderedSubsequence(["a"], [])).toBe(false)
  })

  test("handles duplicates correctly", () => {
    expect(isOrderedSubsequence(["a", "a"], ["a", "b", "a"])).toBe(true)
    expect(isOrderedSubsequence(["a", "a"], ["a", "b"])).toBe(false)
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

  test("fails when components are in wrong order", () => {
    expect(
      isRequestBoundForThisRequest(["@path", "@method", "@authority"], {
        hasQuery: false,
        hasBody: false
      })
    ).toBe(false)
  })
})
