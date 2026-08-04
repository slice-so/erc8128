import { describe, expect, test } from "bun:test"
import {
  formatErc8128ProblemDetails,
  parseErc8128ProblemDetails
} from "./problemDetails"

describe("ERC-8128 problem details", () => {
  test("round trips authentication failures", () => {
    const problem = formatErc8128ProblemDetails({
      detail: "The audience was not accepted.",
      ok: false,
      reason: "audience_mismatch"
    })
    expect(problem.status).toBe(401)
    expect(parseErc8128ProblemDetails(JSON.stringify(problem))).toEqual(problem)
  })

  test("maps unavailable verification to a retryable status", () => {
    expect(
      formatErc8128ProblemDetails({
        ok: false,
        reason: "revocation_unavailable"
      }).status
    ).toBe(503)
  })

  test("rejects unknown problem reasons", () => {
    expect(() =>
      parseErc8128ProblemDetails(
        JSON.stringify({
          reason: "made_up",
          status: 401,
          title: "Invalid",
          type: "about:blank"
        })
      )
    ).toThrow()
  })
})
