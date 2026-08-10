import { describe, expect, test } from "bun:test"
import { parseStorageMode } from "./storage-header"

describe("playground storage selection", () => {
  test("ignores the unsigned debug header by default", () => {
    expect(
      parseStorageMode(
        new Headers({ "x-erc8128-storage": "redis" }),
        "postgres"
      )
    ).toBe("postgres")
  })

  test("allows an explicit non-production override", () => {
    expect(
      parseStorageMode(
        new Headers({ "x-erc8128-storage": "redis" }),
        "postgres",
        true
      )
    ).toBe("redis")
  })
})
