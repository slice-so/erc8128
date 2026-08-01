import { describe, expect, test } from "bun:test"
import { privateKeyToAccount } from "viem/accounts"
import { createUniversalAccountVerifier } from "./universalAccountVerification"
import { bytesToHex } from "./utilities"

const account = privateKeyToAccount(`0x${"11".repeat(32)}`)
const message = new TextEncoder().encode("universal verification")

describe("universal account verification", () => {
  test("uses strict local recovery only for a code-free EOA", async () => {
    const signature = await account.signMessage({ message: { raw: message } })
    let smartChecks = 0
    const verify = createUniversalAccountVerifier({
      getCode: async () => "0x" as const,
      verifySmartAccount: async () => {
        smartChecks += 1
        return true
      }
    })

    expect(
      await verify({
        address: account.address,
        chainId: 1,
        message: { raw: bytesToHex(message) },
        signature
      })
    ).toBe(true)
    expect(smartChecks).toBe(0)
  })

  test("routes ERC-6492 and code-bearing accounts through smart verification", async () => {
    let codeReads = 0
    let smartChecks = 0
    const accountTypes: string[] = []
    const verify = createUniversalAccountVerifier({
      getCode: async () => {
        codeReads += 1
        return "0xef0100" as const
      },
      verifySmartAccount: async ({ accountType, digest }) => {
        smartChecks += 1
        accountTypes.push(accountType)
        expect(digest).toMatch(/^0x[0-9a-f]{64}$/)
        return true
      }
    })
    const input = {
      address: account.address,
      chainId: 1,
      message: { raw: bytesToHex(message) },
      signature: `0x${"22".repeat(65)}` as const
    }

    expect(await verify(input)).toBe(true)
    expect(codeReads).toBe(1)
    expect(smartChecks).toBe(1)

    expect(
      await verify({
        ...input,
        signature:
          `0x${"22".repeat(65)}6492649264926492649264926492649264926492649264926492649264926492` as const
      })
    ).toBe(true)
    expect(codeReads).toBe(1)
    expect(smartChecks).toBe(2)
    expect(accountTypes).toEqual(["deployed", "counterfactual"])
  })

  test("never falls back to ECDSA recovery for a code-bearing account", async () => {
    const signature = await account.signMessage({ message: { raw: message } })
    const verify = createUniversalAccountVerifier({
      getCode: async () => "0xef0100" as const,
      verifySmartAccount: async () => false
    })

    expect(
      await verify({
        address: account.address,
        chainId: 1,
        message: { raw: bytesToHex(message) },
        signature
      })
    ).toBe(false)
  })

  test("reports code and smart-account RPC failures as unavailable", async () => {
    const input = {
      address: account.address,
      chainId: 1,
      message: { raw: bytesToHex(message) },
      signature: `0x${"22".repeat(65)}` as const
    }
    expect(
      await createUniversalAccountVerifier({
        getCode: async () => {
          throw new Error("offline")
        },
        verifySmartAccount: async () => true
      })(input)
    ).toBe("unavailable")
    expect(
      await createUniversalAccountVerifier({
        getCode: async () => "0x01" as const,
        verifySmartAccount: async () => {
          throw new Error("offline")
        }
      })(input)
    ).toBe("unavailable")
  })
})
