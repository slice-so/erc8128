import {
  afterEach,
  beforeEach,
  describe,
  expect,
  mock,
  spyOn,
  test
} from "bun:test"
import { createSigner, type WalletOptions } from "./wallet.js"

// Test private key (well-known test key, DO NOT USE IN PRODUCTION)
const TEST_PRIVATE_KEY =
  "0x0123456789012345678901234567890123456789012345678901234567890123"
const TEST_PRIVATE_KEY_WITHOUT_PREFIX =
  "0123456789012345678901234567890123456789012345678901234567890123"

// Expected address for the test private key
const EXPECTED_ADDRESS = "0x14791697260E4c9A71f18484C9f997B308e59325"

describe("wallet creation", () => {
  let originalEnv: string | undefined

  beforeEach(() => {
    originalEnv = process.env.ETH_PRIVATE_KEY
    delete process.env.ETH_PRIVATE_KEY
  })

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env.ETH_PRIVATE_KEY = originalEnv
    } else {
      delete process.env.ETH_PRIVATE_KEY
    }
  })

  describe("private key from --private-key flag", () => {
    test("creates signer from private key with 0x prefix", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})

      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        ledger: false,
        trezor: false,
        chainId: 1
      })

      expect(signer.address.toLowerCase()).toBe(EXPECTED_ADDRESS.toLowerCase())
      expect(signer.chainId).toBe(1)
      expect(typeof signer.signMessage).toBe("function")

      // Verify warning was logged
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("Warning: Using raw private key is insecure")
      )

      consoleSpy.mockRestore()
    })

    test("creates signer from private key without 0x prefix", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})

      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY_WITHOUT_PREFIX,
        ledger: false,
        trezor: false,
        chainId: 1
      })

      expect(signer.address.toLowerCase()).toBe(EXPECTED_ADDRESS.toLowerCase())

      consoleSpy.mockRestore()
    })

    test("uses specified chain ID", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})

      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        ledger: false,
        trezor: false,
        chainId: 137
      })

      expect(signer.chainId).toBe(137)

      consoleSpy.mockRestore()
    })

    test("signMessage produces valid signature", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})

      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        ledger: false,
        trezor: false,
        chainId: 1
      })

      const message = new TextEncoder().encode("test message")
      const signature = await signer.signMessage(message)

      expect(signature).toMatch(/^0x[0-9a-f]+$/i)
      expect(signature.length).toBe(132) // 65 bytes = 130 hex chars + '0x'

      consoleSpy.mockRestore()
    })
  })

  describe("private key from ETH_PRIVATE_KEY env var", () => {
    test("creates signer from environment variable", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})
      process.env.ETH_PRIVATE_KEY = TEST_PRIVATE_KEY

      const signer = await createSigner({
        ledger: false,
        trezor: false,
        chainId: 1
      })

      expect(signer.address.toLowerCase()).toBe(EXPECTED_ADDRESS.toLowerCase())
      expect(signer.chainId).toBe(1)

      consoleSpy.mockRestore()
    })

    test("logs warning when using env var", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})
      process.env.ETH_PRIVATE_KEY = TEST_PRIVATE_KEY

      await createSigner({
        ledger: false,
        trezor: false,
        chainId: 1
      })

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "Warning: Using raw private key from ETH_PRIVATE_KEY is insecure"
        )
      )

      consoleSpy.mockRestore()
    })

    test("--private-key takes precedence over env var", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})
      // Different key in env (this would produce a different address)
      process.env.ETH_PRIVATE_KEY =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        ledger: false,
        trezor: false,
        chainId: 1
      })

      // Should use the --private-key value
      expect(signer.address.toLowerCase()).toBe(EXPECTED_ADDRESS.toLowerCase())

      consoleSpy.mockRestore()
    })
  })

  describe("error cases", () => {
    test("throws when no wallet specified", async () => {
      await expect(
        createSigner({
          ledger: false,
          trezor: false,
          chainId: 1
        })
      ).rejects.toThrow(
        "No wallet specified. Use --private-key, --keystore, or set ETH_PRIVATE_KEY environment variable."
      )
    })

    test("throws when Ledger is specified", async () => {
      await expect(
        createSigner({
          ledger: true,
          trezor: false,
          chainId: 1
        })
      ).rejects.toThrow("Ledger support is not yet implemented")
    })

    test("throws when Trezor is specified", async () => {
      await expect(
        createSigner({
          ledger: false,
          trezor: true,
          chainId: 1
        })
      ).rejects.toThrow("Trezor support is not yet implemented")
    })

    test("throws on invalid private key", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})

      await expect(
        createSigner({
          privateKey: "not-a-valid-key",
          ledger: false,
          trezor: false,
          chainId: 1
        })
      ).rejects.toThrow()

      consoleSpy.mockRestore()
    })

    test("throws on too short private key", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})

      await expect(
        createSigner({
          privateKey: "0x1234",
          ledger: false,
          trezor: false,
          chainId: 1
        })
      ).rejects.toThrow()

      consoleSpy.mockRestore()
    })
  })

  describe("keystore handling", () => {
    test("throws when keystore file doesn't exist", async () => {
      await expect(
        createSigner({
          keystore: "/nonexistent/path/keystore.json",
          password: "password",
          ledger: false,
          trezor: false,
          chainId: 1
        })
      ).rejects.toThrow("Failed to load keystore")
    })

    // Note: Keystore decryption is not yet implemented, so we can't test successful keystore loading
    // This test documents the current behavior
    test("throws keystore decryption not implemented error for valid keystore", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})

      // Create a minimal valid keystore structure
      const tempKeystorePath = "/tmp/test-keystore.json"
      await Bun.write(
        tempKeystorePath,
        JSON.stringify({
          version: 3,
          id: "test-id",
          address: "14dc79964da2c08b23698b3d3cc7ca32193d9955",
          crypto: {}
        })
      )

      await expect(
        createSigner({
          keystore: tempKeystorePath,
          password: "password",
          ledger: false,
          trezor: false,
          chainId: 1
        })
      ).rejects.toThrow("Keystore decryption not yet implemented")

      consoleSpy.mockRestore()
    })
  })

  describe("EthHttpSigner interface", () => {
    test("signer has correct interface", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})

      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        ledger: false,
        trezor: false,
        chainId: 42161 // Arbitrum
      })

      // Check interface matches EthHttpSigner
      expect(typeof signer.address).toBe("string")
      expect(signer.address).toMatch(/^0x[0-9a-fA-F]{40}$/)
      expect(typeof signer.chainId).toBe("number")
      expect(signer.chainId).toBe(42161)
      expect(typeof signer.signMessage).toBe("function")

      consoleSpy.mockRestore()
    })

    test("signMessage accepts Uint8Array and returns hex signature", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})

      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        ledger: false,
        trezor: false,
        chainId: 1
      })

      // Test with various message types
      const messages = [
        new Uint8Array([1, 2, 3, 4]),
        new TextEncoder().encode("Hello, World!"),
        new Uint8Array(0), // empty message
        new Uint8Array(256).fill(0xff) // longer message
      ]

      for (const message of messages) {
        const signature = await signer.signMessage(message)
        expect(signature).toMatch(/^0x[0-9a-f]+$/i)
      }

      consoleSpy.mockRestore()
    })

    test("same message produces same signature (deterministic)", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})

      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        ledger: false,
        trezor: false,
        chainId: 1
      })

      const message = new TextEncoder().encode("deterministic test")
      const sig1 = await signer.signMessage(message)
      const sig2 = await signer.signMessage(message)

      expect(sig1).toBe(sig2)

      consoleSpy.mockRestore()
    })

    test("different messages produce different signatures", async () => {
      const consoleSpy = spyOn(console, "error").mockImplementation(() => {})

      const signer = await createSigner({
        privateKey: TEST_PRIVATE_KEY,
        ledger: false,
        trezor: false,
        chainId: 1
      })

      const msg1 = new TextEncoder().encode("message 1")
      const msg2 = new TextEncoder().encode("message 2")

      const sig1 = await signer.signMessage(msg1)
      const sig2 = await signer.signMessage(msg2)

      expect(sig1).not.toBe(sig2)

      consoleSpy.mockRestore()
    })
  })
})
