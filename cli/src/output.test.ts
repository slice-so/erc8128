import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test"
import { existsSync, unlinkSync } from "node:fs"
import { readFile } from "node:fs/promises"
import { handleResponse, logVerbose } from "./output.js"

describe("output handling", () => {
  const testOutputFile = "/tmp/test-output.txt"

  afterEach(() => {
    // Clean up test output file if it exists
    try {
      if (existsSync(testOutputFile)) {
        unlinkSync(testOutputFile)
      }
    } catch {
      // Ignore cleanup errors
    }
  })

  describe("handleResponse", () => {
    describe("response body output", () => {
      test("outputs response body to stdout", async () => {
        const consoleSpy = spyOn(console, "log").mockImplementation(() => {})

        const response = new Response("Hello, World!")

        await handleResponse(response, {
          include: false,
          verbose: false
        })

        expect(consoleSpy).toHaveBeenCalledWith("Hello, World!")

        consoleSpy.mockRestore()
      })

      test("outputs JSON response body", async () => {
        const consoleSpy = spyOn(console, "log").mockImplementation(() => {})

        const jsonBody = JSON.stringify({ status: "ok", data: [1, 2, 3] })
        const response = new Response(jsonBody, {
          headers: { "Content-Type": "application/json" }
        })

        await handleResponse(response, {
          include: false,
          verbose: false
        })

        expect(consoleSpy).toHaveBeenCalledWith(jsonBody)

        consoleSpy.mockRestore()
      })

      test("handles empty response body", async () => {
        const consoleSpy = spyOn(console, "log").mockImplementation(() => {})

        const response = new Response("")

        await handleResponse(response, {
          include: false,
          verbose: false
        })

        expect(consoleSpy).toHaveBeenCalledWith("")

        consoleSpy.mockRestore()
      })

      test("handles binary response as text", async () => {
        const consoleSpy = spyOn(console, "log").mockImplementation(() => {})

        // Some non-ASCII bytes
        const response = new Response("Binary: \x00\x01\x02")

        await handleResponse(response, {
          include: false,
          verbose: false
        })

        expect(consoleSpy).toHaveBeenCalled()

        consoleSpy.mockRestore()
      })
    })

    describe("include headers with -i flag", () => {
      test("includes status line and headers when include=true", async () => {
        const consoleSpy = spyOn(console, "log").mockImplementation(() => {})

        const response = new Response("Body content", {
          status: 200,
          statusText: "OK",
          headers: {
            "Content-Type": "text/plain",
            "X-Custom-Header": "custom-value"
          }
        })

        await handleResponse(response, {
          include: true,
          verbose: false
        })

        const output = consoleSpy.mock.calls[0][0]
        expect(output).toContain("HTTP/200")
        expect(output).toContain("content-type: text/plain")
        expect(output).toContain("x-custom-header: custom-value")
        expect(output).toContain("Body content")

        consoleSpy.mockRestore()
      })

      test("includes status line with non-200 status", async () => {
        const consoleSpy = spyOn(console, "log").mockImplementation(() => {})

        const response = new Response("Not Found", {
          status: 404,
          statusText: "Not Found"
        })

        await handleResponse(response, {
          include: true,
          verbose: false
        })

        const output = consoleSpy.mock.calls[0][0]
        expect(output).toContain("HTTP/404 Not Found")
        expect(output).toContain("Not Found")

        consoleSpy.mockRestore()
      })

      test("separates headers from body with blank line", async () => {
        const consoleSpy = spyOn(console, "log").mockImplementation(() => {})

        const response = new Response("Body", {
          status: 200,
          statusText: "OK",
          headers: { "Content-Type": "text/plain" }
        })

        await handleResponse(response, {
          include: true,
          verbose: false
        })

        const output = consoleSpy.mock.calls[0][0]
        // Headers end, then blank line, then body
        expect(output).toContain("\n\nBody")

        consoleSpy.mockRestore()
      })

      test("does not include headers when include=false", async () => {
        const consoleSpy = spyOn(console, "log").mockImplementation(() => {})

        const response = new Response("Just the body", {
          status: 200,
          headers: { "Content-Type": "text/plain" }
        })

        await handleResponse(response, {
          include: false,
          verbose: false
        })

        const output = consoleSpy.mock.calls[0][0]
        expect(output).toBe("Just the body")
        expect(output).not.toContain("HTTP/")
        expect(output).not.toContain("content-type")

        consoleSpy.mockRestore()
      })
    })

    describe("file output with -o flag", () => {
      test("writes response to file", async () => {
        const consoleSpy = spyOn(console, "log").mockImplementation(() => {})

        const response = new Response("File content")

        await handleResponse(response, {
          include: false,
          output: testOutputFile,
          verbose: false
        })

        const fileContent = await readFile(testOutputFile, "utf-8")
        expect(fileContent).toBe("File content")

        // Should not output to console
        expect(consoleSpy).not.toHaveBeenCalled()

        consoleSpy.mockRestore()
      })

      test("writes headers and body to file when include=true", async () => {
        const response = new Response("Body in file", {
          status: 201,
          statusText: "Created",
          headers: { "X-File-Header": "file-value" }
        })

        await handleResponse(response, {
          include: true,
          output: testOutputFile,
          verbose: false
        })

        const fileContent = await readFile(testOutputFile, "utf-8")
        expect(fileContent).toContain("HTTP/201 Created")
        expect(fileContent).toContain("x-file-header: file-value")
        expect(fileContent).toContain("Body in file")
      })

      test("logs success message when verbose=true", async () => {
        const consoleErrorSpy = spyOn(console, "error").mockImplementation(
          () => {}
        )

        const response = new Response("Verbose output")

        await handleResponse(response, {
          include: false,
          output: testOutputFile,
          verbose: true
        })

        expect(consoleErrorSpy).toHaveBeenCalledWith(
          `✓ Response written to ${testOutputFile}`
        )

        consoleErrorSpy.mockRestore()
      })

      test("does not log success message when verbose=false", async () => {
        const consoleErrorSpy = spyOn(console, "error").mockImplementation(
          () => {}
        )

        const response = new Response("Silent output")

        await handleResponse(response, {
          include: false,
          output: testOutputFile,
          verbose: false
        })

        expect(consoleErrorSpy).not.toHaveBeenCalled()

        consoleErrorSpy.mockRestore()
      })

      test("overwrites existing file", async () => {
        // Write initial content
        await Bun.write(testOutputFile, "Initial content")

        const response = new Response("New content")

        await handleResponse(response, {
          include: false,
          output: testOutputFile,
          verbose: false
        })

        const fileContent = await readFile(testOutputFile, "utf-8")
        expect(fileContent).toBe("New content")
      })
    })

    describe("response with various status codes", () => {
      test("handles 500 error response", async () => {
        const consoleSpy = spyOn(console, "log").mockImplementation(() => {})

        const response = new Response("Internal Server Error", {
          status: 500,
          statusText: "Internal Server Error"
        })

        await handleResponse(response, {
          include: true,
          verbose: false
        })

        const output = consoleSpy.mock.calls[0][0]
        expect(output).toContain("HTTP/500 Internal Server Error")

        consoleSpy.mockRestore()
      })

      test("handles 301 redirect response", async () => {
        const consoleSpy = spyOn(console, "log").mockImplementation(() => {})

        const response = new Response("", {
          status: 301,
          statusText: "Moved Permanently",
          headers: { Location: "https://example.com/new-location" }
        })

        await handleResponse(response, {
          include: true,
          verbose: false
        })

        const output = consoleSpy.mock.calls[0][0]
        expect(output).toContain("HTTP/301 Moved Permanently")
        expect(output).toContain("location: https://example.com/new-location")

        consoleSpy.mockRestore()
      })
    })
  })

  describe("logVerbose", () => {
    test("logs message when verbose=true", () => {
      const consoleErrorSpy = spyOn(console, "error").mockImplementation(
        () => {}
      )

      logVerbose("Verbose message", true)

      expect(consoleErrorSpy).toHaveBeenCalledWith("Verbose message")

      consoleErrorSpy.mockRestore()
    })

    test("does not log when verbose=false", () => {
      const consoleErrorSpy = spyOn(console, "error").mockImplementation(
        () => {}
      )

      logVerbose("Silent message", false)

      expect(consoleErrorSpy).not.toHaveBeenCalled()

      consoleErrorSpy.mockRestore()
    })
  })
})
