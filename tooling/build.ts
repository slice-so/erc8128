/// <reference types="bun-types" />
import { existsSync, readdirSync, rmSync } from "node:fs"
import { dirname, join, relative, resolve, sep } from "node:path"

export interface DeclarationBundleOptions {
  compilerOptions?: {
    baseUrl?: string
    paths?: Record<string, string[]>
  }
  external: string[]
  inputs: Record<string, string>
  outdir: string
  project: string
}

interface BuildConfig {
  clientEntrypoints?: string[]
  entrypoints?: string[]
  external?: string[]
  dtsProject?: string
  emitTypes?: boolean
  bundleDeclarations?: (options: DeclarationBundleOptions) => Promise<void>
  declarationBundleCompilerOptions?: {
    baseUrl?: string
    paths?: Record<string, string[]>
  }
  minify?: boolean
  sourcemap?: "none" | "inline" | "external"
  target?: "node" | "browser"
  outdir?: string
  root?: string
  splitting?: boolean
  watch?: boolean
}

const isOutsideDirectory = (path: string) =>
  path === ".." || path.startsWith(`..${sep}`)

const getInferredEntrypointRoot = (entrypoints: string[]) => {
  const firstEntrypoint = entrypoints[0]
  if (firstEntrypoint === undefined) {
    throw new Error("At least one package entrypoint is required.")
  }
  let commonDirectory = dirname(resolve(firstEntrypoint))
  for (const entrypoint of entrypoints.slice(1)) {
    const entrypointDirectory = dirname(resolve(entrypoint))
    while (isOutsideDirectory(relative(commonDirectory, entrypointDirectory))) {
      const parentDirectory = dirname(commonDirectory)
      if (parentDirectory === commonDirectory) {
        throw new Error("Package entrypoints must share a common root.")
      }
      commonDirectory = parentDirectory
    }
  }
  return commonDirectory
}

const removeFilesWithSuffix = (dir: string, suffix: string) => {
  if (!existsSync(dir)) return

  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const entryPath = join(dir, entry.name)

    if (entry.isDirectory()) {
      removeFilesWithSuffix(entryPath, suffix)
      continue
    }

    if (entry.name.endsWith(suffix)) {
      rmSync(entryPath)
    }
  }
}

export async function buildPackage({
  clientEntrypoints = [],
  entrypoints = ["./src/index.ts"],
  external = [],
  dtsProject,
  emitTypes = process.env.EMIT_TYPES !== "false",
  bundleDeclarations,
  declarationBundleCompilerOptions,
  minify = true,
  root,
  sourcemap = "external",
  splitting = false,
  target = "browser",
  outdir = "./dist/esm"
}: BuildConfig = {}) {
  rmSync(outdir, { force: true, recursive: true })
  if (entrypoints.length === 0) {
    throw new Error("At least one package entrypoint is required.")
  }
  const outputRoot = resolve(root ?? getInferredEntrypointRoot(entrypoints))
  const clientEntrypointSet = new Set(clientEntrypoints)
  if (
    clientEntrypoints.some(
      (clientEntrypoint) => !entrypoints.includes(clientEntrypoint)
    )
  ) {
    throw new Error("Client entrypoints must also be package entrypoints.")
  }
  const result = await Bun.build({
    define: { "process.env.NODE_ENV": JSON.stringify("production") },
    entrypoints,
    outdir,
    external,
    format: "esm",
    jsx: { development: false, runtime: "automatic" },
    minify,
    root,
    sourcemap,
    splitting,
    target
  })
  if (!result.success) {
    throw new AggregateError(result.logs, "Build failed")
  }
  for (const clientEntrypoint of clientEntrypointSet) {
    const relativeOutputPath = relative(outputRoot, resolve(clientEntrypoint))
    if (isOutsideDirectory(relativeOutputPath)) {
      throw new Error("Client entrypoints must be inside the package root.")
    }
    const outputPath = join(
      outdir,
      relativeOutputPath.replace(/\.[^.]+$/, ".js")
    )
    const contents = await Bun.file(outputPath).text()
    await Bun.write(outputPath, `"use client";\n${contents}`)
  }

  console.log("Build successful in ", outdir)

  if (sourcemap === "none") {
    removeFilesWithSuffix(outdir, ".map")
  }

  if (emitTypes) {
    const project =
      dtsProject ??
      (existsSync("tsconfig.build.json")
        ? "tsconfig.build.json"
        : "tsconfig.json")
    const tsc = Bun.spawn(
      [
        "bunx",
        "tsc",
        "-p",
        project,
        "--emitDeclarationOnly",
        "--declaration",
        "--noEmit",
        "false",
        "--declarationMap",
        "false"
      ],
      {
        stdout: "inherit",
        stderr: "inherit"
      }
    )
    const exitCode = await tsc.exited

    if (exitCode !== 0) {
      throw new Error(`Declaration build failed with exit code ${exitCode}`)
    }

    console.log("Types emitted from ", project)

    if (bundleDeclarations !== undefined) {
      const declarationInputs = Object.fromEntries(
        entrypoints.map((entrypoint) => {
          const relativeOutputPath = relative(outputRoot, resolve(entrypoint))
          if (isOutsideDirectory(relativeOutputPath)) {
            throw new Error(
              "Package entrypoints must be inside the package root."
            )
          }
          const declarationName = relativeOutputPath.replace(/\.[^.]+$/, "")
          return [declarationName, join(outdir, `${declarationName}.d.ts`)]
        })
      )
      await bundleDeclarations({
        compilerOptions: declarationBundleCompilerOptions,
        external,
        inputs: declarationInputs,
        outdir,
        project
      })
    }
  }

  return result
}
