/// <reference types="bun-types" />
import dts, { type Options } from "bun-plugin-dts"

interface BuildConfig {
  entrypoint?: string
  external?: string[]
  dtsConfig?: Options
  emitTypes?: boolean
  minify?: boolean
  sourcemap?: "none" | "inline" | "external"
  target?: "node" | "browser"
  outdir?: string
  watch?: boolean
}

export async function buildPackage({
  entrypoint = "./src/index.ts",
  external = [],
  dtsConfig,
  emitTypes = process.env.EMIT_TYPES !== "false",
  minify = true,
  sourcemap = "external",
  target = "browser",
  outdir = "./dist/esm"
}: BuildConfig = {}) {
  const result = await Bun.build({
    entrypoints: [entrypoint],
    outdir,
    external,
    format: "esm",
    minify,
    sourcemap,
    target,
    plugins: emitTypes ? [dts(dtsConfig)] : []
  })

  if (!result.success) {
    throw new AggregateError(result.logs, "Build failed")
  }

  console.log("Build successful in ", outdir)

  return result
}
