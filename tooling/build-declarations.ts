import { cpSync, existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { rollup } from "rollup"
import { dts } from "rollup-plugin-dts"
import type { DeclarationBundleOptions } from "./build"

const isExternalImport = (source: string, external: string[]) =>
  external.some(
    (dependency) => source === dependency || source.startsWith(`${dependency}/`)
  )

const removeDeclarationFiles = (dir: string) => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const entryPath = join(dir, entry.name)

    if (entry.isDirectory()) {
      removeDeclarationFiles(entryPath)
      continue
    }

    if (entry.name.endsWith(".d.ts")) {
      rmSync(entryPath)
    }
  }
}

export const bundleDeclarationTypes = async ({
  compilerOptions,
  external,
  inputs,
  outdir,
  project
}: DeclarationBundleOptions) => {
  for (const input of Object.values(inputs)) {
    if (!existsSync(input)) {
      throw new Error(`Declaration entrypoint not found: ${input}`)
    }
  }

  const bundleOutdir = mkdtempSync(join(tmpdir(), "slice-declarations-"))
  try {
    const bundle = await rollup({
      input: inputs,
      external: (source) => isExternalImport(source, external),
      plugins: [dts({ compilerOptions, tsconfig: project })]
    })

    await bundle.write({
      chunkFileNames: "types-[hash].d.ts",
      dir: bundleOutdir,
      entryFileNames: "[name].d.ts",
      format: "es"
    })
    await bundle.close()

    removeDeclarationFiles(outdir)
    cpSync(bundleOutdir, outdir, { recursive: true })
  } finally {
    rmSync(bundleOutdir, { force: true, recursive: true })
  }

  console.log("Types bundled into ", outdir)
}
