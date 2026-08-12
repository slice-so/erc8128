import { cpSync, mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { buildPackage } from "../../build"
import { bundleDeclarationTypes } from "../../build-declarations"
import { dependencies, peerDependencies } from "./package.json"

const DtsPaths = [new URL("./dist/esm/index.d.ts", import.meta.url)]
const buildRoot = mkdtempSync(join(tmpdir(), "erc8128-build-"))
const buildSource = join(buildRoot, "src")
cpSync(new URL("./src", import.meta.url), buildSource, { recursive: true })

try {
  await buildPackage({
    bundleDeclarations: bundleDeclarationTypes,
    entrypoints: [join(buildSource, "index.ts")],
    external: [...Object.keys(dependencies), ...Object.keys(peerDependencies)],
    root: buildSource,
    sourcemap: "none"
  })
} finally {
  rmSync(buildRoot, { force: true, recursive: true })
}

for (const dtsPath of DtsPaths) {
  const dtsFile = Bun.file(dtsPath)
  if (!(await dtsFile.exists())) continue
  const declarationText = await dtsFile.text()
  const compactDeclarationText = declarationText
    .replace(/\/\*\*[\s\S]*?\*\/\n?/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trimEnd()
    .concat("\n")

  if (compactDeclarationText !== declarationText) {
    await Bun.write(dtsPath, compactDeclarationText)
  }
}
