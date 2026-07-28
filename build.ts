import { buildPackage } from "../../build"
import { dependencies, peerDependencies } from "./package.json"

const DtsPaths = [new URL("./dist/esm/index.d.ts", import.meta.url)]

await buildPackage({
  entrypoints: ["./src/index.ts"],
  external: [...Object.keys(dependencies), ...Object.keys(peerDependencies)],
  sourcemap: "none"
})

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
