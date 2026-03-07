import { buildPackage } from "../../build"
import { dependencies, peerDependencies } from "./package.json"

const DtsPath = new URL("./dist/esm/index.d.ts", import.meta.url)

await buildPackage({
  dtsConfig: {
    output: {
      noBanner: true
    }
  },
  external: [...Object.keys(dependencies), ...Object.keys(peerDependencies)],
  sourcemap: "none"
})

const dtsFile = Bun.file(DtsPath)
if (await dtsFile.exists()) {
  const declarationText = await dtsFile.text()
  const compactDeclarationText = declarationText
    .replace(/\/\*\*[\s\S]*?\*\/\n?/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trimEnd()
    .concat("\n")

  if (compactDeclarationText !== declarationText) {
    await Bun.write(DtsPath, compactDeclarationText)
  }
}
