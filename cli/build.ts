import { chmod, readFile, writeFile } from "node:fs/promises"
import path from "node:path"
import { buildPackage } from "../../../build.ts"
import { dependencies, peerDependencies } from "./package.json"

await buildPackage({
  outdir: "dist",
  target: "node",
  emitTypes: false,
  external: [
    ...Object.keys(dependencies),
    ...Object.keys(peerDependencies ?? {})
  ]
})

const outputPath = path.resolve("dist/index.js")
const shebang = "#!/usr/bin/env node\n"
const existing = await readFile(outputPath, "utf-8")

if (!existing.startsWith(shebang)) {
  await writeFile(outputPath, `${shebang}${existing}`)
}

await chmod(outputPath, 0o755)
