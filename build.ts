import { buildPackage } from "./build.shared.ts"
import { dependencies, peerDependencies } from "./package.json"

await buildPackage({
  external: [...Object.keys(dependencies), ...Object.keys(peerDependencies)],
  sourcemap: "none"
})
