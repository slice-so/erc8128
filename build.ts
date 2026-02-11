import { buildPackage } from "../../build"
import { dependencies, peerDependencies } from "./package.json"

await buildPackage({
  external: [...Object.keys(dependencies), ...Object.keys(peerDependencies)]
})
