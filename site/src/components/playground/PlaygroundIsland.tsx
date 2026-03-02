import { PlaygroundInner } from "./PlaygroundInner"
import { Web3Provider } from "./Web3Provider"

export default function PlaygroundIsland() {
  return (
    <Web3Provider>
      <PlaygroundInner />
    </Web3Provider>
  )
}
