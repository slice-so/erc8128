// Generic tab group handler
function initTabGroup(
  tabSelector: string,
  attr: string,
  onChange?: (value: string) => void
) {
  document.querySelectorAll(tabSelector).forEach((tab) => {
    tab.addEventListener("click", () => {
      const value = tab.getAttribute(attr) || ""
      document.querySelectorAll(tabSelector).forEach((t) => {
        t.classList.toggle("active", t.getAttribute(attr) === value)
      })
      onChange?.(value)
    })
  })
}

// Code tab switching
initTabGroup(".code-tab[data-tab]", "data-tab", (tab) => {
  document.querySelectorAll(".code-block").forEach((b) => {
    b.classList.toggle("active", b.getAttribute("data-tab") === tab)
  })
})

// Install tab switching
const installCommands: Record<string, string> = {
  bun: "bun add @slicekit/erc8128",
  pnpm: "pnpm add @slicekit/erc8128",
  npm: "npm install @slicekit/erc8128"
}

const installCommandEl = document.querySelector(".install-command")

initTabGroup(".code-tab[data-pm]", "data-pm", (pm) => {
  if (installCommandEl) {
    installCommandEl.textContent = installCommands[pm]
  }
})

// Code snippets for copy
const codeSnippets: Record<string, string> = {
  sign: `import { createSignerClient } from '@slicekit/erc8128'
import { privateKeyToAccount } from 'viem/accounts'

const account = privateKeyToAccount('0x...')
const signer = {
  chainId: 1,
  address: account.address,
  signMessage: (msg) => account.signMessage({ message: { raw: msg } }),
}

const signerClient = createSignerClient(signer)

const response = await signerClient.fetch(
  'https://api.example.com/orders', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ amount: '100' }),
})`,
  verify: `import { createVerifierClient } from '@slicekit/erc8128'
import { createPublicClient, http } from 'viem'
import { mainnet } from 'viem/chains'
import { nonceStore } from './nonceStore'

const publicClient = createPublicClient({
  chain: mainnet,
  transport: http(),
})

const verifierClient = createVerifierClient(publicClient.verifyMessage, nonceStore)

const result = await verifierClient.verifyRequest(request)

if (result.ok) {
  console.log(\`Authenticated: \${result.address}\`)
}`
}

// Checkmark SVG for copy feedback
function createCheckmarkSvg(): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg")
  svg.setAttribute("width", "16")
  svg.setAttribute("height", "16")
  svg.setAttribute("viewBox", "0 0 24 24")
  svg.setAttribute("fill", "none")
  svg.setAttribute("stroke", "#4ade80")
  svg.setAttribute("stroke-width", "2.5")
  const polyline = document.createElementNS(
    "http://www.w3.org/2000/svg",
    "polyline"
  )
  polyline.setAttribute("points", "20 6 9 17 4 12")
  svg.appendChild(polyline)
  return svg
}

function showCopyFeedback(btn: HTMLElement) {
  const toast = document.getElementById("toast")
  if (toast) {
    toast.classList.add("show")
    setTimeout(() => toast.classList.remove("show"), 2000)
  }

  const originalChildren = Array.from(btn.childNodes).map((n) =>
    n.cloneNode(true)
  )
  btn.replaceChildren(createCheckmarkSvg())
  setTimeout(() => {
    btn.replaceChildren(...originalChildren)
  }, 2000)
}

// Unified copy handler for all .copy-btn elements
document.querySelectorAll(".copy-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const codeType = btn.getAttribute("data-code")
    let text: string

    if (codeType) {
      text = codeSnippets[codeType] || ""
    } else {
      const activePm =
        document
          .querySelector(".code-tab[data-pm].active")
          ?.getAttribute("data-pm") || "bun"
      text = installCommands[activePm]
    }

    navigator.clipboard.writeText(text)
    showCopyFeedback(btn as HTMLElement)
  })
})
