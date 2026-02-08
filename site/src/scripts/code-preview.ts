// Code tab switching
document.querySelectorAll(".code-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    const target = tab.getAttribute("data-tab")
    document.querySelectorAll(".code-tab").forEach((t) => {
      t.classList.toggle("active", t.getAttribute("data-tab") === target)
    })
    document.querySelectorAll(".code-block").forEach((b) => {
      const isTarget = b.getAttribute("data-tab") === target
      b.classList.toggle("active", isTarget)
    })
  })
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

// Copy code buttons
document.querySelectorAll(".copy-code-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const codeType = btn.getAttribute("data-code") || ""
    const text = codeSnippets[codeType] || ""
    navigator.clipboard.writeText(text)
    showCopyFeedback(btn as HTMLElement)
  })
})

// Copy install command
document.querySelector(".copy-btn")?.addEventListener("click", () => {
  navigator.clipboard.writeText("npm install @slicekit/erc8128")
  showCopyFeedback(document.querySelector(".copy-btn") as HTMLElement)
})

function showCopyFeedback(btn: HTMLElement) {
  const toast = document.getElementById("toast")
  if (toast) {
    toast.classList.add("show")
    setTimeout(() => toast.classList.remove("show"), 2000)
  }

  // Save original children and swap with checkmark icon
  const originalChildren = Array.from(btn.childNodes).map((n) =>
    n.cloneNode(true)
  )
  btn.replaceChildren(createCheckmarkSvg())
  setTimeout(() => {
    btn.replaceChildren(...originalChildren)
  }, 2000)
}
