import { signRequest } from "@slicekit/erc8128"
import { ConnectKitButton } from "connectkit"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { createPublicClient, http } from "viem"
import { mainnet } from "viem/chains"
import { useAccount, useChainId, useConnectorClient } from "wagmi"
import { ExpandablePre } from "./ExpandablePre"

// ── helpers ──────────────────────────────────────────

function escapeHtml(str: string) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}

function normalizePath(raw: string) {
  const trimmed = raw.trim()
  if (!trimmed) return "/verify"
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`
}

function toHex(bytes: Uint8Array) {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as `0x${string}`
}

async function sha256Base64(text: string) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text || "")
  )
  let binary = ""
  new Uint8Array(digest).forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return btoa(binary)
}

const ensClient = createPublicClient({
  chain: mainnet,
  transport: http(
    `https://eth-mainnet.g.alchemy.com/v2/${(import.meta as any).env?.PUBLIC_ALCHEMY_KEY ?? ""}`
  )
})
const ensCache = new Map<string, string | null>()

async function resolveEns(address: string): Promise<string | null> {
  const cached = ensCache.get(address.toLowerCase())
  if (cached !== undefined) return cached
  try {
    const name = await ensClient.getEnsName({
      address: address as `0x${string}`
    })
    ensCache.set(address.toLowerCase(), name)
    return name
  } catch {
    ensCache.set(address.toLowerCase(), null)
    return null
  }
}

// ── default state ────────────────────────────────────

const DEFAULT_BODY = `{
  "action": "mint",
  "tokenId": 42
}`

const ALL_COMPONENTS = ["@method", "@path", "content-digest", "nonce"] as const

// ── component ────────────────────────────────────────

export function PlaygroundInner() {
  const { address, isConnected, connector } = useAccount()
  const chainId = useChainId()
  const { data: connectorClient } = useConnectorClient()

  // Porto detection — Porto auto-approves personal_sign via embedded session key
  const isPorto =
    connector?.id === "porto" ||
    connector?.name?.toLowerCase().includes("porto")
  const [portoAutoSign, setPortoAutoSign] = useState(false)

  // Form state
  const [method, setMethod] = useState("POST")
  const [path] = useState("/verify")
  const [body, setBody] = useState(DEFAULT_BODY)
  const [selectedComponents, setSelectedComponents] = useState<Set<string>>(
    new Set(ALL_COMPONENTS)
  )
  const [ttl, setTtl] = useState(60)
  const [nonce, setNonce] = useState(() =>
    crypto.randomUUID().replaceAll("-", "").slice(0, 16)
  )

  // Result state
  const [signedHeadersHtml, setSignedHeadersHtml] = useState(
    "Sign the request to generate headers."
  )
  const [verificationResultText, setVerificationResultText] =
    useState("Not sent yet.")
  const [signTiming, setSignTiming] = useState("")
  const [verifyTiming, setVerifyTiming] = useState("")
  const [verifyOk, setVerifyOk] = useState(false)
  const [verifyData, setVerifyData] = useState<any>(null)
  const [ensName, setEnsName] = useState<string | null>(null)
  const [lastSignedRequest, setLastSignedRequest] = useState<Request | null>(
    null
  )

  // UI state
  const [signing, setSigning] = useState(false)
  const [signPulse, setSignPulse] = useState(false)
  const [copiedCurl, setCopiedCurl] = useState(false)

  const hasBody = method !== "GET" && body.length > 0
  const includeContentDigest =
    selectedComponents.has("content-digest") && hasBody

  // Reset Porto state on disconnect
  useEffect(() => {
    if (!isConnected) {
      setPortoAutoSign(false)
    }
  }, [isConnected])

  // ── Signature base preview ─────────────────────────

  const signatureBasePreviewHtml = useMemo(() => {
    const lines: string[] = []
    const authority = "erc8128.org"
    lines.push(`<span style="color:#86efac">"@authority": ${authority}</span>`)
    if (selectedComponents.has("@method"))
      lines.push(`<span style="color:#86efac">"@method": ${method}</span>`)
    if (selectedComponents.has("@path"))
      lines.push(
        `<span style="color:#86efac">"@path": ${normalizePath(path)}</span>`
      )

    if (includeContentDigest) {
      lines.push(
        `<span style="color:#c4b5fd">"content-digest": sha-256=:...</span>`
      )
    }
    if (selectedComponents.has("nonce")) {
      lines.push(`<span style="color:#67e8f9">"nonce": ${nonce}</span>`)
    }

    const allComponents = ["@authority"]
    if (selectedComponents.has("@method")) allComponents.push("@method")
    if (selectedComponents.has("@path")) allComponents.push("@path")
    if (includeContentDigest) allComponents.push("content-digest")

    const now = Math.floor(Date.now() / 1000)
    const expires = now + ttl
    let paramsStr = `;created=${now};expires=${expires}`
    if (selectedComponents.has("nonce")) paramsStr += `;nonce="${nonce}"`
    paramsStr += `;keyid="erc8128:${chainId || 1}:${address || "0x..."}"`

    lines.push(
      `<span style="color:rgba(255,255,255,0.35)">"@signature-params": (${allComponents.map((x) => `"${x}"`).join(" ")})${paramsStr}</span>`
    )

    return lines.join("\n")
  }, [
    method,
    path,
    body,
    selectedComponents,
    ttl,
    nonce,
    chainId,
    address,
    includeContentDigest
  ])

  // ── Sign & Verify ──────────────────────────────────

  const signAndVerify = useCallback(async () => {
    if (!address || !connectorClient) return
    setSigning(true)

    const normalizedPath = normalizePath(path)
    const signUrl = `https://erc8128.org${normalizedPath}`
    const fetchUrl = `${window.location.origin}${normalizedPath}`
    const components = Array.from(selectedComponents)
      .filter((c) => c !== "nonce")
      .filter((c) => !(c === "content-digest" && !hasBody))
    const includeNonce = selectedComponents.has("nonce")

    let walletWaitMs = 0
    const signer = {
      address: address as `0x${string}`,
      chainId: chainId || 1,
      signMessage: async (message: Uint8Array) => {
        const messageHex = toHex(message)
        const t0 = performance.now()
        const sig = (await (connectorClient as any).request({
          method: "personal_sign",
          params: [messageHex, address]
        })) as `0x${string}`
        walletWaitMs = performance.now() - t0
        return sig
      }
    }

    try {
      const requestHeaders: Record<string, string> = {}
      if (includeContentDigest && hasBody) {
        requestHeaders["content-type"] = "application/json"
      }

      const signStart = performance.now()
      const signed = await signRequest(
        signUrl,
        {
          method,
          headers: requestHeaders,
          body: hasBody ? body : undefined
        },
        signer,
        {
          binding: "class-bound",
          replay: includeNonce ? "non-replayable" : "replayable",
          nonce: includeNonce ? nonce : undefined,
          ttlSeconds: ttl,
          components
        }
      )
      const signMs =
        Math.round((performance.now() - signStart - walletWaitMs) * 10) / 10
      setSignTiming(`${signMs}ms`)
      setLastSignedRequest(signed)

      // Trigger pulse animation for Porto auto-signing (fast = session key)
      if (isPorto && walletWaitMs < 1000) {
        setPortoAutoSign(true)
        setSignPulse(true)
        setTimeout(() => setSignPulse(false), 800)
      }

      // Display signed headers
      const headerLines: string[] = []
      signed.headers.forEach((value, key) => {
        headerLines.push(
          `<span style="color:#67e8f9">${escapeHtml(key)}:</span> ${escapeHtml(value)}`
        )
      })
      setSignedHeadersHtml(headerLines.join("\n"))

      // Send to server
      const response = await fetch(fetchUrl, {
        method: signed.method,
        headers: signed.headers,
        body: hasBody ? body : undefined
      })

      let payload: any = null
      try {
        payload = await response.json()
      } catch {
        payload = {
          ok: response.ok,
          status: response.status,
          message: await response.text()
        }
      }

      if (payload?.verifyMs != null) {
        setVerifyTiming(`${Math.round(payload.verifyMs)}ms`)
      }

      setVerifyOk(!!payload?.ok)
      setVerifyData(payload)

      if (payload?.ok && payload?.address) {
        resolveEns(payload.address).then(setEnsName)
      } else {
        setEnsName(null)
      }

      const displayPayload = { ...payload }
      delete displayPayload.verifyMs
      setVerificationResultText(JSON.stringify(displayPayload, null, 2))

      // Regenerate nonce
      setNonce(crypto.randomUUID().replaceAll("-", "").slice(0, 16))
    } catch (error) {
      setVerificationResultText(
        `Signing failed: ${(error as Error)?.message || "Unknown error"}`
      )
      setVerifyOk(false)
      setVerifyData(null)
    } finally {
      setSigning(false)
    }
  }, [
    address,
    connectorClient,
    method,
    path,
    selectedComponents,
    ttl,
    nonce,
    hasBody,
    chainId,
    isPorto,
    includeContentDigest
  ])

  // ── Copy as cURL ───────────────────────────────────

  const copyCurl = useCallback(async () => {
    if (!lastSignedRequest) {
      setVerificationResultText("Sign a request first, then copy as cURL.")
      return
    }
    const headers: string[] = []
    lastSignedRequest.headers.forEach((value, key) => {
      headers.push(`-H '${key}: ${value.replaceAll("'", "'\\''")}'`)
    })
    const curl = [
      `curl -X ${method} '${window.location.origin}${normalizePath(path)}'`,
      ...headers,
      method !== "GET" && method !== "DELETE"
        ? `--data '${body.replaceAll("'", "'\\''")}'`
        : ""
    ]
      .filter(Boolean)
      .join(" \\\n  ")

    await navigator.clipboard.writeText(curl)
    setCopiedCurl(true)
    setTimeout(() => setCopiedCurl(false), 1200)
  }, [lastSignedRequest, method, path, body])

  // ── Reset ──────────────────────────────────────────

  const resetAll = useCallback(() => {
    setMethod("POST")
    setBody(DEFAULT_BODY)
    setSelectedComponents(new Set(ALL_COMPONENTS))
    setTtl(60)
    setNonce(crypto.randomUUID().replaceAll("-", "").slice(0, 16))
    setSignedHeadersHtml("Sign the request to generate headers.")
    setVerificationResultText("Not sent yet.")
    setSignTiming("")
    setVerifyTiming("")
    setVerifyOk(false)
    setVerifyData(null)
    setEnsName(null)
    setLastSignedRequest(null)
  }, [])

  // ── Toggle component checkbox ──────────────────────

  const toggleComponent = (component: string) => {
    setSelectedComponents((prev) => {
      const next = new Set(prev)
      if (next.has(component)) next.delete(component)
      else next.add(component)
      return next
    })
  }

  // ── Render ─────────────────────────────────────────

  return (
    <section
      className="border-b border-white/15 px-4 py-14 sm:px-6 md:px-10 lg:px-14"
      id="playground"
    >
      {/* Header */}
      <div className="mb-8 flex flex-col gap-5 md:flex-row md:items-start md:justify-between">
        <div>
          <h2 className="text-4xl font-extrabold uppercase tracking-[-0.03em]">
            PLAYGROUND
          </h2>
          <p className="mt-2 text-xs uppercase tracking-[0.25em] text-white/55">
            SIGN AND VERIFY AN HTTP REQUEST WITH YOUR ETHEREUM WALLET
          </p>
          <p className="mt-3 max-w-xl font-mono text-sm leading-relaxed text-white/50">
            Test ERC-8128 HTTP signatures in real time. Compose a request,
            select signature components, and sign with your Ethereum wallet —
            the server verifies instantly. No backend, no API keys.
          </p>
        </div>

        <ConnectKitButton.Custom>
          {({ isConnected, show, truncatedAddress, ensName: ckEns }) => (
            <button
              onClick={show}
              className="shrink-0 border border-white/15 px-5 py-3 font-mono text-xs uppercase tracking-[0.12em] text-white transition-colors duration-200 hover:bg-white hover:text-black"
              type="button"
            >
              {isConnected
                ? `${ckEns ?? truncatedAddress} [WEB3]`
                : "CONNECT WALLET [WEB3]"}
            </button>
          )}
        </ConnectKitButton.Custom>
      </div>

      {/* Main grid */}
      <div className="grid gap-0 border border-white/15 lg:grid-cols-[minmax(0,0.42fr)_minmax(0,0.58fr)]">
        {/* Left column — Compose & Components */}
        <div className="border-b border-white/15 p-4 md:p-6 lg:border-b-0 lg:border-r lg:border-white/15">
          <div className="mb-5">
            <p className="font-mono text-xs uppercase tracking-[0.12em] text-white/55">
              &gt; 01 // COMPOSE REQUEST
            </p>
          </div>

          <div className="mb-5 grid gap-4 md:grid-cols-[140px_1fr]">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.18em] text-white/45">
                Method
              </span>
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className="playground-field h-11 w-full"
              >
                <option>GET</option>
                <option>POST</option>
                <option>PUT</option>
                <option>DELETE</option>
              </select>
            </label>
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.18em] text-white/45">
                Path
              </span>
              <input
                className="playground-field playground-field-disabled h-11 w-full"
                type="text"
                value={path}
                disabled
              />
            </label>
          </div>

          {method !== "GET" && (
            <label className="mb-9 block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.18em] text-white/45">
                Body (JSON)
              </span>
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                className="playground-field min-h-44 w-full resize-y"
                spellCheck={false}
              />
            </label>
          )}

          <div className="mb-4 flex items-center justify-between">
            <p className="font-mono text-xs uppercase tracking-[0.12em] text-white/55">
              &gt; 02 // SIGNATURE COMPONENTS
            </p>
            <button
              onClick={resetAll}
              className="font-mono text-[11px] uppercase tracking-[0.15em] text-white/45 transition-colors hover:text-white"
              type="button"
            >
              Reset
            </button>
          </div>

          <div className="relative mb-8 border border-white/15 p-3">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {ALL_COMPONENTS.map((comp) => (
                <label
                  key={comp}
                  className={`component-chip ${
                    comp.startsWith("@")
                      ? "text-[#86efac]"
                      : comp === "content-digest"
                        ? "text-[#c4b5fd]"
                        : "text-[#67e8f9]"
                  }`}
                >
                  <input
                    type="checkbox"
                    className="component-checkbox"
                    checked={selectedComponents.has(comp)}
                    onChange={() => toggleComponent(comp)}
                  />
                  <span>{comp}</span>
                </label>
              ))}
            </div>

            <div className="mt-3 flex items-center justify-between border-t border-white/10 pt-3">
              <label className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.12em] text-white/45">
                <span>TTL</span>
                <input
                  type="number"
                  min={1}
                  max={3600}
                  value={ttl}
                  onChange={(e) => setTtl(parseInt(e.target.value, 10) || 60)}
                  className="ttl-input"
                />
                <span>sec</span>
              </label>
            </div>
          </div>

          <div className="flex flex-col gap-3">
            <button
              onClick={signAndVerify}
              disabled={!isConnected || signing}
              className={`relative h-12 w-full border font-mono text-sm font-semibold uppercase tracking-[0.12em] transition-all duration-200 ${
                signing
                  ? "border-white/30 text-white/30 cursor-wait"
                  : signPulse
                    ? "border-[#67e8f9] bg-[#67e8f9]/20 text-[#67e8f9] shadow-[0_0_20px_rgba(103,232,249,0.3)]"
                    : "border-[#67e8f9] bg-transparent text-[#67e8f9] hover:bg-[#67e8f9] hover:text-black"
              }`}
              type="button"
            >
              {signing ? "SIGNING..." : "SIGN REQUEST"}
              {signPulse && (
                <span className="absolute inset-0 animate-ping border border-[#67e8f9] opacity-30" />
              )}
            </button>

            {/* Porto status badge */}
            {isConnected && isPorto && (
              <div className="flex items-center justify-center gap-2 py-1">
                <span
                  className={`inline-block h-2 w-2 rounded-full ${
                    portoAutoSign
                      ? "bg-[#67e8f9] shadow-[0_0_6px_rgba(103,232,249,0.5)]"
                      : "bg-[#67e8f9]/50"
                  }`}
                />
                <span
                  className={`font-mono text-[11px] uppercase tracking-[0.18em] ${
                    portoAutoSign ? "text-[#67e8f9]" : "text-white/45"
                  }`}
                >
                  {portoAutoSign ? "SESSION KEY: AUTO-SIGNING" : "PORTO: CONNECTED"}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Right column — Preview & Results */}
        <div className="p-4 md:p-6">
          <div className="mb-3">
            <p className="font-mono text-xs uppercase tracking-[0.12em] text-white/55">
              &gt; 03 // SIGNATURE BASE PREVIEW
            </p>
          </div>

          <div className="relative mb-6">
            <pre
              className="overflow-x-auto border border-white/15 bg-white/5 p-4 font-mono text-[13px] leading-7 text-white/70"
              dangerouslySetInnerHTML={{ __html: signatureBasePreviewHtml }}
            />
            <span className="absolute right-3 top-3 border border-white/15 px-2 py-1 font-mono text-[10px] uppercase tracking-[0.16em] text-white/40">
              RFC 9421
            </span>
          </div>

          <div className="mb-6 border border-white/15 p-4">
            <div className="mb-2 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <p className="font-mono text-xs uppercase tracking-[0.12em] text-white/55">
                  &gt; 04 // SIGNED HEADERS
                </p>
                {signTiming && (
                  <span className="font-mono text-[10px] text-white/30">
                    {signTiming}
                  </span>
                )}
              </div>
              <button
                onClick={copyCurl}
                className="font-mono text-[11px] uppercase tracking-[0.14em] text-white/50 transition-colors hover:text-white"
                type="button"
              >
                {copiedCurl ? "Copied" : "Copy as cURL"}
              </button>
            </div>
            <ExpandablePre html={signedHeadersHtml} />
          </div>

          <div className="border border-white/15 p-4">
            <div className="mb-2 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <p className="font-mono text-xs uppercase tracking-[0.12em] text-white/55">
                  &gt; 05 // VERIFICATION RESULT
                </p>
                {verifyTiming && (
                  <span className="font-mono text-[10px] text-white/30">
                    {verifyTiming}
                  </span>
                )}
              </div>
              {verifyOk && verifyData && (
                <div className="flex items-center gap-2">
                  <span
                    className="result-badge"
                    style={{
                      color:
                        verifyData.binding === "request-bound"
                          ? "#86efac"
                          : "#fcd34d",
                      borderColor:
                        verifyData.binding === "request-bound"
                          ? "#86efac"
                          : "#fcd34d"
                    }}
                  >
                    {verifyData.binding === "request-bound"
                      ? "REQUEST-BOUND"
                      : "CLASS-BOUND"}
                  </span>
                  <span
                    className="result-badge"
                    style={{
                      color: verifyData.replayable
                        ? "rgba(255,255,255,0.4)"
                        : "#67e8f9",
                      borderColor: verifyData.replayable
                        ? "rgba(255,255,255,0.2)"
                        : "#67e8f9"
                    }}
                  >
                    {verifyData.replayable ? "REPLAYABLE" : "NON-REPLAYABLE"}
                  </span>
                </div>
              )}
            </div>

            {verifyOk && verifyData?.address && (
              <div className="mb-2 flex items-center justify-between gap-3 border border-[#86efac]/15 bg-[#86efac]/[0.06] p-2 px-3">
                <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-[#86efac]/70">
                  Authenticated Account
                </span>
                <div className="flex flex-col items-end">
                  {ensName && (
                    <span className="font-mono text-[13px] text-[#86efac]">
                      {ensName}
                    </span>
                  )}
                  <span
                    className={`font-mono ${ensName ? "text-[10px] text-white/35" : "text-[12px] text-[#86efac]"}`}
                  >
                    {`${verifyData.address.slice(0, 6)}...${verifyData.address.slice(-4)}`}
                  </span>
                </div>
              </div>
            )}

            <ExpandablePre text={verificationResultText} />
          </div>
        </div>
      </div>
    </section>
  )
}
