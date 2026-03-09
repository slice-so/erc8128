import { signRequest } from "@slicekit/erc8128"
import { ConnectKitButton, useModal } from "connectkit"
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react"
import {
  createPublicClient,
  createWalletClient,
  custom,
  type EIP1193Provider,
  http,
  keccak256
} from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { mainnet } from "viem/chains"
import { useAccount, useChainId } from "wagmi"
import { ExpandablePre } from "./ExpandablePre"
import { SessionKeyBadge } from "./SessionKeyBadge"

// ── helpers ──────────────────────────────────────────

function escapeHtml(str: string) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}

function normalizePath(raw: string) {
  const trimmed = raw.trim()
  if (!trimmed) return "/verify"
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`
}

function getSigningPath(raw: string) {
  return normalizePath(raw)
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
    `https://eth-mainnet.g.alchemy.com/v2/${import.meta.env.PUBLIC_ALCHEMY_KEY || ""}`
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
  "storeId": 1,
  "productId": 42,
  "quantity": 2
}`

const ALL_COMPONENTS = ["@method", "@path", "content-digest", "nonce"] as const

type AppWalletState = { id: string; publicKey: string; expiry: number }

type StorageMode = "redis" | "postgres"

const STORAGE_LABELS: Record<StorageMode, string> = {
  redis: "Redis",
  postgres: "Postgres"
}

type VerifyPayload = {
  ok?: boolean
  status?: number
  message?: string
  reason?: string
  detail?: string
  address?: string
  binding?: string
  replayable?: boolean
  verifyMs?: number
  storageMode?: StorageMode
  cacheStrategy?: string
  "cached-verification"?: boolean
}

type SentRequestSnapshot = {
  url: string
  method: string
  headers: [string, string][]
  body?: string
}

const APP_WALLET_PRIVATE_KEY_STORAGE_KEY = "erc8128_playground_app_wallet_key"
const APP_WALLET_EXPIRY_STORAGE_KEY = "erc8128_playground_app_wallet_expiry"
const PLAYGROUND_ORIGIN =
  import.meta.env.SITE?.replace(/\/$/, "") || "https://erc8128.org"

function getPlaygroundOrigin() {
  return PLAYGROUND_ORIGIN
}

function getRequestOrigin() {
  if (typeof window !== "undefined" && window.location.origin) {
    return window.location.origin.replace(/\/$/, "")
  }

  return PLAYGROUND_ORIGIN
}

function readStoredAppWalletPrivateKey(): `0x${string}` | null {
  if (typeof window === "undefined") return null

  const privateKey = localStorage.getItem(APP_WALLET_PRIVATE_KEY_STORAGE_KEY) as
    | `0x${string}`
    | null
  const expiryRaw = localStorage.getItem(APP_WALLET_EXPIRY_STORAGE_KEY)
  const expiry = Number(expiryRaw)

  if (!privateKey || !Number.isFinite(expiry)) {
    return null
  }

  if (expiry <= Math.floor(Date.now() / 1000)) {
    localStorage.removeItem(APP_WALLET_PRIVATE_KEY_STORAGE_KEY)
    localStorage.removeItem(APP_WALLET_EXPIRY_STORAGE_KEY)
    return null
  }

  return privateKey
}

async function parseResponsePayload(
  response: Response
): Promise<VerifyPayload> {
  const text = await response.text()
  if (!text) {
    return {
      ok: response.ok,
      status: response.status,
      message: ""
    }
  }

  try {
    return JSON.parse(text) as VerifyPayload
  } catch {
    return {
      ok: response.ok,
      status: response.status,
      message: text
    }
  }
}

// ── component ────────────────────────────────────────

export function PlaygroundInner() {
  const { address, isConnected, connector } = useAccount()
  const chainId = useChainId()
  const { setOpen: openConnectModal } = useModal()
  const [appWallet, setAppWallet] = useState<AppWalletState | null>(null)
  const [autoSigningPending, setAutoSigningPending] = useState(false)

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
  const [storageMode, setStorageMode] = useState<StorageMode>("postgres")

  // Result state
  const [signedHeadersHtml, setSignedHeadersHtml] = useState(
    "Sign the request to generate headers."
  )
  const [verificationResultText, setVerificationResultText] =
    useState("Not sent yet.")
  const [signTiming, setSignTiming] = useState("")
  const [verifyTiming, setVerifyTiming] = useState("")
  const [verifyOk, setVerifyOk] = useState(false)
  const [verifyData, setVerifyData] = useState<VerifyPayload | null>(null)
  const [ensName, setEnsName] = useState<string | null>(null)
  const [userEnsName, setUserEnsName] = useState<string | null>(null)
  const [lastSentRequest, setLastSentRequest] =
    useState<SentRequestSnapshot | null>(null)

  // UI state
  const [signing, setSigning] = useState(false)
  const [signPulse, setSignPulse] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [copiedCurl, setCopiedCurl] = useState(false)
  const [contentDigestPreview, setContentDigestPreview] = useState<string>("")
  const providerRef = useRef<EIP1193Provider | null>(null)
  const signingRef = useRef(false)

  const hasBody = method !== "GET" && body.length > 0
  const includeContentDigest =
    selectedComponents.has("content-digest") && hasBody

  useEffect(() => {
    let cancelled = false

    if (!includeContentDigest) {
      setContentDigestPreview("")
      return
    }

    sha256Base64(body)
      .then((digest) => {
        if (!cancelled) setContentDigestPreview(`sha-256=:${digest}:`)
      })
      .catch(() => {
        if (!cancelled)
          setContentDigestPreview("sha-256=:[digest unavailable]:")
      })

    return () => {
      cancelled = true
    }
  }, [body, includeContentDigest])

  // Clear app wallet on actual disconnect (not initial mount)
  const wasConnectedRef = useRef(false)
  useEffect(() => {
    if (isConnected) {
      wasConnectedRef.current = true
    } else if (wasConnectedRef.current) {
      wasConnectedRef.current = false
      setAppWallet(null)
      providerRef.current = null
      localStorage.removeItem(APP_WALLET_PRIVATE_KEY_STORAGE_KEY)
      localStorage.removeItem(APP_WALLET_EXPIRY_STORAGE_KEY)
    }
  }, [isConnected])

  useEffect(() => {
    if (!address) {
      setUserEnsName(null)
      return
    }
    resolveEns(address).then(setUserEnsName)
  }, [address])

  // biome-ignore lint/correctness/useExhaustiveDependencies: deps are intentional triggers to reset provider on connection change
  useEffect(() => {
    providerRef.current = null
  }, [connector?.id, address, chainId])

  useEffect(() => {
    if (!isConnected) return

    const privateKey = localStorage.getItem(
      APP_WALLET_PRIVATE_KEY_STORAGE_KEY
    ) as `0x${string}` | null
    const expiryRaw = localStorage.getItem(APP_WALLET_EXPIRY_STORAGE_KEY)
    const expiry = Number(expiryRaw)

    if (!privateKey || !Number.isFinite(expiry)) return

    if (expiry <= Math.floor(Date.now() / 1000)) {
      localStorage.removeItem(APP_WALLET_PRIVATE_KEY_STORAGE_KEY)
      localStorage.removeItem(APP_WALLET_EXPIRY_STORAGE_KEY)
      setAppWallet(null)
      return
    }

    const keyAccount = privateKeyToAccount(privateKey)
    setAppWallet({
      id: `session-${expiry}`,
      publicKey: keyAccount.address,
      expiry
    })
  }, [isConnected])

  const getProvider = useCallback(async () => {
    if (!connector) return null
    if (!providerRef.current) {
      providerRef.current = (await connector.getProvider()) as EIP1193Provider
    }
    return providerRef.current
  }, [connector])

  const getWalletClient = useCallback(async () => {
    if (!address) return null
    const provider = await getProvider()
    if (!provider) return null
    return createWalletClient({
      account: address as `0x${string}`,
      chain: mainnet,
      transport: custom(provider)
    })
  }, [address, getProvider])

  const sendRequestSnapshot = useCallback(
    async (requestSnapshot: SentRequestSnapshot) => {
      setVerifyOk(false)
      setVerifyData(null)
      setVerifyTiming("")
      setVerificationResultText("Processing request...")
      setVerifying(true)

      try {
        const response = await fetch(requestSnapshot.url, {
          method: requestSnapshot.method,
          headers: requestSnapshot.headers,
          body: requestSnapshot.body
        })

        const payload = await parseResponsePayload(response)

        if (payload?.verifyMs != null) {
          setVerifyTiming(`verified in ${Math.round(payload.verifyMs)}ms`)
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
        delete displayPayload.storageMode
        delete displayPayload.cacheStrategy
        setVerificationResultText(JSON.stringify(displayPayload, null, 2))
      } catch (error) {
        setVerifyTiming("")
        setVerifyOk(false)
        setVerifyData(null)
        setEnsName(null)
        setVerificationResultText(
          `Request failed: ${(error as Error)?.message || "Unknown error"}`
        )
      } finally {
        setVerifying(false)
      }
    },
    []
  )

  const enableAutoSigning = useCallback(async () => {
    if (!isConnected || !address) return
    setAutoSigningPending(true)

    try {
      const walletClient = await getWalletClient()
      if (!walletClient) throw new Error("Wallet is not ready")

      const sig = await walletClient.signMessage({
        account: address as `0x${string}`,
        message: "Create app wallet to sign requests on the ERC-8128 Playground"
      })
      const privateKey = keccak256(sig)
      const keyAccount = privateKeyToAccount(privateKey)
      const expiry = Math.floor(Date.now() / 1000) + 60 * 60

      const granted = {
        id: `app-wallet-${keyAccount.address.slice(2, 10)}`,
        publicKey: keyAccount.address,
        expiry
      }

      localStorage.setItem(APP_WALLET_PRIVATE_KEY_STORAGE_KEY, privateKey)
      localStorage.setItem(APP_WALLET_EXPIRY_STORAGE_KEY, `${granted.expiry}`)

      setAppWallet(granted)
      setVerificationResultText(
        `Auto-signing enabled. App wallet ${granted.publicKey} signs as a separate identity until ${new Date(
          granted.expiry * 1000
        ).toLocaleTimeString()}.`
      )
    } catch (error) {
      setAppWallet(null)
      localStorage.removeItem(APP_WALLET_PRIVATE_KEY_STORAGE_KEY)
      localStorage.removeItem(APP_WALLET_EXPIRY_STORAGE_KEY)
      setVerificationResultText(
        `Enable auto-signing failed: ${(error as Error)?.message || "Unknown error"}`
      )
    } finally {
      setAutoSigningPending(false)
    }
  }, [address, isConnected, getWalletClient])

  const disconnectAppWallet = useCallback(() => {
    setAppWallet(null)
    localStorage.removeItem(APP_WALLET_PRIVATE_KEY_STORAGE_KEY)
    localStorage.removeItem(APP_WALLET_EXPIRY_STORAGE_KEY)
    setVerificationResultText("App wallet disconnected.")
  }, [])

  // ── Signature base preview ─────────────────────────

  const signatureBasePreviewHtml = useMemo(() => {
    const lines: string[] = []
    const authority = new URL(getPlaygroundOrigin()).host
    const signingPath = getSigningPath(path)
    lines.push(`<span style="color:#86efac">"@authority": ${authority}</span>`)
    if (selectedComponents.has("@method"))
      lines.push(`<span style="color:#86efac">"@method": ${method}</span>`)
    if (selectedComponents.has("@path"))
      lines.push(`<span style="color:#86efac">"@path": ${signingPath}</span>`)

    if (includeContentDigest) {
      lines.push(
        `<span style="color:#c4b5fd">"content-digest": ${escapeHtml(contentDigestPreview || "sha-256=:[calculating...]:")}</span>`
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
    const storedSessionKey = readStoredAppWalletPrivateKey()
    const previewSigner = storedSessionKey
      ? privateKeyToAccount(storedSessionKey as `0x${string}`).address
      : (address ?? "0x...")
    paramsStr += `;keyid="erc8128:${chainId || 1}:${previewSigner}"`

    lines.push(
      `<span style="color:rgba(255,255,255,0.35)">"@signature-params": (${allComponents.map((x) => `"${x}"`).join(" ")})${paramsStr}</span>`
    )

    return lines.join("\n")
  }, [
    method,
    path,
    selectedComponents,
    ttl,
    nonce,
    chainId,
    address,
    includeContentDigest,
    contentDigestPreview
  ])

  // ── Sign & Verify ──────────────────────────────────

  const signAndVerify = useCallback(async () => {
    if (!address || !connector || signingRef.current) return

    signingRef.current = true
    setSigning(true)

    const normalizedPath = normalizePath(path)
    const signingPath = getSigningPath(path)
    const signingOrigin = getPlaygroundOrigin()
    const requestOrigin = getRequestOrigin()
    const signUrl = new URL(signingPath, signingOrigin).toString()
    const fetchUrl = new URL(normalizedPath, requestOrigin).toString()
    const components = Array.from(selectedComponents)
      .filter((c) => c !== "nonce")
      .filter((c) => !(c === "content-digest" && !hasBody))
    const includeNonce = selectedComponents.has("nonce")
    const storedPrivateKey = readStoredAppWalletPrivateKey()
    const sessionAccount = storedPrivateKey
      ? privateKeyToAccount(storedPrivateKey)
      : null
    const sessionAddress = sessionAccount?.address ?? null

    if (appWallet && !storedPrivateKey) {
      setAppWallet(null)
    }

    let walletWaitMs = 0

    const signer = {
      address: (sessionAddress ?? address) as `0x${string}`,
      chainId: chainId || 1,
      signMessage: async (message: Uint8Array) => {
        const t0 = performance.now()

        if (sessionAccount) {
          const signature = await sessionAccount.signMessage({
            message: { raw: toHex(message) }
          })

          walletWaitMs = performance.now() - t0
          return signature as `0x${string}`
        }

        const walletClient = await getWalletClient()
        if (!walletClient) throw new Error("Wallet provider unavailable")

        const messageHex = toHex(message)
        const sig = await walletClient.signMessage({
          account: address as `0x${string}`,
          message: { raw: messageHex }
        })

        walletWaitMs = performance.now() - t0
        return sig
      }
    }

    try {
      const requestHeaders: Record<string, string> = {}
      if (hasBody) {
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
      setSignTiming(`signed in ${signMs}ms`)

      // Trigger pulse animation for app-wallet auto-signing (fast path).
      if (storedPrivateKey && walletWaitMs < 1000) {
        setSignPulse(true)
        setTimeout(() => setSignPulse(false), 800)
      }

      // Display signed headers
      const headerLines: string[] = []
      signed.headers.forEach((value, key) => {
        if (key.toLowerCase() === "content-type") return
        headerLines.push(
          `<span style="color:#67e8f9">${escapeHtml(key)}:</span> ${escapeHtml(value)}`
        )
      })
      setSignedHeadersHtml(headerLines.join("\n"))

      // Send to server — inject hidden storage header (NOT signed)
      const fetchHeaders = new Headers(signed.headers)
      fetchHeaders.set("x-erc8128-storage", storageMode)
      const requestSnapshot = {
        url: fetchUrl,
        method: signed.method,
        headers: Array.from(fetchHeaders.entries()),
        ...(hasBody ? { body } : {})
      } satisfies SentRequestSnapshot
      setLastSentRequest(requestSnapshot)
      await sendRequestSnapshot(requestSnapshot)

      // Regenerate nonce
      setNonce(crypto.randomUUID().replaceAll("-", "").slice(0, 16))
    } catch (error) {
      setVerificationResultText(
        `Signing failed: ${(error as Error)?.message || "Unknown error"}`
      )
      setSignTiming("")
      setVerifyTiming("")
      setVerifyOk(false)
      setVerifyData(null)
      setLastSentRequest(null)
    } finally {
      signingRef.current = false
      setSigning(false)
    }
  }, [
    address,
    connector,
    method,
    path,
    body,
    selectedComponents,
    ttl,
    nonce,
    hasBody,
    chainId,
    getWalletClient,
    appWallet,
    storageMode,
    sendRequestSnapshot
  ])

  const replayLastRequest = useCallback(async () => {
    if (!lastSentRequest || signingRef.current) return
    await sendRequestSnapshot(lastSentRequest)
  }, [lastSentRequest, sendRequestSnapshot])

  // ── Copy as cURL ───────────────────────────────────

  const copyCurl = useCallback(async () => {
    if (!lastSentRequest) {
      setVerificationResultText("Sign a request first, then copy as cURL.")
      return
    }
    const headers: string[] = []
    for (const [key, value] of lastSentRequest.headers) {
      headers.push(`-H '${key}: ${value.replaceAll("'", "'\\''")}'`)
    }
    const curl = [
      `curl -X ${lastSentRequest.method} '${lastSentRequest.url}'`,
      ...headers,
      lastSentRequest.body !== undefined
        ? `--data '${lastSentRequest.body.replaceAll("'", "'\\''")}'`
        : ""
    ]
      .filter(Boolean)
      .join(" \\\n  ")

    await navigator.clipboard.writeText(curl)
    setCopiedCurl(true)
    setTimeout(() => setCopiedCurl(false), 1200)
  }, [lastSentRequest])

  // ── Reset ──────────────────────────────────────────

  const resetAll = useCallback(() => {
    setMethod("POST")
    setBody(DEFAULT_BODY)
    setSelectedComponents(new Set(ALL_COMPONENTS))
    setTtl(60)
    setNonce(crypto.randomUUID().replaceAll("-", "").slice(0, 16))
    setStorageMode("postgres")
    setSignedHeadersHtml("Sign the request to generate headers.")
    setVerificationResultText("Not sent yet.")
    setSignTiming("")
    setVerifyTiming("")
    setVerifyOk(false)
    setVerifyData(null)
    setEnsName(null)
    setLastSentRequest(null)
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
      id={useId()}
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
          <div className="mt-3 space-y-2 font-mono text-sm leading-relaxed text-white/50">
            <p>1. Connect a wallet and configure the request parameters</p>
            <p>2. Sign the request and view the verification result</p>
            <p>3. Enable auto-signing to use an app wallet without popups</p>
            <p>
              4. Optional: call DELETE without one or more components to view
              the ERC-8128 error response
            </p>
          </div>
        </div>

        <div className="shrink-0">
          <ConnectKitButton.Custom>
            {({ isConnected, show, truncatedAddress, ensName: ckEns }) => (
              <button
                onClick={show}
                className="w-full border border-white/15 px-5 py-3 font-mono text-xs uppercase tracking-[0.12em] text-white transition-colors duration-200 hover:bg-white hover:text-black"
                type="button"
              >
                {isConnected
                  ? `${ckEns ?? truncatedAddress}`
                  : "CONNECT WALLET"}
              </button>
            )}
          </ConnectKitButton.Custom>
          {isConnected && appWallet && (
            <button
              onClick={disconnectAppWallet}
              className="mt-2 w-full font-mono text-[10px] uppercase tracking-[0.16em] text-white/45 transition-colors hover:text-[#fca5a5] py-1 px-5 cursor-pointer text-center bg-transparent border-none"
              type="button"
            >
              Disconnect App Wallet
            </button>
          )}
        </div>
      </div>

      {/* Main grid */}
      <div className="lg:grid gap-0 border border-white/15 lg:grid-cols-[minmax(0,0.42fr)_minmax(0,0.58fr)] lg:max-h-[756px]">
        {/* Left column — Compose & Components */}
        <div className="border-b border-white/15 p-4 md:p-6 lg:border-b-0 lg:border-r lg:border-white/15 flex flex-col justify-between">
          <div>
            <div className="mb-5">
              <p className="font-mono text-xs uppercase tracking-[0.12em] text-white/55">
                &gt; {"COMPOSE REQUEST"}
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
                &gt; {"SIGNATURE COMPONENTS"}
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

            <div className="mb-4 mt-6">
              <p className="mb-3 font-mono text-xs uppercase tracking-[0.12em] text-white/55">
                &gt; {"SERVER STORAGE BACKEND"}
              </p>
              <div className="border border-white/15 p-3">
                <div className="grid grid-cols-1 gap-2">
                  {(["redis", "postgres"] as const).map((mode) => (
                    <label
                      key={mode}
                      className={`component-chip ${
                        storageMode === mode
                          ? mode === "redis"
                            ? "text-[#fbbf24]"
                            : "text-[#60a5fa]"
                          : "text-white/35"
                      }`}
                    >
                      <input
                        type="radio"
                        name="storage-mode"
                        className="component-checkbox"
                        checked={storageMode === mode}
                        onChange={() => setStorageMode(mode)}
                      />
                      <span>{STORAGE_LABELS[mode]}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          </div>
          <div>
            <div className="flex flex-col gap-3">
              <button
                onClick={
                  isConnected ? signAndVerify : () => openConnectModal(true)
                }
                disabled={signing}
                className={`group relative h-12 w-full overflow-hidden border font-mono text-sm font-semibold uppercase tracking-[0.12em] transition-all duration-300 ${
                  signing
                    ? "border-[#67e8f9]/45 text-[#67e8f9]/55 cursor-wait"
                    : signPulse
                      ? "border-[#67e8f9] bg-[#67e8f9]/20 text-[#67e8f9] shadow-[0_0_26px_rgba(103,232,249,0.35)]"
                      : "border-[#67e8f9] bg-transparent text-[#67e8f9] hover:shadow-[0_0_20px_rgba(103,232,249,0.25)]"
                }`}
                type="button"
              >
                <span className="absolute inset-0 -translate-x-full bg-linear-to-r from-transparent via-[#67e8f9]/25 to-transparent transition-transform duration-700 group-hover:translate-x-full" />
                {signing
                  ? "SIGNING..."
                  : isConnected
                    ? "SIGN REQUEST"
                    : "CONNECT WALLET"}
                {signPulse && (
                  <span className="absolute inset-0 animate-ping border border-[#67e8f9] opacity-30" />
                )}
              </button>

              {isConnected && !appWallet && (
                <button
                  onClick={enableAutoSigning}
                  disabled={autoSigningPending || signing}
                  className={`h-11 w-full border font-mono text-xs font-semibold tracking-[0.08em] transition-colors duration-200 ${
                    autoSigningPending || signing
                      ? "border-white/20 text-white/30 cursor-wait"
                      : "border-white/35 text-white/75 hover:border-[#67e8f9] hover:text-[#67e8f9]"
                  }`}
                  type="button"
                >
                  {autoSigningPending
                    ? "ENABLING AUTO-SIGNING..."
                    : "Enable Auto-signing (App wallet)"}
                </button>
              )}

              <SessionKeyBadge
                isConnected={isConnected}
                appWallet={appWallet}
                appWalletPending={autoSigningPending}
              />
            </div>
          </div>
        </div>

        {/* Right column — Preview & Results */}
        <div className="p-4 md:p-6 lg:flex lg:flex-col lg:min-h-0">
          <div className="mb-3">
            <p className="font-mono text-xs uppercase tracking-[0.12em] text-white/55">
              &gt; {"SIGNATURE BASE PREVIEW"}
            </p>
          </div>

          <div className="relative mb-6">
            <pre
              className="overflow-x-auto bg-white/5 p-4 font-mono text-[13px] leading-7 text-white/45"
              // biome-ignore lint/security/noDangerouslySetInnerHtml: HTML built internally from controlled values
              dangerouslySetInnerHTML={{ __html: signatureBasePreviewHtml }}
            />
            <span className="absolute right-0 top-0 bg-white/15 px-2 py-1 font-mono text-[10px] uppercase tracking-[0.16em] text-white/45">
              RFC 9421
            </span>
          </div>

          <div className="mb-6">
            <div className="mb-2 flex items-start justify-between">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.12em] text-white/55">
                  &gt; {"SIGNED HEADERS"}
                </p>
                {signTiming && (
                  <p className="mt-1 font-mono text-[10px] text-yellow-300/90">
                    {signTiming}
                  </p>
                )}
              </div>
              <div className="flex items-center gap-3">
                {lastSentRequest && (
                  <button
                    onClick={replayLastRequest}
                    disabled={verifying}
                    className={`inline-flex items-center gap-2 border px-3 py-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] transition-all ${
                      verifying
                        ? "cursor-wait border-[#67e8f9]/25 text-[#67e8f9]/35"
                        : "border-[#67e8f9]/60 bg-[#67e8f9]/8 text-[#67e8f9] hover:border-[#67e8f9] hover:bg-[#67e8f9]/14"
                    }`}
                    type="button"
                  >
                    <svg
                      aria-hidden="true"
                      className={`h-3.5 w-3.5 ${verifying ? "animate-spin" : ""}`}
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <path
                        d="M20 11a8 8 0 1 0-2.34 5.66M20 11V5m0 6h-6"
                        stroke="currentColor"
                        strokeLinecap="square"
                        strokeLinejoin="miter"
                        strokeWidth="1.8"
                      />
                    </svg>
                    <span>{verifying ? "Replaying..." : "Replay Request"}</span>
                  </button>
                )}
              </div>
            </div>
            <ExpandablePre html={signedHeadersHtml} />
            {lastSentRequest && (
              <div className="mt-3 flex justify-end">
                <button
                  onClick={copyCurl}
                  className="border border-white/12 bg-white/4 px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-white/45 transition-colors hover:border-white/20 hover:bg-white/7 hover:text-white/70"
                  type="button"
                >
                  {copiedCurl ? "Copied" : "Copy as cURL"}
                </button>
              </div>
            )}
          </div>

          <div className="lg:flex lg:flex-1 lg:flex-col lg:min-h-0">
            <div className="mb-2 flex items-start justify-between">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.12em] text-white/55">
                  &gt; {"VERIFICATION RESULT"}
                </p>
                {verifyTiming && (
                  <p
                    className={`mt-1 font-mono text-[10px] ${
                      verifyData?.["cached-verification"]
                        ? "text-emerald-300/90"
                        : "text-yellow-300/90"
                    }`}
                  >
                    {verifyTiming}
                    {verifyData?.["cached-verification"] && (
                      <span className="text-emerald-300/90"> (cached)</span>
                    )}
                    {verifyData?.storageMode && (
                      <span
                        className="ml-1"
                        style={{
                          color:
                            verifyData.storageMode === "redis"
                              ? "#fbbf24"
                              : "#60a5fa"
                        }}
                      >
                        · {verifyData.storageMode}
                      </span>
                    )}
                  </p>
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
                        ? "rgba(255,255,255,0.6)"
                        : "#67e8f9",
                      borderColor: verifyData.replayable
                        ? "rgba(255,255,255,0.4)"
                        : "#67e8f9"
                    }}
                  >
                    {verifyData.replayable ? "REPLAYABLE" : "NON-REPLAYABLE"}
                  </span>
                </div>
              )}
            </div>

            {verifyOk && verifyData?.address && (
              <div className="mb-2 flex items-center justify-between gap-3 border border-[#86efac]/15 bg-[#86efac]/6 p-2 px-3">
                <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-[#86efac]/70">
                  Authenticated Account
                </span>
                <div className="flex flex-col items-end">
                  {!appWallet && ensName && (
                    <span className="font-mono text-[13px] text-[#86efac]">
                      {ensName}
                    </span>
                  )}
                  {appWallet &&
                  verifyData.address.toLowerCase() ===
                    appWallet.publicKey.toLowerCase() ? (
                    <>
                      <span className="font-mono text-[12px] text-[#86efac]">
                        {`${verifyData.address.slice(0, 6)}...${verifyData.address.slice(-4)}`}
                      </span>
                      <span className="font-mono text-[10px] text-white/35">
                        {"App wallet for " +
                          (userEnsName ||
                            (address
                              ? `${address.slice(0, 6)}...${address.slice(-4)}`
                              : "unknown account"))}
                      </span>
                    </>
                  ) : (
                    <span
                      className={`font-mono ${ensName ? "text-[10px] text-white/35" : "text-[12px] text-[#86efac]"}`}
                    >
                      {`${verifyData.address.slice(0, 6)}...${verifyData.address.slice(-4)}`}
                    </span>
                  )}
                </div>
              </div>
            )}

            {verifying && (
              <div className="mb-2 border border-[#67e8f9]/30 bg-[#67e8f9]/8 px-3 py-2">
                <div className="relative h-[3px] w-full overflow-hidden rounded-full bg-white/10">
                  <div className="absolute inset-y-0 w-1/2 animate-[appwallet-progress_1.1s_ease-in-out_infinite] rounded-full bg-[#67e8f9]" />
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
