import { useEffect, useState } from "react"

interface SessionKeyBadgeProps {
  isConnected: boolean
  appWallet: { id: string; publicKey: string; expiry: number } | null
  appWalletPending: boolean
}

function formatTimeRemaining(expirySeconds: number) {
  const remaining = Math.max(0, expirySeconds - Math.floor(Date.now() / 1000))
  if (remaining <= 0) return "expired"
  const m = Math.floor(remaining / 60)
  const s = remaining % 60
  if (m >= 60) {
    const h = Math.floor(m / 60)
    const rm = m % 60
    return rm > 0 ? `${h}h ${rm}m` : `${h}h`
  }
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

export function SessionKeyBadge({
  isConnected,
  appWallet,
  appWalletPending
}: SessionKeyBadgeProps) {
  const [, setTick] = useState(0)

  useEffect(() => {
    if (!appWallet) return
    const id = setInterval(() => setTick((t) => t + 1), 1000)
    return () => clearInterval(id)
  }, [appWallet])

  if (!isConnected) return null

  if (appWalletPending || !appWallet) return null

  if (appWallet) {
    const shortKey = `${appWallet.publicKey.slice(0, 6)}...${appWallet.publicKey.slice(-4)}`

    return (
      <div className="flex flex-col items-center gap-1 py-1">
        <div className="flex items-center gap-2">
          <span className="inline-block h-2 w-2 rounded-full bg-[#67e8f9] shadow-[0_0_6px_rgba(103,232,249,0.5)]" />
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-[#67e8f9]">
            AUTO-SIGN ENABLED
          </span>
        </div>
        <span className="font-mono text-[10px] tracking-[0.12em] text-white/30">
          {shortKey} · expires in {formatTimeRemaining(appWallet.expiry)}
        </span>
      </div>
    )
  }

  return null
}
