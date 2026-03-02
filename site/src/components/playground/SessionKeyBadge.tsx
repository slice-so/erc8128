interface SessionKeyBadgeProps {
  isPorto: boolean
  isConnected: boolean
  sessionKey: { id: string; publicKey: string; expiry: number } | null
  sessionKeyPending: boolean
  onGrantSessionKey: () => void
}

export function SessionKeyBadge({
  isPorto,
  isConnected,
  sessionKey,
  sessionKeyPending,
  onGrantSessionKey
}: SessionKeyBadgeProps) {
  if (!isConnected || !isPorto) return null

  if (sessionKeyPending) {
    return (
      <div className="flex items-center justify-center gap-2 py-1">
        <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-[#67e8f9]" />
        <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-white/45">
          Granting session key...
        </span>
      </div>
    )
  }

  if (sessionKey) {
    const shortKey = sessionKey.publicKey
      ? `${sessionKey.publicKey.slice(0, 6)}...${sessionKey.publicKey.slice(-4)}`
      : "wallet-managed"
    const expiresIn = Math.max(
      0,
      sessionKey.expiry - Math.floor(Date.now() / 1000)
    )
    const expiresMin = Math.ceil(expiresIn / 60)

    return (
      <div className="flex flex-col items-center gap-1 py-1">
        <div className="flex items-center gap-2">
          <span className="inline-block h-2 w-2 rounded-full bg-[#67e8f9] shadow-[0_0_6px_rgba(103,232,249,0.5)]" />
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-[#67e8f9]">
            Session key active
          </span>
        </div>
        <span className="font-mono text-[10px] tracking-[0.12em] text-white/30">
          {shortKey} · expires in {expiresMin}m
        </span>
      </div>
    )
  }

  // Porto connected but no session key
  return (
    <button
      onClick={onGrantSessionKey}
      className="py-1 font-mono text-[11px] uppercase tracking-[0.18em] text-white/45 transition-colors hover:text-[#67e8f9]"
      type="button"
    >
      Grant session key for auto-signing →
    </button>
  )
}
