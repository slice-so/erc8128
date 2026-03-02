import { useEffect, useRef, useState } from "react"

interface ExpandablePreProps {
  html?: string
  text?: string
}

export function ExpandablePre({ html, text }: ExpandablePreProps) {
  const preRef = useRef<HTMLPreElement>(null)
  const [expanded, setExpanded] = useState(false)
  const [isOverflowing, setIsOverflowing] = useState(false)

  useEffect(() => {
    const el = preRef.current
    if (!el) return
    setIsOverflowing(el.scrollHeight > el.clientHeight)
  }, [])

  return (
    <div className="relative">
      <pre
        ref={preRef}
        className="overflow-x-auto bg-white/5 p-3 font-mono text-[12px] leading-6 text-white/55 transition-all duration-300"
        style={{
          maxHeight: expanded ? "none" : "12rem",
          overflowY: expanded ? "auto" : "hidden"
        }}
        {...(html
          ? { dangerouslySetInnerHTML: { __html: html } }
          : { children: text })}
      />
      {isOverflowing && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="mt-2 w-full font-mono text-[11px] uppercase tracking-[0.15em] text-white/40 transition-colors hover:text-white/70"
          type="button"
        >
          {expanded ? "Show less ▲" : "Show more ▼"}
        </button>
      )}
    </div>
  )
}
