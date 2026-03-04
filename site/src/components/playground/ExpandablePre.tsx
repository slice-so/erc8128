interface ExpandablePreProps {
  html?: string
  text?: string
}

export function ExpandablePre({ html, text }: ExpandablePreProps) {
  return (
    <pre
      className="max-h-52 overflow-auto bg-white/5 p-3 font-mono text-[12px] leading-6 text-white/55"
      {...(html
        ? { dangerouslySetInnerHTML: { __html: html } }
        : { children: text })}
    />
  )
}
