const FINAL_ADDR = "0x71C7...d93A"
const PLACEHOLDER = "0x0000...0000"
const HEX = "0123456789abcdefABCDEF"

// ── Timing configuration ──

const TIMING = {
  // SIGN (document / text / signature)
  signTextMs: 600,
  signSigMs: 500,
  signDelaysMs: [0, 80, 160, 240, 320],

  // LINE - three phases with explicit delays
  lineStartDelayMs: 200,
  lineSignToSendMs: 400,
  lineDelayAtSendMs: 250,
  lineSendToVerifyMs: 400,
  lineDelayAtVerifyMs: 1400,
  lineReturnMs: 600,

  // LINE SIGNATURE LABEL
  lineSigFadeMs: 150,

  // POST-RETURN
  holdMs: 2000,
  fadeOutMs: 500,
  cycleGapMs: 200,

  // PROCESS (plays during lineDelayAtSendMs)
  spinnerFadeMs: 150,
  processSpinMs: 2000,
  spinnerRps: 1,

  // VERIFY (plays during lineDelayAtVerifyMs)
  scrambleMs: 1200,
  verifyDrawMs: 300,
  verifySettleMs: 200,
  verifyPulseMs: 1000,
  verifyPulseFadeMs: 500,
  addrFadeInMs: 200,
  ensFadeInMs: 150,

  // SCRAMBLE animation mechanics
  scrambleTickMs: 70,
  staggerMs: 60,
  minCharResolveMs: 120,

  // MOBILE (per-step cycles)
  mobile: {
    signCycleMs: 3000,
    sendCycleMs: 1500,
    verifyCycleMs: 0,
    verifyStartDelayMs: 1000,
    scrambleMs: 1000,
    verifyHoldMs: 2000,
    fadeOutMs: 500
  }
}

// ── Timeline builder ──

function buildTimeline(timing: typeof TIMING) {
  const signTextEnd = timing.signTextMs
  const signEnd = signTextEnd + timing.signSigMs

  const lineStart = signEnd + timing.lineStartDelayMs
  const lineSigStart = lineStart
  const lineSigEnd = lineSigStart + timing.lineSigFadeMs
  const lineSendArrive = lineStart + timing.lineSignToSendMs

  const lineSendPauseEnd = lineSendArrive + timing.lineDelayAtSendMs
  const lineVerifyArrive = lineSendPauseEnd + timing.lineSendToVerifyMs
  const lineVerifyPauseEnd = lineVerifyArrive + timing.lineDelayAtVerifyMs

  const returnStart = lineVerifyPauseEnd
  const returnEnd = returnStart + timing.lineReturnMs
  const holdEnd = returnEnd + timing.holdMs
  const fadeOutStart = holdEnd
  const fadeOutEnd = fadeOutStart + timing.fadeOutMs
  const cycleMs = fadeOutEnd + timing.cycleGapMs

  const processStart = lineSendArrive
  const processFadeInEnd = processStart + timing.spinnerFadeMs
  const processSpinEnd = processFadeInEnd + timing.processSpinMs
  const processFadeOutEnd = processSpinEnd + timing.spinnerFadeMs

  const verifyStart = lineVerifyArrive
  const scrambleEnd = verifyStart + timing.scrambleMs
  const ensFadeInStart = scrambleEnd
  const ensFadeInEnd = ensFadeInStart + timing.ensFadeInMs
  const checkStart = ensFadeInStart
  const checkDrawEnd = checkStart + timing.verifyDrawMs
  const checkSettleEnd = checkDrawEnd + timing.verifySettleMs

  return {
    signTextEnd,
    signEnd,
    lineStart,
    lineSigStart,
    lineSigEnd,
    lineSendArrive,
    lineSendPauseEnd,
    lineVerifyArrive,
    lineVerifyPauseEnd,
    returnStart,
    returnEnd,
    holdEnd,
    fadeOutStart,
    fadeOutEnd,
    cycleMs,
    processStart,
    processFadeInEnd,
    processSpinEnd,
    processFadeOutEnd,
    verifyStart,
    scrambleEnd,
    ensFadeInStart,
    ensFadeInEnd,
    checkStart,
    checkDrawEnd,
    checkSettleEnd
  }
}

// ── Dynamic keyframe injection ──

function injectTimingStyles(
  timing: typeof TIMING,
  timeline: ReturnType<typeof buildTimeline>
) {
  const safeMs = (ms: number) => (Number.isFinite(ms) ? ms : 0)
  const pct = (ms: number) => {
    if (!Number.isFinite(timeline.cycleMs) || timeline.cycleMs <= 0) return 0
    return Math.min(100, Math.max(0, (safeMs(ms) / timeline.cycleMs) * 100))
  }
  const p = (ms: number) => `${pct(ms).toFixed(2)}%`
  const pm = (ms: number) => {
    if (!Number.isFinite(mobileVerifyCycleMs) || mobileVerifyCycleMs <= 0)
      return "0%"
    const value = Math.min(
      100,
      Math.max(0, (safeMs(ms) / mobileVerifyCycleMs) * 100)
    )
    return `${value.toFixed(2)}%`
  }
  const jumpPct = (ms: number, maxMs: number) =>
    `${Math.min(pct(ms) + 0.01, pct(maxMs)).toFixed(2)}%`
  const mobileVerifyStartDelay = timing.mobile.verifyStartDelayMs ?? 1000
  const mobileScrambleMs = timing.mobile.scrambleMs ?? timing.scrambleMs
  const mobileHoldMs = timing.mobile.verifyHoldMs ?? 2000
  const mobileFadeOutMs = timing.mobile.fadeOutMs ?? timing.fadeOutMs
  const mobileVerifyCycleMs =
    timing.mobile.verifyCycleMs ||
    mobileVerifyStartDelay +
      mobileScrambleMs +
      mobileHoldMs +
      mobileFadeOutMs +
      timing.cycleGapMs

  const sigStart = timeline.signTextEnd
  const sigEnd = timeline.signEnd

  const checkStart = timeline.checkStart
  const checkDrawEnd = timeline.checkDrawEnd
  const checkSettleEnd = timeline.checkSettleEnd
  const ringPeak = checkStart + timing.verifyPulseMs
  const ringEnd = ringPeak + timing.verifyPulseFadeMs
  const addrFadeInEnd = timeline.verifyStart + timing.addrFadeInMs
  const mobileScrambleStart = mobileVerifyStartDelay
  const mobileScrambleEnd = mobileScrambleStart + mobileScrambleMs
  const mobileEnsFadeInEnd = mobileScrambleEnd + timing.ensFadeInMs
  const mobileAddrFadeInEnd = mobileScrambleStart + timing.addrFadeInMs
  const mobileCheckStart = mobileScrambleEnd
  const mobileCheckDrawEnd = mobileCheckStart + timing.verifyDrawMs
  const mobileCheckSettleEnd = mobileCheckDrawEnd + timing.verifySettleMs
  const mobileFadeOutStart = mobileScrambleEnd + mobileHoldMs
  const mobileFadeOutEnd = mobileFadeOutStart + mobileFadeOutMs

  const styleText = `
#hiw-grid {
  --hiw-cycle: ${timeline.cycleMs}ms;
  --hiw-green: rgba(34, 197, 94, 0.95);
  --hiw-proc-spin-deg: ${(timing.processSpinMs / 1000) * timing.spinnerRps * 360}deg;
  --hiw-proc-spin-period: ${1000 / timing.spinnerRps}ms;
  --hiw-sign-delay-0: ${timing.signDelaysMs[0]}ms;
  --hiw-sign-delay-1: ${timing.signDelaysMs[1]}ms;
  --hiw-sign-delay-2: ${timing.signDelaysMs[2]}ms;
  --hiw-sign-delay-3: ${timing.signDelaysMs[3]}ms;
  --hiw-sign-delay-4: ${timing.signDelaysMs[4]}ms;
}

@media (max-width: 767px) {
  .hiw-step[data-step="sign"] { --hiw-cycle: ${timing.mobile.signCycleMs}ms; }
  .hiw-step[data-step="send"] { --hiw-cycle: ${timing.mobile.sendCycleMs}ms; }
  .hiw-step[data-step="verify"] { --hiw-cycle: ${mobileVerifyCycleMs}ms; }
}

@keyframes hiwSignFadeInHold {
  0% { opacity: 0; }
  ${p(timeline.signTextEnd)} { opacity: 0.55; }
  ${p(timeline.fadeOutStart)} { opacity: 0.55; }
  ${p(timeline.fadeOutEnd)} { opacity: 0; }
  100% { opacity: 0; }
}

@keyframes hiwDocOutline {
  0% { opacity: 0; stroke-dasharray: 1; stroke-dashoffset: 1; }
  ${p(timeline.signTextEnd)} { opacity: 0.35; stroke-dashoffset: 0; }
  ${p(timeline.fadeOutStart)} { opacity: 0.35; stroke-dashoffset: 0; }
  ${p(timeline.fadeOutEnd)} { opacity: 0; stroke-dashoffset: 0; }
  100% { opacity: 0; stroke-dashoffset: 0; }
}

@keyframes hiwSigDrawHold {
  0% { opacity: 0; stroke-dashoffset: 120; }
  ${p(sigStart)} { opacity: 0; stroke-dashoffset: 120; }
  ${jumpPct(sigStart, sigEnd)} { opacity: 1; stroke-dashoffset: 120; }
  ${p(sigEnd)} { opacity: 1; stroke-dashoffset: 0; }
  ${p(timeline.fadeOutStart)} { opacity: 1; stroke-dashoffset: 0; }
  ${p(timeline.fadeOutEnd)} { opacity: 0; stroke-dashoffset: 0; }
  100% { opacity: 0; stroke-dashoffset: 0; }
}

@keyframes hiwProcSpin {
  0% { opacity: 0; transform: rotate(0deg); }
  ${p(timeline.processStart)} { opacity: 0; transform: rotate(0deg); }
  ${p(timeline.processFadeInEnd)} { opacity: 1; transform: rotate(0deg); }
  ${p(timeline.processSpinEnd)} { opacity: 1; transform: rotate(var(--hiw-proc-spin-deg)); }
  ${p(timeline.processFadeOutEnd)} { opacity: 0; transform: rotate(var(--hiw-proc-spin-deg)); }
  100% { opacity: 0; transform: rotate(var(--hiw-proc-spin-deg)); }
}

@keyframes hiwCheckDraw {
  0% { opacity: 0; stroke-dashoffset: 60; transform: scale(1); }
  ${p(checkStart)} { opacity: 0; stroke-dashoffset: 60; transform: scale(1); }
  ${p(checkDrawEnd)} { opacity: 1; stroke-dashoffset: 0; transform: scale(1.06); }
  ${p(checkSettleEnd)} { opacity: 0.88; stroke-dashoffset: 0; transform: scale(1); }
  ${p(timeline.fadeOutStart)} { opacity: 0.88; stroke-dashoffset: 0; transform: scale(1); }
  ${p(timeline.fadeOutEnd)} { opacity: 0; stroke-dashoffset: 0; transform: scale(1); }
  100% { opacity: 0; stroke-dashoffset: 0; transform: scale(1); }
}

@keyframes hiwShieldGlow {
  0% { stroke: white; opacity: 0.3; }
  ${p(checkStart)} { stroke: white; opacity: 0.3; }
  ${p(checkDrawEnd)} { stroke: var(--hiw-green); opacity: 1; }
  ${p(timeline.fadeOutStart)} { stroke: var(--hiw-green); opacity: 1; }
  ${p(timeline.fadeOutEnd)} { stroke: white; opacity: 0.3; }
  100% { stroke: white; opacity: 0.3; }
}

@keyframes hiwVerifyRing {
  0% { opacity: 0; transform: scale(0.85); }
  ${p(checkStart)} { opacity: 0; transform: scale(0.85); }
  ${p(ringPeak)} { opacity: 0.12; transform: scale(1.02); }
  ${p(ringEnd)} { opacity: 0; transform: scale(1.12); }
  100% { opacity: 0; transform: scale(1.12); }
}

@keyframes hiwVerifyAddr {
  0% { opacity: 0.18; }
  ${p(timeline.verifyStart)} { opacity: 0.18; }
  ${p(addrFadeInEnd)} { opacity: 0.62; }
  ${p(timeline.scrambleEnd)} { opacity: 0.62; }
  ${p(timeline.lineVerifyPauseEnd)} { opacity: 0.65; }
  ${p(timeline.fadeOutStart)} { opacity: 0.65; }
  ${p(timeline.fadeOutEnd)} { opacity: 0.18; }
  100% { opacity: 0.18; }
}

@keyframes hiwVerifyPill {
  0% { opacity: 0.1; }
  ${p(timeline.verifyStart)} { opacity: 0.1; }
  ${p(addrFadeInEnd)} { opacity: 0.38; }
  ${p(timeline.scrambleEnd)} { opacity: 0.38; }
  ${p(timeline.lineVerifyPauseEnd)} { opacity: 0.4; }
  ${p(timeline.fadeOutStart)} { opacity: 0.4; }
  ${p(timeline.fadeOutEnd)} { opacity: 0.1; }
  100% { opacity: 0.1; }
}

@keyframes hiwVerifyEns {
  0% { opacity: 0; }
  ${p(timeline.ensFadeInStart)} { opacity: 0; }
  ${p(timeline.ensFadeInEnd)} { opacity: 0.6; }
  ${p(timeline.fadeOutStart)} { opacity: 0.6; }
  ${p(timeline.fadeOutEnd)} { opacity: 0; }
  100% { opacity: 0; }
}

@keyframes hiwVerifyAddrMobile {
  0% { opacity: 0.18; }
  ${pm(mobileVerifyStartDelay)} { opacity: 0.18; }
  ${pm(mobileAddrFadeInEnd)} { opacity: 1; }
  ${pm(mobileFadeOutStart)} { opacity: 1; }
  ${pm(mobileFadeOutEnd)} { opacity: 0.18; }
  100% { opacity: 0.18; }
}

@keyframes hiwVerifyPillMobile {
  0% { opacity: 0.1; }
  ${pm(mobileVerifyStartDelay)} { opacity: 0.1; }
  ${pm(mobileAddrFadeInEnd)} { opacity: 0.4; }
  ${pm(mobileFadeOutStart)} { opacity: 0.4; }
  ${pm(mobileFadeOutEnd)} { opacity: 0.1; }
  100% { opacity: 0.1; }
}

@keyframes hiwCheckMobile {
  0% { opacity: 0; stroke-dashoffset: 60; transform: scale(1); }
  ${pm(mobileCheckStart)} { opacity: 0; stroke-dashoffset: 60; transform: scale(1); }
  ${pm(mobileCheckDrawEnd)} { opacity: 1; stroke-dashoffset: 0; transform: scale(1.06); }
  ${pm(mobileCheckSettleEnd)} { opacity: 0.88; stroke-dashoffset: 0; transform: scale(1); }
  ${pm(mobileFadeOutStart)} { opacity: 0.88; stroke-dashoffset: 0; transform: scale(1); }
  ${pm(mobileFadeOutEnd)} { opacity: 0; stroke-dashoffset: 0; transform: scale(1); }
  100% { opacity: 0; stroke-dashoffset: 0; transform: scale(1); }
}

@keyframes hiwLineSig {
  0% { opacity: 0; }
  ${p(timeline.lineSigStart)} { opacity: 0; }
  ${p(timeline.lineSigEnd)} { opacity: 0.9; }
  ${p(timeline.fadeOutStart)} { opacity: 0.9; }
  ${p(timeline.fadeOutEnd)} { opacity: 0; }
  100% { opacity: 0; }
}

@keyframes hiwProcSpinMobile {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

@keyframes hiwEnsMobile {
  0% { opacity: 0; }
  ${pm(mobileScrambleEnd)} { opacity: 0; }
  ${pm(mobileEnsFadeInEnd)} { opacity: 0.6; }
  ${pm(mobileFadeOutStart)} { opacity: 0.6; }
  ${pm(mobileFadeOutEnd)} { opacity: 0; }
  100% { opacity: 0; }
}

@keyframes hiwShieldMobile {
  0% { stroke: white; opacity: 0.3; }
  ${pm(mobileScrambleEnd)} { stroke: white; opacity: 0.3; }
  ${pm(mobileEnsFadeInEnd)} { stroke: var(--hiw-green); opacity: 1; }
  ${pm(mobileFadeOutStart)} { stroke: var(--hiw-green); opacity: 1; }
  ${pm(mobileFadeOutEnd)} { stroke: white; opacity: 0.3; }
  100% { stroke: white; opacity: 0.3; }
}
      `.trim()

  let styleEl = document.getElementById(
    "hiw-timing-styles"
  ) as HTMLStyleElement | null
  if (!styleEl) {
    styleEl = document.createElement("style")
    styleEl.id = "hiw-timing-styles"
    document.head.appendChild(styleEl)
  }
  styleEl.textContent = styleText
}

// ── Verify address scramble animator ──

function clamp(v: number, lo = 0, hi = 1) {
  return Math.max(lo, Math.min(hi, v))
}

function isStaticChar(ch: string, index: number) {
  return (
    ch === "." ||
    ch === "\u2026" ||
    (ch === "x" && index === 1) ||
    (ch === "0" && index === 0)
  )
}

function supportsReducedMotion() {
  return (
    window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ?? false
  )
}

function createVerifyAnimator(verifyStep: HTMLElement) {
  const addrText = verifyStep.querySelector<SVGTextElement>("#hiw-addr-text")
  const addrPill = verifyStep.querySelector<SVGRectElement>("#hiw-addr-pill")
  if (!addrText || !addrPill) return null

  let scrambleInterval: number | null = null
  let timers: number[] = []
  let animationBound = false
  let currentStartDelay = 0
  let currentFadeOutDelay = 0
  let onAnimTick: (() => void) | null = null
  let fallbackTimer: number | null = null

  const setPlaceholder = () => {
    addrText.textContent = PLACEHOLDER
  }

  const setFinal = () => {
    addrText.textContent = FINAL_ADDR
  }

  const clearTimers = () => {
    timers.forEach((t) => {
      clearTimeout(t)
    })
    timers = []
    if (fallbackTimer !== null) {
      clearTimeout(fallbackTimer)
      fallbackTimer = null
    }
    if (scrambleInterval !== null) {
      clearInterval(scrambleInterval)
      scrambleInterval = null
    }
  }

  const runCycle = (
    startDelay: number,
    _cycleMs: number,
    fadeOutDelay: number,
    scrambleMs: number
  ) => {
    clearTimers()
    if (!verifyStep.classList.contains("hiw-active")) return

    currentStartDelay = Math.max(0, startDelay)
    currentFadeOutDelay = Math.max(currentStartDelay, fadeOutDelay)
    const activeScrambleMs = Math.max(0, scrambleMs)

    const startOnce = () => {
      clearTimers()
      if (!verifyStep.classList.contains("hiw-active")) return
      setPlaceholder()
      const startTimer = window.setTimeout(() => {
        const start = performance.now()
        scrambleInterval = window.setInterval(() => {
          const t = performance.now() - start
          const tick = Math.floor(t / TIMING.scrambleTickMs)
          const chars = FINAL_ADDR.split("")
          const perCharDelay = Math.min(
            TIMING.staggerMs,
            activeScrambleMs / Math.max(1, chars.length - 1)
          )
          const perCharDuration = Math.max(
            TIMING.minCharResolveMs,
            activeScrambleMs - perCharDelay * (chars.length - 1)
          )
          const totalDuration = activeScrambleMs
          const output = chars
            .map((ch, i) => {
              if (isStaticChar(ch, i)) return ch
              const local = clamp((t - i * perCharDelay) / perCharDuration)
              if (local >= 1) return ch
              return HEX[(i * 13 + tick * 7) % HEX.length]
            })
            .join("")
          addrText.textContent = output
          if (t >= totalDuration) {
            if (scrambleInterval !== null) {
              clearInterval(scrambleInterval)
              scrambleInterval = null
            }
            setFinal()
          }
        }, TIMING.scrambleTickMs)
      }, currentStartDelay)

      const fadeOutTimer = window.setTimeout(() => {
        setPlaceholder()
      }, currentFadeOutDelay)

      timers.push(startTimer, fadeOutTimer)
    }

    if (!animationBound) {
      onAnimTick = () => {
        if (fallbackTimer !== null) {
          clearTimeout(fallbackTimer)
          fallbackTimer = null
        }
        startOnce()
      }
      addrText.addEventListener("animationstart", onAnimTick)
      addrText.addEventListener("animationiteration", onAnimTick)
      animationBound = true
    }

    fallbackTimer = window.setTimeout(startOnce, 50)
  }

  const stop = () => {
    clearTimers()
    if (animationBound && onAnimTick) {
      addrText.removeEventListener("animationstart", onAnimTick)
      addrText.removeEventListener("animationiteration", onAnimTick)
      animationBound = false
      onAnimTick = null
    }
  }

  return { runCycle, stop, setFinal }
}

// ── Initialization ──

function init() {
  const grid = document.getElementById("hiw-grid")
  if (!grid) return

  const steps = Array.from(grid.querySelectorAll(".hiw-step"))
  const lineFill = grid.querySelector<SVGLineElement>("#hiw-line-fill")
  const lineReturn = grid.querySelector<SVGLineElement>("#hiw-line-return")
  const isMobile = window.matchMedia?.("(max-width: 767px)")?.matches ?? false
  let timeline = buildTimeline(TIMING)
  injectTimingStyles(TIMING, timeline)
  const mobileVerifyStartDelayMs = TIMING.mobile.verifyStartDelayMs ?? 1000
  const mobileScrambleMs = TIMING.mobile.scrambleMs ?? TIMING.scrambleMs
  const mobileHoldMs = TIMING.mobile.verifyHoldMs ?? 2000
  const mobileFadeOutMs = TIMING.mobile.fadeOutMs ?? TIMING.fadeOutMs
  const mobileVerifyCycleMs =
    TIMING.mobile.verifyCycleMs ||
    mobileVerifyStartDelayMs +
      mobileScrambleMs +
      mobileHoldMs +
      mobileFadeOutMs +
      TIMING.cycleGapMs

  const cycleMs = isMobile ? mobileVerifyCycleMs : timeline.cycleMs
  const verifyDelayMs = isMobile
    ? mobileVerifyStartDelayMs
    : timeline.verifyStart
  const verifyFadeOutDelayMs = isMobile
    ? mobileVerifyStartDelayMs +
      mobileScrambleMs +
      mobileHoldMs +
      mobileFadeOutMs
    : Math.max(0, timeline.fadeOutEnd)
  const reduceMotion = supportsReducedMotion()

  const verifyStep = steps.find(
    (s) => s.getAttribute("data-step") === "verify"
  ) as HTMLElement | undefined
  const verifyAnimator = verifyStep ? createVerifyAnimator(verifyStep) : null

  if (reduceMotion) {
    if (verifyAnimator) verifyAnimator.setFinal()
    return
  }

  // ── Connection line animations (desktop) ──

  let lineAnimation: Animation | null = null
  let lineReturnAnimation: Animation | null = null

  const startLine = () => {
    if (!lineFill) return
    if (lineAnimation) lineAnimation.cancel()
    if (lineReturnAnimation) lineReturnAnimation.cancel()
    timeline = buildTimeline(TIMING)
    injectTimingStyles(TIMING, timeline)
    if (!Number.isFinite(timeline.cycleMs) || timeline.cycleMs <= 0) return

    const cycleMs = timeline.cycleMs
    const toOffset = (ms: number) => Math.max(0, Math.min(1, ms / cycleMs))

    const lineStart = toOffset(timeline.lineStart)
    const lineSendArrive = toOffset(timeline.lineSendArrive)
    const lineSendPauseEnd = toOffset(timeline.lineSendPauseEnd)
    const lineVerifyArrive = toOffset(timeline.lineVerifyArrive)
    const lineVerifyPauseEnd = toOffset(timeline.lineVerifyPauseEnd)
    const returnStart = toOffset(timeline.returnStart)
    const returnEnd = toOffset(timeline.returnEnd)
    const holdEnd = toOffset(timeline.holdEnd)
    const fadeOutEnd = toOffset(timeline.fadeOutEnd)

    // Purple line: sign -> send -> verify
    lineAnimation = lineFill.animate(
      [
        { strokeDashoffset: 1, opacity: 0, offset: 0 },
        { strokeDashoffset: 1, opacity: 0, offset: lineStart },
        { strokeDashoffset: 0.5, opacity: 1, offset: lineSendArrive },
        { strokeDashoffset: 0.5, opacity: 1, offset: lineSendPauseEnd },
        { strokeDashoffset: 0, opacity: 1, offset: lineVerifyArrive },
        { strokeDashoffset: 0, opacity: 1, offset: lineVerifyPauseEnd },
        { strokeDashoffset: 0, opacity: 1, offset: holdEnd },
        { strokeDashoffset: 0, opacity: 0, offset: fadeOutEnd },
        { strokeDashoffset: 0, opacity: 0, offset: 1 }
      ],
      { duration: cycleMs, iterations: Infinity, easing: "linear" }
    )

    // Green return line: verify -> send
    if (lineReturn) {
      lineReturnAnimation = lineReturn.animate(
        [
          { strokeDashoffset: 1, opacity: 0, offset: 0 },
          { strokeDashoffset: 1, opacity: 0, offset: returnStart },
          { strokeDashoffset: 0, opacity: 1, offset: returnEnd },
          { strokeDashoffset: 0, opacity: 1, offset: holdEnd },
          { strokeDashoffset: 0, opacity: 0, offset: fadeOutEnd },
          { strokeDashoffset: 0, opacity: 0, offset: 1 }
        ],
        { duration: cycleMs, iterations: Infinity, easing: "linear" }
      )
    }
  }

  const stopLine = () => {
    if (lineAnimation) {
      lineAnimation.cancel()
      lineAnimation = null
    }
    if (lineReturnAnimation) {
      lineReturnAnimation.cancel()
      lineReturnAnimation = null
    }
  }

  // ── Intersection observer setup ──

  if (!("IntersectionObserver" in window)) {
    steps.forEach((s) => {
      s.classList.add("hiw-active")
    })
    grid.classList.add("hiw-grid-active")
    startLine()
    if (verifyAnimator) {
      const scrambleMs = isMobile ? mobileScrambleMs : TIMING.scrambleMs
      verifyAnimator.runCycle(
        verifyDelayMs,
        cycleMs,
        verifyFadeOutDelayMs,
        scrambleMs
      )
    }
    return
  }

  if (isMobile) {
    const stepObserver = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          const el = e.target as HTMLElement
          if (e.isIntersecting) {
            el.classList.add("hiw-active")
            if (verifyAnimator && el === verifyStep) {
              const scrambleMs = isMobile ? mobileScrambleMs : TIMING.scrambleMs
              verifyAnimator.runCycle(
                verifyDelayMs,
                cycleMs,
                verifyFadeOutDelayMs,
                scrambleMs
              )
            }
          } else {
            el.classList.remove("hiw-active")
            if (verifyAnimator && el === verifyStep) verifyAnimator.stop()
          }
        })
      },
      { threshold: 0.25 }
    )

    steps.forEach((s) => {
      stepObserver.observe(s)
    })
    return
  }

  // Desktop: full sequence when grid enters viewport
  const gridObserver = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          grid.classList.add("hiw-grid-active")
          steps.forEach((s) => {
            s.classList.add("hiw-active")
          })
          startLine()
          if (verifyAnimator) {
            const scrambleMs = isMobile ? mobileScrambleMs : TIMING.scrambleMs
            verifyAnimator.runCycle(
              verifyDelayMs,
              cycleMs,
              verifyFadeOutDelayMs,
              scrambleMs
            )
          }
        } else {
          grid.classList.remove("hiw-grid-active")
          steps.forEach((s) => {
            s.classList.remove("hiw-active")
          })
          stopLine()
          if (verifyAnimator) verifyAnimator.stop()
        }
      })
    },
    { threshold: 0.25 }
  )

  gridObserver.observe(grid)
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init)
} else {
  init()
}
