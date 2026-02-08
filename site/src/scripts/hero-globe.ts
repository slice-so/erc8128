const canvas = document.getElementById("dots") as HTMLCanvasElement
const ctx = canvas.getContext("2d")

let width = 0
let height = 0
let dpr = 1
let angleX = 0.3
let angleY = 0
let targetAngleX = -0.2
let targetAngleY = 0
let autoRotateY = 0
let isDragging = false
let lastMouseX = 0
let lastMouseY = 0
let mouseX = -9999
let mouseY = -9999
let velocityX = 0
let velocityY = 0

function resize() {
  const parent = canvas.parentElement
  if (!parent || !ctx) return
  width = parent.offsetWidth
  height = parent.offsetHeight
  dpr = window.devicePixelRatio || 1
  canvas.width = width * dpr
  canvas.height = height * dpr
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
}

// ── Sphere geometry ──

const LINE_COLOR = "192, 155, 255"
const FADE_OUT_MS = 500
const EDGE_DRAW_MS = 150
const HORIZONTAL_DENSITY = 3
const LATITUDE_STEPS = 18
const LONGITUDE_BASE = 12
const K_NEIGHBORS = 6
const ROW_DENSITY_EXPONENT = 1

const spherePoints: { x: number; y: number; z: number }[] = []
const poleIndexSet = new Set<number>()

const longitudeCount = Math.max(
  12,
  Math.round(LONGITUDE_BASE * HORIZONTAL_DENSITY)
)

// Explicit poles
poleIndexSet.add(spherePoints.length)
spherePoints.push({ x: 0, y: 1, z: 0 })
poleIndexSet.add(spherePoints.length)
spherePoints.push({ x: 0, y: -1, z: 0 })

for (let i = 1; i < LATITUDE_STEPS - 1; i++) {
  const v = i / (LATITUDE_STEPS - 1)
  const y = Math.cos(Math.PI * v)
  const radius = Math.sqrt(1 - y * y)
  const rowOffset = (i % 2) * 0.5
  const rowLongitudes = Math.max(
    6,
    Math.round(longitudeCount * radius ** ROW_DENSITY_EXPONENT)
  )

  for (let j = 0; j < rowLongitudes; j++) {
    const theta = ((j + rowOffset) / rowLongitudes) * Math.PI * 2
    spherePoints.push({
      x: Math.cos(theta) * radius,
      y: y,
      z: Math.sin(theta) * radius
    })
  }
}

// ── Build adjacency graph ──

const NUM_POINTS = spherePoints.length
const pairSet = new Set<string>()
for (let i = 0; i < NUM_POINTS; i++) {
  const distances: { idx: number; dist: number }[] = []
  for (let j = 0; j < NUM_POINTS; j++) {
    if (i === j) continue
    const dx = spherePoints[i].x - spherePoints[j].x
    const dy = spherePoints[i].y - spherePoints[j].y
    const dz = spherePoints[i].z - spherePoints[j].z
    distances.push({ idx: j, dist: Math.sqrt(dx * dx + dy * dy + dz * dz) })
  }
  distances.sort((a, b) => a.dist - b.dist)
  for (let k = 0; k < Math.min(K_NEIGHBORS, distances.length); k++) {
    const j = distances[k].idx
    const a = Math.min(i, j)
    const b = Math.max(i, j)
    pairSet.add(`${a}-${b}`)
  }
}

const pairs: [number, number][] = Array.from(pairSet, (key) => {
  const [a, b] = key.split("-").map(Number)
  return [a, b]
})

const adjacency: number[][] = Array.from({ length: NUM_POINTS }, () => [])
const pairByEdge = new Map<string, number>()
for (let pIdx = 0; pIdx < pairs.length; pIdx++) {
  const [i, j] = pairs[pIdx]
  adjacency[i].push(j)
  adjacency[j].push(i)
  pairByEdge.set(`${i}-${j}`, pIdx)
  pairByEdge.set(`${j}-${i}`, pIdx)
}

// ── Traveling signals ──

interface TravelingSignal {
  path: number[]
  edgeIndices: number[]
  currentEdge: number
  t: number
  opacity: number
  isFading: boolean
  fadeStart: number
  fade: number
}

const signals: TravelingSignal[] = []
const MAX_SIGNALS = 15

function findRandomPath(minHops: number, maxHops: number): number[] | null {
  const start = Math.floor(Math.random() * NUM_POINTS)
  const path = [start]
  const visited = new Set([start])
  let current = start

  const targetHops =
    minHops + Math.floor(Math.random() * (maxHops - minHops + 1))

  for (let step = 0; step < targetHops; step++) {
    const neighbors = adjacency[current].filter((n) => !visited.has(n))
    if (neighbors.length === 0) break
    const next = neighbors[Math.floor(Math.random() * neighbors.length)]
    path.push(next)
    visited.add(next)
    current = next
  }

  return path.length >= minHops + 1 ? path : null
}

function spawnSignal() {
  if (signals.length >= MAX_SIGNALS) return

  const path = findRandomPath(2, 4)
  if (!path) return

  const edgeIndices: number[] = []
  for (let i = 0; i < path.length - 1; i++) {
    const key = `${path[i]}-${path[i + 1]}`
    const altKey = `${path[i + 1]}-${path[i]}`
    const pIdx = pairByEdge.get(key) ?? pairByEdge.get(altKey)
    if (pIdx === undefined) return
    edgeIndices.push(pIdx)
  }

  signals.push({
    path,
    edgeIndices,
    currentEdge: 0,
    t: 0,
    opacity: 0.45 + Math.random() * 0.2,
    isFading: false,
    fadeStart: -1,
    fade: 1
  })
}

// Seed initial signals
for (let i = 0; i < 7; i++) {
  spawnSignal()
  if (signals.length > 0) {
    const s = signals[signals.length - 1]
    const advanceEdges = Math.floor(
      Math.random() * Math.min(3, s.edgeIndices.length)
    )
    s.currentEdge = advanceEdges
    s.t = Math.random()
  }
}

interface EdgeGlow {
  intensity: number
  progress: number
  fromNode: number
  toNode: number
}

const edgeGlowMap = new Map<number, EdgeGlow>()

// ── Input handling ──

const heroGlobe = canvas.parentElement
if (heroGlobe) {
  heroGlobe.addEventListener("mousedown", (e) => {
    isDragging = true
    lastMouseX = e.clientX
    lastMouseY = e.clientY
    velocityX = 0
    velocityY = 0
  })

  window.addEventListener("mousemove", (e) => {
    const rect = heroGlobe.getBoundingClientRect()
    mouseX = e.clientX - rect.left
    mouseY = e.clientY - rect.top

    if (isDragging) {
      const dx = e.clientX - lastMouseX
      const dy = e.clientY - lastMouseY
      velocityY = -dx * 0.005
      velocityX = -dy * 0.005
      targetAngleY -= dx * 0.005
      targetAngleX -= dy * 0.005
      lastMouseX = e.clientX
      lastMouseY = e.clientY
    }
  })
  heroGlobe.addEventListener("mouseleave", () => {
    mouseX = -9999
    mouseY = -9999
  })

  heroGlobe.addEventListener(
    "touchstart",
    (e) => {
      isDragging = true
      const t = e.touches[0]
      lastMouseX = t.clientX
      lastMouseY = t.clientY
      velocityX = 0
      velocityY = 0
    },
    { passive: true }
  )

  heroGlobe.addEventListener(
    "touchmove",
    (e) => {
      const t = e.touches[0]
      const rect = heroGlobe.getBoundingClientRect()
      mouseX = t.clientX - rect.left
      mouseY = t.clientY - rect.top

      if (isDragging) {
        const dx = t.clientX - lastMouseX
        const dy = t.clientY - lastMouseY
        velocityY = -dx * 0.005
        velocityX = -dy * 0.005
        targetAngleY -= dx * 0.005
        targetAngleX -= dy * 0.005
        lastMouseX = t.clientX
        lastMouseY = t.clientY
      }
    },
    { passive: true }
  )

  heroGlobe.addEventListener("touchend", () => {
    isDragging = false
    mouseX = -9999
    mouseY = -9999
  })
}

window.addEventListener("mouseup", () => {
  isDragging = false
})

// ── Render loop ──

function easeOutCubic(t: number): number {
  return 1 - (1 - t) ** 3
}

let lastTime = 0
let isActive = true
let rafId = 0

function draw(time: number) {
  if (!isActive || !ctx) return
  const elapsedMs = lastTime ? time - lastTime : 16.67
  const dt = Math.min(elapsedMs / 16.67, 3)
  lastTime = time

  if (!width || !height) {
    rafId = requestAnimationFrame(draw)
    return
  }

  ctx.clearRect(0, 0, width, height)

  const cx = width / 2
  const cy = height / 2
  const sphereRadius = Math.min(width, height) * 0.38
  const cursorRadius = sphereRadius * 0.35

  // Auto-rotation and momentum
  if (!isDragging) {
    autoRotateY += 0.0015 * dt
    targetAngleY += velocityY * dt
    targetAngleX += velocityX * dt
    velocityX *= 0.96
    velocityY *= 0.96
  }

  angleX += (targetAngleX - angleX) * 0.1 * dt
  angleY += (targetAngleY - angleY) * 0.1 * dt

  const totalAngleY = angleY + autoRotateY
  const cosY = Math.cos(totalAngleY)
  const sinY = Math.sin(totalAngleY)
  const cosX = Math.cos(angleX)
  const sinX = Math.sin(angleX)

  // Project points
  const projected: { px: number; py: number; z: number; idx: number }[] = []

  for (let i = 0; i < spherePoints.length; i++) {
    const p = spherePoints[i]
    const x1 = p.x * cosY - p.z * sinY
    const z1 = p.x * sinY + p.z * cosY
    const y1 = p.y
    const y2 = y1 * cosX - z1 * sinX
    const z2 = y1 * sinX + z1 * cosX

    projected.push({
      px: cx + x1 * sphereRadius,
      py: cy + y2 * sphereRadius,
      z: z2,
      idx: i
    })
  }

  // Update signals
  edgeGlowMap.clear()

  for (let si = signals.length - 1; si >= 0; si--) {
    const sig = signals[si]
    if (sig.isFading) {
      if (sig.fadeStart < 0) sig.fadeStart = time
      const fadeT = Math.min((time - sig.fadeStart) / FADE_OUT_MS, 1)
      sig.fade = 1 - easeOutCubic(fadeT)
      if (fadeT >= 1) {
        signals.splice(si, 1)
        continue
      }
    } else {
      sig.t += elapsedMs / EDGE_DRAW_MS
    }

    while (
      !sig.isFading &&
      sig.t >= 1 &&
      sig.currentEdge < sig.edgeIndices.length - 1
    ) {
      sig.t -= 1
      sig.currentEdge++
    }

    if (
      !sig.isFading &&
      sig.t >= 1 &&
      sig.currentEdge >= sig.edgeIndices.length - 1
    ) {
      sig.isFading = true
      sig.fadeStart = time
      sig.fade = 1
      sig.t = 1
      sig.currentEdge = sig.edgeIndices.length - 1
    }

    const maxEdge = sig.isFading ? sig.edgeIndices.length - 1 : sig.currentEdge
    for (let edgeIdx = 0; edgeIdx <= maxEdge; edgeIdx++) {
      const pairIdx = sig.edgeIndices[edgeIdx]
      const isCurrent = edgeIdx === sig.currentEdge && !sig.isFading
      const progress = isCurrent ? easeOutCubic(Math.min(sig.t, 1)) : 1
      const age = maxEdge - edgeIdx
      const ageFalloff = 1 - age / Math.max(1, sig.edgeIndices.length - 1)
      const intensity = sig.opacity * sig.fade * (0.5 + 0.5 * ageFalloff)

      const existing = edgeGlowMap.get(pairIdx)
      if (!existing || existing.intensity < intensity) {
        edgeGlowMap.set(pairIdx, {
          intensity,
          progress,
          fromNode: sig.path[edgeIdx],
          toNode: sig.path[edgeIdx + 1]
        })
      }
    }
  }

  if (Math.random() < 0.07 * dt) spawnSignal()

  // Draw edges
  for (let pIdx = 0; pIdx < pairs.length; pIdx++) {
    const [i, j] = pairs[pIdx]
    const a = projected[i]
    const b = projected[j]

    const avgZ = (a.z + b.z) / 2
    const depthFactor = (avgZ + 1) / 2

    const baseOpacity = 0.02 + depthFactor * 0.05

    let cursorBoost = 0
    const midX = (a.px + b.px) / 2
    const midY = (a.py + b.py) / 2
    const distToCursor = Math.sqrt((midX - mouseX) ** 2 + (midY - mouseY) ** 2)
    if (distToCursor < cursorRadius) {
      cursorBoost = (1 - distToCursor / cursorRadius) * 0.07
    }

    const glow = edgeGlowMap.get(pIdx)

    if (glow && glow.intensity > 0.01) {
      const dimOpacity = Math.min(baseOpacity + cursorBoost, 0.18)
      ctx.strokeStyle = `rgba(${LINE_COLOR}, ${dimOpacity})`
      ctx.lineWidth = 0.4 + depthFactor * 0.4
      ctx.beginPath()
      ctx.moveTo(a.px, a.py)
      ctx.lineTo(b.px, b.py)
      ctx.stroke()

      const fromPt = projected[glow.fromNode] || a
      const toPt = projected[glow.toNode] || b
      const drawX = fromPt.px + (toPt.px - fromPt.px) * glow.progress
      const drawY = fromPt.py + (toPt.py - fromPt.py) * glow.progress

      const glowIntensity = glow.intensity * depthFactor
      const grad = ctx.createLinearGradient(fromPt.px, fromPt.py, drawX, drawY)
      grad.addColorStop(0, `rgba(${LINE_COLOR}, ${glowIntensity * 0.35})`)
      grad.addColorStop(1, `rgba(${LINE_COLOR}, ${glowIntensity})`)

      ctx.strokeStyle = grad
      ctx.lineWidth = 0.8 + depthFactor * 0.8
      ctx.beginPath()
      ctx.moveTo(fromPt.px, fromPt.py)
      ctx.lineTo(drawX, drawY)
      ctx.stroke()
    } else {
      const finalOpacity = Math.min(baseOpacity + cursorBoost, 0.18)
      ctx.strokeStyle = `rgba(${LINE_COLOR}, ${finalOpacity})`
      ctx.lineWidth = 0.4 + depthFactor * 0.4
      ctx.beginPath()
      ctx.moveTo(a.px, a.py)
      ctx.lineTo(b.px, b.py)
      ctx.stroke()
    }
  }

  // Draw dots
  const sortedProjected = [...projected].sort((a, b) => a.z - b.z)

  for (const pt of sortedProjected) {
    const depthFactor = (pt.z + 1) / 2
    const isPole = poleIndexSet.has(pt.idx)
    let opacity = 0.12 + depthFactor * 0.55
    let dotSize = 0.8 + depthFactor * 1.5

    const distToCursor = Math.sqrt(
      (pt.px - mouseX) ** 2 + (pt.py - mouseY) ** 2
    )
    if (distToCursor < cursorRadius && !isPole) {
      const proximity = 1 - distToCursor / cursorRadius
      dotSize += proximity * 1.4
      opacity = Math.min(opacity + proximity * 0.2, 0.85)
    }

    if (isPole) {
      dotSize = 1.1 + depthFactor * 1.6
    }

    ctx.fillStyle = `rgba(255, 255, 255, ${opacity})`
    ctx.beginPath()
    ctx.arc(pt.px, pt.py, dotSize, 0, Math.PI * 2)
    ctx.fill()

    if (isPole) {
      const halo = ctx.createRadialGradient(
        pt.px,
        pt.py,
        0,
        pt.px,
        pt.py,
        dotSize * 2.4
      )
      halo.addColorStop(0, `rgba(255, 255, 255, ${opacity * 0.12})`)
      halo.addColorStop(1, "rgba(255, 255, 255, 0)")
      ctx.fillStyle = halo
      ctx.beginPath()
      ctx.arc(pt.px, pt.py, dotSize * 2.4, 0, Math.PI * 2)
      ctx.fill()
    }
  }

  rafId = requestAnimationFrame(draw)
}

// ── Visibility control ──

function startAnimation() {
  if (isActive) return
  isActive = true
  lastTime = 0
  rafId = requestAnimationFrame(draw)
}

function stopAnimation() {
  isActive = false
  if (rafId) cancelAnimationFrame(rafId)
}

const visibilityObserver = new IntersectionObserver(
  ([entry]) => {
    if (entry.isIntersecting) {
      startAnimation()
    } else {
      stopAnimation()
    }
  },
  { root: null, threshold: 0.1 }
)

if (heroGlobe) {
  visibilityObserver.observe(heroGlobe)
}

window.addEventListener("resize", resize)
setTimeout(() => {
  resize()
  rafId = requestAnimationFrame(draw)
}, 100)
