// Inline SVG chart builders (no libraries, no CDNs). All dynamic text is escaped; numbers are clamped.
import { CATEGORIES, CATEGORY_SHORT } from './meta.js'

const ce = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
const clamp = (v) => Math.max(0, Math.min(100, Number.isFinite(+v) ? +v : 0))
export const scoreClass = (s) => (s >= 90 ? 'good' : s >= 75 ? 'ok' : s >= 60 ? 'fair' : s >= 40 ? 'poor' : 'bad')

/** 270-degree animated gauge. The value arc starts at 0; the app sets data-value to animate it. */
export function gaugeSvg(score, grade, { size = 220, label = 'Security score' } = {}) {
  const r = 80, C = 2 * Math.PI * r, arc = C * 0.75
  const s = clamp(score)
  return `<svg class="gauge ${scoreClass(s)}" viewBox="0 0 200 200" width="${size}" height="${size}" role="img" aria-label="${ce(label)}: ${s} out of 100, grade ${ce(grade)}">` +
    `<defs><linearGradient id="gg" x1="0" y1="1" x2="1" y2="0"><stop offset="0" class="g0"/><stop offset="1" class="g1"/></linearGradient></defs>` +
    `<circle class="track" cx="100" cy="100" r="${r}" fill="none" stroke-width="14" stroke-linecap="round" stroke-dasharray="${arc.toFixed(2)} ${C.toFixed(2)}" transform="rotate(135 100 100)"/>` +
    `<circle class="val" cx="100" cy="100" r="${r}" fill="none" stroke-width="14" stroke-linecap="round" stroke="url(#gg)" stroke-dasharray="0 ${C.toFixed(2)}" data-arc="${arc.toFixed(2)}" data-c="${C.toFixed(2)}" data-value="${s}" transform="rotate(135 100 100)"/>` +
    `<text class="num" x="100" y="104" text-anchor="middle" data-target="${s}">${s}</text>` +
    `<text class="sub" x="100" y="128" text-anchor="middle">out of 100</text>` +
    `<text class="grade" x="100" y="166" text-anchor="middle">Grade ${ce(grade)}</text></svg>`
}

/** Radar chart over the category sub-scores (0-100). */
export function radarSvg(categories, { size = 320 } = {}) {
  const keys = Object.keys(CATEGORIES)
  const cx = 160, cy = 150, R = 100
  const pt = (i, v) => { const a = -Math.PI / 2 + (2 * Math.PI * i) / keys.length; return [cx + R * (v / 100) * Math.cos(a), cy + R * (v / 100) * Math.sin(a)] }
  const ring = (v) => keys.map((_, i) => pt(i, v).map((n) => n.toFixed(1)).join(',')).join(' ')
  const poly = keys.map((k, i) => pt(i, clamp(categories[k])).map((n) => n.toFixed(1)).join(',')).join(' ')
  const labels = keys.map((k, i) => { const [x, y] = pt(i, 122); const anchor = x < cx - 8 ? 'end' : x > cx + 8 ? 'start' : 'middle'; return `<text class="lbl" x="${x.toFixed(1)}" y="${(y + 4).toFixed(1)}" text-anchor="${anchor}">${ce(CATEGORY_SHORT[k])}</text>` }).join('')
  const axes = keys.map((_, i) => { const [x, y] = pt(i, 100); return `<line class="axis" x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}"/>` }).join('')
  const dots = keys.map((k, i) => { const [x, y] = pt(i, clamp(categories[k])); return `<circle class="dot" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="4"><title>${ce(CATEGORIES[k])}: ${clamp(categories[k])}/100</title></circle>` }).join('')
  return `<svg class="radar" viewBox="-50 0 420 300" width="${size}" height="${Math.round(size * 0.72)}" role="img" aria-label="Category radar chart. ${keys.map((k) => `${ce(CATEGORY_SHORT[k])} ${clamp(categories[k])}`).join(', ')}">` +
    [25, 50, 75, 100].map((v) => `<polygon class="ring" points="${ring(v)}"/>`).join('') + axes + `<polygon class="shape" points="${poly}"/>` + dots + labels + `</svg>`
}

export function sparklineSvg(points, { w = 260, h = 70 } = {}) {
  const p = points.map(clamp)
  if (!p.length) return ''
  const step = p.length > 1 ? (w - 16) / (p.length - 1) : 0
  const xy = p.map((v, i) => [8 + i * step, h - 8 - ((h - 16) * v) / 100])
  const line = xy.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ')
  const area = `8,${h - 8} ${line} ${(8 + (p.length - 1) * step).toFixed(1)},${h - 8}`
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" width="100%" height="${h}" role="img" aria-label="Score trend over ${p.length} runs: ${p.join(', ')}"><polygon class="area" points="${area}"/><polyline class="line" fill="none" points="${line}"/>${xy.map(([x, y], i) => `<circle class="pt" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3.5"><title>Run ${i + 1}: ${p[i]}</title></circle>`).join('')}</svg>`
}

/** Small horizontal bar for a category sub-score. */
export function barSvg(v, { w = 160 } = {}) {
  const s = clamp(v)
  return `<svg class="bar ${scoreClass(s)}" viewBox="0 0 ${w} 8" width="${w}" height="8" aria-hidden="true"><rect class="bg" width="${w}" height="8" rx="4"/><rect class="fg" width="${((w * s) / 100).toFixed(1)}" height="8" rx="4"/></svg>`
}
