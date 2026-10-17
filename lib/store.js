// Local-only persistence helpers (history of runs, rule toggles and weights). Take a Storage-like object so they are testable.
// Nothing here ever stores the pasted configuration: only scores, counts and a short user-visible run name.
import { CATALOG, SEVERITY_WEIGHT } from '../engine.js'

export const HISTORY_KEY = 'asc.history.v2'
export const SETTINGS_KEY = 'asc.settings.v2'
export const HISTORY_MAX = 50
export const DEFAULT_SETTINGS = { disabled: [], weights: { ...SEVERITY_WEIGHT } }

const read = (st, key, dflt) => { try { const v = st && st.getItem(key); return v ? JSON.parse(v) : dflt } catch { return dflt } }
const write = (st, key, v) => { try { st.setItem(key, JSON.stringify(v)); return true } catch { return false } }

export function sanitizeSettings(o) {
  const out = { disabled: [], weights: { ...SEVERITY_WEIGHT } }
  if (!o || typeof o !== 'object') return out
  if (Array.isArray(o.disabled)) out.disabled = [...new Set(o.disabled.filter((x) => typeof x === 'string' && Object.prototype.hasOwnProperty.call(CATALOG, x)))]
  if (o.weights && typeof o.weights === 'object') for (const k of Object.keys(SEVERITY_WEIGHT)) { const v = Number(o.weights[k]); if (Number.isFinite(v)) out.weights[k] = Math.max(0, Math.min(50, Math.round(v))) }
  return out
}
export const loadSettings = (st) => sanitizeSettings(read(st, SETTINGS_KEY, null))
export const saveSettings = (st, s) => write(st, SETTINGS_KEY, sanitizeSettings(s))

export function entryFromReport(report, name, now = Date.now()) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const f of report.findings) counts[f.severity]++
  return { t: now, name: String(name || 'Untitled run').replace(/[\u0000-\u001f]/g, ' ').slice(0, 60), score: report.score, grade: report.grade, categories: report.categories, counts }
}
export function loadHistory(st) {
  const h = read(st, HISTORY_KEY, [])
  if (!Array.isArray(h)) return []
  return h.filter((e) => e && typeof e.score === 'number' && Number.isFinite(e.score) && typeof e.t === 'number').slice(-HISTORY_MAX)
    .map((e) => ({ t: e.t, name: String(e.name || '').slice(0, 60), score: Math.max(0, Math.min(100, Math.round(e.score))), grade: String(e.grade || '').slice(0, 1), categories: e.categories && typeof e.categories === 'object' ? e.categories : {}, counts: e.counts && typeof e.counts === 'object' ? e.counts : {} }))
}
export function addHistory(st, entry) { const h = loadHistory(st); h.push(entry); return write(st, HISTORY_KEY, h.slice(-HISTORY_MAX)) ? h.slice(-HISTORY_MAX) : h }
export const clearHistory = (st) => write(st, HISTORY_KEY, [])
export function trend(history) {
  if (history.length < 2) return { delta: 0, direction: 'flat', points: history.map((e) => e.score) }
  const delta = history[history.length - 1].score - history[history.length - 2].score
  return { delta, direction: delta > 0 ? 'up' : delta < 0 ? 'down' : 'flat', points: history.map((e) => e.score) }
}
