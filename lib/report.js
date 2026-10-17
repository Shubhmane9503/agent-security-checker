// Report exports (JSON, SARIF 2.1.0, standalone HTML, badge SVG) and report comparison. Pure functions, all output escaped.
import { CATEGORIES, CATALOG, OWASP, ATLAS, SEVERITY_ORDER, SEVERITY_WEIGHT, ENGINE_VERSION, MATRIX_COLUMNS } from '../engine.js'

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))

export function reportToJson(report) {
  // The report never contains the pasted config; evidence is masked by the engine.
  return JSON.stringify({ tool: 'agent-security-checker', engine: report.engine || ENGINE_VERSION, score: report.score, grade: report.grade, categories: report.categories, summary: report.summary, trifecta: report.trifecta || null, findings: report.findings.map((f) => ({ id: f.id, severity: f.severity, category: f.cat, title: f.title, detail: f.detail, evidence: f.evidence, owasp: f.owasp, atlas: f.atlas, fix: f.fix })), matrix: report.matrix || [], ...(report.customized ? { customized: true, disabledRules: report.disabled || [] } : {}) }, null, 2)
}

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' }
const SECURITY_SEVERITY = { critical: '9.5', high: '8.0', medium: '5.5', low: '2.0' }

export function reportToSarif(report, { uri = 'agent-config.json' } = {}) {
  const ids = [...new Set(report.findings.map((f) => f.id))]
  const rules = ids.map((id) => {
    const c = CATALOG[id]
    const worst = report.findings.filter((f) => f.id === id).map((f) => f.severity).sort((a, b) => SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b))[0]
    return {
      id, name: c.title.replace(/[^A-Za-z0-9]+/g, ' ').trim().split(' ').map((w) => w[0].toUpperCase() + w.slice(1)).join(''),
      shortDescription: { text: c.title }, fullDescription: { text: c.why }, help: { text: c.fix, markdown: `**Fix:** ${c.fix}\n\n**Why:** ${c.why}` },
      defaultConfiguration: { level: SARIF_LEVEL[worst] },
      properties: { tags: ['security', 'llm-agent', ...(c.owasp || []).map((o) => `OWASP-${o}`), ...(c.atlas || [])], 'security-severity': SECURITY_SEVERITY[worst], category: c.cat },
    }
  })
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'agent-security-checker', version: report.engine || ENGINE_VERSION, informationUri: 'https://github.com/Shubhmane9503/agent-security-checker', rules } },
      results: report.findings.map((f) => ({
        ruleId: f.id, ruleIndex: ids.indexOf(f.id), level: SARIF_LEVEL[f.severity],
        message: { text: f.detail + (f.evidence ? ` Evidence (masked): ${f.evidence}` : '') },
        locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 1 } } }],
        properties: { severity: f.severity },
      })),
      properties: { score: report.score, grade: report.grade },
    }],
  }, null, 2)
}

export function badgeColor(score) { return score >= 90 ? '#1a7f37' : score >= 75 ? '#2f7d32' : score >= 60 ? '#9a6700' : score >= 40 ? '#bc4c00' : '#cf222e' }

export function badgeSvg(score, grade, label = 'agent security') {
  const value = `${score}/100 ${grade}`
  const w = (t) => Math.round(t.length * 6.4 + 12)
  const lw = w(label), vw = w(value), total = lw + vw
  const color = badgeColor(score)
  const title = `${label}: ${value}`
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="${esc(title)}"><title>${esc(title)}</title>` +
    `<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#fff" stop-opacity=".12"/><stop offset="1" stop-opacity=".12"/></linearGradient>` +
    `<clipPath id="r"><rect width="${total}" height="20" rx="3" fill="#fff"/></clipPath>` +
    `<g clip-path="url(#r)"><rect width="${lw}" height="20" fill="#3d444d"/><rect x="${lw}" width="${vw}" height="20" fill="${color}"/><rect width="${total}" height="20" fill="url(#s)"/></g>` +
    `<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11"><text x="${lw / 2}" y="14">${esc(label)}</text><text x="${lw + vw / 2}" y="14">${esc(value)}</text></g></svg>`
}

export function compareReports(a, b) {
  const key = (f) => `${f.id}|${f.detail}`
  const ka = new Map(a.findings.map((f) => [key(f), f])), kb = new Map(b.findings.map((f) => [key(f), f]))
  return {
    delta: b.score - a.score,
    categories: Object.keys(CATEGORIES).map((k) => ({ key: k, label: CATEGORIES[k], a: a.categories[k], b: b.categories[k], delta: b.categories[k] - a.categories[k] })),
    fixed: [...ka.entries()].filter(([k]) => !kb.has(k)).map(([, f]) => f),
    added: [...kb.entries()].filter(([k]) => !ka.has(k)).map(([, f]) => f),
    unchanged: [...kb.entries()].filter(([k]) => ka.has(k)).map(([, f]) => f),
  }
}

const SEV_COLOR = { critical: '#b42318', high: '#b54708', medium: '#8a6a00', low: '#475467' }
export function reportToHtml(report, title = 'Agent security report') {
  const cats = Object.entries(CATEGORIES).map(([k, v]) => `<tr><td>${esc(v)}</td><td>${report.categories[k]}/100</td></tr>`).join('')
  const finds = report.findings.map((f) => {
    const tags = [...(f.owasp || []).map((o) => `OWASP ${o} ${OWASP[o] || ''}`), ...(f.atlas || []).map((a) => `${a} ${ATLAS[a] || ''}`)]
    return `<section class="f"><h3><span class="sev" style="color:${SEV_COLOR[f.severity]}">${esc(f.severity.toUpperCase())}</span> ${esc(f.id)} ${esc(f.title)}</h3><p>${esc(f.detail)}${f.evidence ? ` Evidence (masked): <code>${esc(f.evidence)}</code>` : ''}</p>${tags.length ? `<p class="tags">${tags.map((t) => `<span>${esc(t)}</span>`).join(' ')}</p>` : ''}<p><b>Fix:</b> ${esc(f.fix)}</p></section>`
  }).join('') || '<p>No findings from the rule set. That does not prove the agent is safe.</p>'
  const mat = (report.matrix || []).length ? `<h2>Tool permission matrix</h2><table><tr><th>Tool</th>${MATRIX_COLUMNS.map(([, l]) => `<th>${esc(l)}</th>`).join('')}<th>Confirm</th><th>Scoped</th><th>Risk</th></tr>${report.matrix.map((m) => `<tr><td>${esc(m.name)}</td>${MATRIX_COLUMNS.map(([k]) => `<td>${m.kinds.includes(k) ? '●' : ''}</td>`).join('')}<td>${m.confirmed === null ? '–' : m.confirmed ? 'yes' : 'no'}</td><td>${m.scoped === null ? '–' : m.scoped ? 'yes' : 'no'}</td><td>${esc(m.risk)}</td></tr>`).join('')}</table>` : ''
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>
body{font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;max-width:860px;margin:24px auto;padding:0 16px;color:#101828}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin-top:28px}h3{font-size:15px;margin:0 0 4px}
.score{font-size:44px;font-weight:700}table{border-collapse:collapse;width:100%;margin:8px 0}td,th{border:1px solid #d0d5dd;padding:4px 8px;text-align:left;font-size:13px}
.f{border:1px solid #d0d5dd;border-radius:8px;padding:10px 12px;margin:10px 0;break-inside:avoid}.tags span{display:inline-block;background:#f2f4f7;border-radius:10px;padding:1px 8px;font-size:12px;margin-right:4px}
code{background:#f2f4f7;padding:1px 4px;border-radius:4px}.note{color:#475467;font-size:12px}
@media print{body{margin:0}a{color:inherit}}</style></head><body>
<h1>${esc(title)}</h1><div class="score">${report.score}/100 <small>grade ${esc(report.grade)}</small></div>
<table>${cats}</table>${report.trifecta && report.trifecta.complete ? `<p><b>Lethal trifecta:</b> private data, untrusted content and an outbound channel are all present${report.trifecta.gated ? ' (outbound channel is gated).' : ' and the outbound channel is not gated.'}</p>` : ''}
<h2>Findings (${report.findings.length})</h2>${finds}${mat}
<p class="note">Static pattern review of configuration text. It cannot observe real model behaviour, and a high score does not prove an agent is safe. Generated by agent-security-checker ${esc(report.engine || ENGINE_VERSION)}.</p></body></html>`
}

export const SEVERITY_WEIGHT_DEFAULTS = SEVERITY_WEIGHT
