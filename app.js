// AI Agent Security Checker v2: UI. Plain ES module, no build, no network. All dynamic output goes through esc().
import { analyze, CATEGORIES, CATALOG, OWASP, ATLAS, SEVERITY_ORDER, SEVERITY_WEIGHT, encodeReport, decodeReport, reportToMarkdown, MAX_INPUT_CHARS, MATRIX_COLUMNS, ENGINE_VERSION } from './engine.js'
import { CATEGORY_SHORT } from './lib/meta.js'
import { esc, reportToJson, reportToSarif, reportToHtml, badgeSvg, compareReports } from './lib/report.js'
import { rankFixes, simulate, hardenPrompt, attackCases, attackCasesToText, ATTACK_NOTICE } from './lib/advice.js'
import { gaugeSvg, radarSvg, sparklineSvg, barSvg, scoreClass } from './lib/charts.js'
import { loadSettings, saveSettings, loadHistory, addHistory, clearHistory, entryFromReport, trend, DEFAULT_SETTINGS, sanitizeSettings } from './lib/store.js'
import { SAMPLES } from './lib/samples.js'

const MAX_FILE_BYTES = 2000000
const GALLERY = {
  '01-support-bot-open.json': ['Support bot', 'Open: secrets in the prompt, refunds and shell with no approval.', 'JSON'],
  '02-research-assistant-mixed.json': ['Research assistant', 'Mixed: good prompt hygiene, one risky fetch-and-send chain.', 'JSON'],
  '03-ops-agent-hardened.json': ['Ops agent', 'Hardened: approvals, scoping, filtering and limits.', 'JSON'],
  '04-mcp-dev-workstation.json': ['MCP dev workstation', 'An MCP server config: broad filesystem root, unpinned packages, plain-HTTP server.', 'MCP'],
  '05-support-crew.yaml': ['Support crew', 'Multi-agent YAML with handoffs, shared memory and a refund agent.', 'YAML'],
  '06-inbox-copilot.json': ['Inbox copilot', 'OpenAI-style tools that complete the lethal trifecta.', 'OpenAI'],
}
const FORMAT_NAMES = { 'openai-tools': 'OpenAI tools', 'anthropic-tools': 'Anthropic tools', 'langchain-tools': 'LangChain tools', 'mcp-config': 'MCP config', 'multi-agent': 'multi-agent', 'chat-messages': 'chat messages', generic: 'generic', text: 'text sections', shared: 'shared report', empty: 'empty' }

const $ = (sel, root = document) => root.querySelector(sel)
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)]
const store = (() => { try { const k = '__asc'; window.localStorage.setItem(k, '1'); window.localStorage.removeItem(k); return window.localStorage } catch { return null } })()
const reducedMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches

const state = {
  view: 'analyze', tab: 'findings', report: null, raw: '', shared: false, name: '',
  applied: new Set(), sev: new Set(), q: '', cat: '', settings: loadSettings(store),
  history: loadHistory(store), cmp: { a: '', b: '', result: null }, rulesQ: '', rulesCat: '', hardened: null, saveHistory: true,
}

// ---------- helpers ----------
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), 1800) }
async function copyText(text, msg = 'Copied to clipboard') {
  try { await navigator.clipboard.writeText(text); toast(msg); return true } catch { /* fall back */ }
  const ta = document.createElement('textarea'); ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select()
  let ok = false; try { ok = document.execCommand('copy') } catch { /* ignore */ }
  ta.remove(); toast(ok ? msg : 'Copy blocked by the browser: select the text and copy manually'); return ok
}
function download(name, text, type = 'text/plain') {
  const a = document.createElement('a'); const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }))
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000); toast(`Downloaded ${name}`)
}
const opts = () => ({ disabled: state.settings.disabled, weights: state.settings.weights })
const fmtName = (f) => String(f || '').split('+').map((p) => { const [a, b] = p.includes(':') ? p.split(':') : ['', p]; return (a ? a.toUpperCase() + ' · ' : '') + (FORMAT_NAMES[b] || b) }).join(' + ')
const fmtDate = (t) => new Date(t).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
const sevChip = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`
const slug = (s) => String(s || 'agent').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'agent'

// ---------- navigation ----------
function setView(v) {
  state.view = v
  for (const b of $$('#mainnav button')) { const on = b.dataset.view === v; b.setAttribute('aria-selected', on); b.tabIndex = on ? 0 : -1 }
  for (const s of $$('main > section')) s.hidden = s.id !== `view-${v}`
  if (v === 'compare') renderCompare()
  if (v === 'history') renderHistory()
  if (v === 'rules') renderRules()
  if (v === 'settings') renderSettings()
  if (v === 'analyze' && !state.report) renderEmpty()
  window.scrollTo({ top: 0 })
}

// ---------- analysis ----------
function setError(msg) { $('#in-error').innerHTML = msg ? `<div class="alert err">${esc(msg)}</div>` : '' }
function updateMeta() {
  const n = $('#in').value.length
  $('#in-meta').textContent = `${n.toLocaleString()} / ${MAX_INPUT_CHARS.toLocaleString()} characters${n > MAX_INPUT_CHARS ? ' (only the first part is analysed)' : ''}`
}
function runAnalysis(raw, { name, save = true } = {}) {
  setError('')
  if (!String(raw).trim()) { setError('Paste or upload an agent configuration first, or pick one of the sample agents below.'); $('#in').focus(); return }
  let report
  try { report = analyze(raw, opts()) } catch (e) { setError('Could not analyze this input: ' + (e && e.message ? e.message : 'unknown error')); return }
  state.raw = raw; state.report = report; state.shared = false; state.applied = new Set(); state.hardened = null
  state.name = String(name || $('#runname').value || '').trim()
  if (save && state.saveHistory) { state.history = addHistory(store, entryFromReport(report, state.name || `Run ${state.history.length + 1}`)) }
  $('#fmt-chip').innerHTML = `<span class="chip">Detected: ${esc(fmtName(report.format))}</span>`
  if (history.replaceState && location.hash.startsWith('#r=')) history.replaceState(null, '', location.pathname + location.search)
  renderResults(true)
}
function loadSample(file) {
  const s = SAMPLES.find((x) => x.file === file); if (!s) return null
  let text = s.text
  if (file.endsWith('.json')) { try { const j = JSON.parse(text); delete j._label; text = JSON.stringify(j, null, 2) } catch { /* keep */ } }
  return { text, title: (GALLERY[file] || [file])[0] }
}
async function readFile(file) {
  if (!file) return
  if (file.size > MAX_FILE_BYTES) { setError(`That file is ${(file.size / 1e6).toFixed(1)} MB. The limit is 2 MB.`); return }
  if (file.type && !/^(text\/|application\/(json|x-yaml|yaml|xml))/.test(file.type) && !/\.(json|ya?ml|txt|md|mcp)$/i.test(file.name)) { setError('Unsupported file type. Use .json, .yaml, .yml, .txt or .md.'); return }
  let text = ''
  try { text = await file.text() } catch { setError('Could not read that file.'); return }
  if (/\u0000/.test(text.slice(0, 2000))) { setError('That looks like a binary file, not a text configuration.'); return }
  $('#in').value = text; updateMeta(); $('#runname').value = $('#runname').value || file.name.replace(/\.[^.]+$/, '').slice(0, 60)
  runAnalysis(text)
}

// ---------- results ----------
function renderEmpty() {
  $('.grid').classList.remove('has-report')
  const gallery = Object.keys(GALLERY).filter((f) => SAMPLES.some((s) => s.file === f)).map((f) => {
    let sc = ''
    try { const r = analyze(loadSample(f).text); sc = `<span class="pill ${scoreClass(r.score)}" style="color:var(--${scoreClass(r.score)})">${r.score}/100 ${esc(r.grade)}</span>` } catch { /* ignore */ }
    return `<button class="sample" data-action="sample" data-file="${esc(f)}"><b>${esc(GALLERY[f][0])}</b>${sc}<span class="d">${esc(GALLERY[f][1])}</span><span class="meta">${esc(GALLERY[f][2])} · fictional</span></button>`
  }).join('')
  $('#results').innerHTML = `<div class="card fade"><div class="empty"><svg viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M32 6l20 8v14c0 14-8.5 22-20 28C20.500 50 12 42 12 28V14z"/><path d="M23 32l6 6 12-12"/></svg><h3>No report yet</h3><p>Analyze your own configuration on the left, or try a fictional sample agent:</p></div><div class="gallery" aria-label="Sample agents">${gallery}</div></div>`
}

function counts(report) { const c = { critical: 0, high: 0, medium: 0, low: 0 }; for (const f of report.findings) c[f.severity]++; return c }

function trifectaHtml(t) {
  if (!t) return ''
  const leg = (k, title, d) => `<div class="leg ${d.present ? 'on' : ''}"><b>${esc(title)}</b><small>${d.present ? esc(d.evidence.slice(0, 3).join(', ')) : 'Not detected'}</small></div>`
  const msg = t.complete ? (t.gated ? 'All three legs are present, but the outbound channel is guarded by approval or scoping.' : 'All three legs are present and the outbound channel is not guarded. One planted instruction could leak private data.') : `${t.legs} of 3 legs present. Removing any one leg breaks the exfiltration chain.`
  return `<div class="card" style="margin-top:16px"><h2>Lethal trifecta <span class="sub">private data + untrusted content + external communication</span></h2><div class="tri">${leg('p', 'Private data', t.privateData)}${leg('u', 'Untrusted content', t.untrusted)}${leg('e', 'External communication', t.external)}</div><p class="meta banner-tri" style="margin:10px 0 0">${esc(msg)}</p></div>`
}

function renderResults(animate) {
  const r = state.report
  $('.grid').classList.toggle('has-report', !!r)
  if (!r) { renderEmpty(); return }
  const c = counts(r)
  const cats = Object.entries(CATEGORIES).map(([k, v]) => `<div class="cat"><span>${esc(v)}</span><span class="v">${r.categories[k]}</span>${barSvg(r.categories[k], { w: 300 })}</div>`).join('')
  const tab = (id, label, n) => `<button role="tab" id="tab-${id}" data-tab="${id}" aria-selected="${state.tab === id}" aria-controls="panel" tabindex="${state.tab === id ? 0 : -1}">${label}${n === undefined ? '' : `<span class="n">${n}</span>`}</button>`
  $('#results').innerHTML = `
  <div class="card fade">
    ${state.shared ? '<div class="alert info">Shared report. It contains scores and finding text only, never the configuration. Matrix, attack tests and the hardened prompt need the original config.</div>' : ''}
    ${r.customized ? '<div class="alert warn">Customized scoring: some rules are disabled or weights changed in Settings. Scores are not comparable with default runs.</div>' : ''}
    ${r.summary.truncated ? '<div class="alert warn">Input was longer than 200,000 characters; only the first part was analysed.</div>' : ''}
    <div class="summary">
      <div id="gauge-wrap">${gaugeSvg(r.score, r.grade)}</div>
      <div>
        <h2 style="font-size:18px;margin-bottom:10px">${esc(state.name || 'Security report')}</h2>
        <div class="counts">${SEVERITY_ORDER.map((s) => `<span class="sev ${s}">${c[s]} ${s}</span>`).join('')}</div>
        <div class="cats">${cats}</div>
        <p class="meta" style="margin:10px 0 0">${r.summary.tools} tool${r.summary.tools === 1 ? '' : 's'}${r.summary.agents ? `, ${r.summary.agents} agents` : ''}${r.summary.mcpServers ? `, ${r.summary.mcpServers} MCP servers` : ''} · ${r.summary.promptChars.toLocaleString()} prompt characters · engine ${esc(ENGINE_VERSION)}</p>
      </div>
      <div class="radar-wrap">${radarSvg(r.categories, { size: 300 })}
        <table class="sr-only"><caption>Category scores</caption>${Object.entries(CATEGORIES).map(([k, v]) => `<tr><th>${esc(v)}</th><td>${r.categories[k]}</td></tr>`).join('')}</table>
      </div>
    </div>
    <div class="tabs" role="tablist" aria-label="Report sections">${tab('findings', 'Findings', r.findings.length)}${tab('roadmap', 'Fix roadmap')}${tab('matrix', 'Permission matrix', r.matrix.length)}${tab('attacks', 'Attack tests')}${tab('export', 'Export & share')}</div>
    <div class="panel" id="panel" role="tabpanel" aria-labelledby="tab-${state.tab}"></div>
  </div>${trifectaHtml(r.trifecta)}`
  renderPanel()
  animateGauge(animate)
}

function animateGauge(animate, root = document) {
  for (const g of $$('svg.gauge', root)) {
    const arcEl = $('.val', g), num = $('.num', g)
    const total = +arcEl.dataset.arc, cc = +arcEl.dataset.c, val = +arcEl.dataset.value
    const setArc = (v) => arcEl.setAttribute('stroke-dasharray', `${((total * v) / 100).toFixed(2)} ${cc}`)
    if (!animate || reducedMotion()) { setArc(val); num.textContent = val; continue }
    num.textContent = '0'
    requestAnimationFrame(() => requestAnimationFrame(() => setArc(val)))
    const t0 = performance.now()
    const step = (now) => { const p = Math.min(1, (now - t0) / 1100); num.textContent = Math.round(val * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(step) }
    requestAnimationFrame(step)
  }
}

function renderPanel() {
  const p = $('#panel'); if (!p || !state.report) return
  p.setAttribute('aria-labelledby', `tab-${state.tab}`)
  for (const b of $$('.tabs [data-tab]')) { const on = b.dataset.tab === state.tab; b.setAttribute('aria-selected', on); b.tabIndex = on ? 0 : -1 }
  const fn = { findings: panelFindings, roadmap: panelRoadmap, matrix: panelMatrix, attacks: panelAttacks, export: panelExport }[state.tab]
  p.innerHTML = fn()
  if (state.tab === 'findings') renderFindingList()
  animateGauge(false, p)
}

// ----- findings -----
function panelFindings() {
  const r = state.report, c = counts(r)
  return `<div class="filters" role="group" aria-label="Filter findings">
    <input type="search" id="fq" placeholder="Search findings, rules, OWASP, ATLAS…" aria-label="Search findings" value="${esc(state.q)}">
    ${SEVERITY_ORDER.map((s) => `<button class="toggle" data-action="sev" data-sev="${s}" aria-pressed="${state.sev.has(s)}">${s} <span class="meta">${c[s]}</span></button>`).join('')}
    <select id="fcat" aria-label="Filter by category"><option value="">All categories</option>${Object.entries(CATEGORIES).map(([k, v]) => `<option value="${k}" ${state.cat === k ? 'selected' : ''}>${esc(v)}</option>`).join('')}</select>
  </div><div id="flist"></div>`
}
function filteredFindings() {
  const q = state.q.trim().toLowerCase()
  return state.report.findings.filter((f) => (!state.sev.size || state.sev.has(f.severity)) && (!state.cat || f.cat === state.cat) &&
    (!q || `${f.id} ${f.title} ${f.detail} ${f.fix} ${(f.owasp || []).join(' ')} ${(f.owasp || []).map((o) => OWASP[o]).join(' ')} ${(f.atlas || []).join(' ')} ${f.cat}`.toLowerCase().includes(q)))
}
function tagsHtml(f) {
  return [...(f.owasp || []).map((o) => `<a class="tag" href="#rule=${esc(f.id)}" data-action="rule" data-id="${esc(f.id)}" title="OWASP LLM Top 10 (2025): ${esc(OWASP[o] || o)}">OWASP ${esc(o)} · ${esc(OWASP[o] || '')}</a>`),
    ...(f.atlas || []).map((a) => `<span class="tag" title="MITRE ATLAS: ${esc(ATLAS[a] || a)}">ATLAS ${esc(a)}</span>`)].join('')
}
function renderFindingList() {
  const list = filteredFindings(), el = $('#flist'); if (!el) return
  if (!state.report.findings.length) { el.innerHTML = '<div class="empty"><h3>No findings from the rule set</h3><p>That does not prove the agent is safe: this is a static review of text. Run the attack tests too.</p></div>'; return }
  if (!list.length) { el.innerHTML = '<div class="empty"><h3>No findings match these filters</h3><p>Clear the search or severity filters to see all findings.</p><button class="btn small" data-action="clear-filters">Clear filters</button></div>'; return }
  el.innerHTML = `<p class="meta" aria-live="polite">${list.length} of ${state.report.findings.length} findings</p>` + list.map((f) => `<article class="finding ${esc(f.severity)}">
    <div class="row">${sevChip(f.severity)}<a class="tag" href="#rule=${esc(f.id)}" data-action="rule" data-id="${esc(f.id)}">${esc(f.id)} · rule docs</a><span class="tag">${esc(CATEGORY_SHORT[f.cat] || f.cat)}</span></div>
    <h3>${esc(f.title)}</h3><p>${esc(f.detail || '')}</p>${f.evidence ? `<p class="meta">Evidence (masked): <code>${esc(f.evidence)}</code></p>` : ''}
    <div>${tagsHtml(f)}</div><p class="fix"><b>Fix:</b> ${esc(f.fix)}</p></article>`).join('')
}

// ----- roadmap -----
function panelRoadmap() {
  const r = state.report
  if (!r.findings.length) return '<div class="empty"><h3>Nothing to fix</h3><p>No findings from the rule set. Keep running the attack tests to check real behaviour.</p></div>'
  const fixes = rankFixes(r, state.settings.weights)
  const sim = simulate(r, [...state.applied], state.settings.weights)
  const row = (g, i) => `<li class="win"><input type="checkbox" id="fx-${esc(g.id)}" data-action="apply" data-id="${esc(g.id)}" ${state.applied.has(g.id) ? 'checked' : ''} aria-label="Apply fix ${esc(g.id)}"><div><h3><label for="fx-${esc(g.id)}">${esc(g.title)}</label></h3><p>${esc(g.fix)}</p><div style="margin-top:6px">${sevChip(g.severity)} <span class="tag">${esc(g.id)}</span><span class="tag">effort: ${['', 'one line', 'config change', 'redesign'][g.effort]}</span><span class="tag">${g.count} finding${g.count > 1 ? 's' : ''}</span></div></div><div class="imp"><b>+${g.gain}</b>score gain now<br>${g.gain === 0 ? 'unlocks gains after other fixes' : 'score after: ' + g.projected}<br>${g.points} weighted pts</div></li>`
  const top = fixes.slice(0, 5), rest = fixes.slice(5)
  let hard = ''
  if (!state.shared && state.raw) {
    state.hardened = state.hardened || hardenPrompt(state.raw)
    const h = state.hardened
    hard = `<div class="card" style="margin-top:18px;background:var(--surface2)"><h2>Suggested hardened system prompt</h2>
      <p class="meta">Prompt-only changes would take findings from ${h.findingsBefore} to ${h.findingsAfter} and the score from ${h.before} to ${h.projected}. Tool, config and output-filter issues need changes in code. ${esc(h.note)}</p>
      ${h.changes.length ? `<ul>${h.changes.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
      <pre class="code" tabindex="0" aria-label="Hardened prompt">${esc(h.prompt || '(empty: add a system prompt first)')}</pre>
      <div class="row"><button class="btn small" data-action="copy-hardened">Copy prompt</button><button class="btn small" data-action="dl-hardened">Download .txt</button></div></div>`
  }
  return `<div class="sim card" style="background:var(--surface2);margin-bottom:16px"><div>${gaugeSvg(sim.score, sim.grade, { size: 150, label: 'Projected score' })}</div>
    <div><h2 style="margin-bottom:4px">Before / after simulation</h2><p class="meta" style="margin:0 0 8px">Tick fixes below to see the projected score. It assumes each fix is fully implemented and removes every finding of that rule.</p>
    <p style="margin:0 0 8px"><b>${r.score}</b> now → <b class="delta ${sim.score > r.score ? 'up' : 'flat'}">${sim.score}</b> projected (${sim.score - r.score >= 0 ? '+' : ''}${sim.score - r.score}), ${sim.remaining} finding${sim.remaining === 1 ? '' : 's'} left</p>
    <div class="row"><button class="btn small" data-action="apply-top">Apply top 5</button><button class="btn small" data-action="apply-all">Apply all fixes</button><button class="btn small" data-action="apply-none">Reset</button></div></div></div>
    <h2 style="font-size:15px">Top ${top.length} quick wins <span class="meta">ordered by real score gain per unit of effort</span></h2><ol class="wins">${top.map(row).join('')}</ol>
    ${rest.length ? `<details style="margin-top:14px"><summary style="cursor:pointer;font-weight:650">More fixes (${rest.length})</summary><ol class="wins" style="margin-top:10px;counter-reset:w 5">${rest.map(row).join('')}</ol></details>` : ''}${hard}`
}

// ----- matrix -----
function panelMatrix() {
  const r = state.report
  if (!r.matrix.length) return `<div class="empty"><h3>No tools detected</h3><p>${state.shared ? 'Shared reports do not include the tool list.' : 'Add a TOOLS section, a tools array or an MCP server config to see the permission matrix.'}</p></div>`
  return `<p class="meta">Excessive-agency view: what each tool can do, and whether approval and scoping are described. ● means the capability was inferred from the tool name and description.</p>
  <div class="tw"><table><thead><tr><th>Tool</th>${MATRIX_COLUMNS.map(([, l]) => `<th class="c">${esc(l)}</th>`).join('')}<th class="c">Reads untrusted</th><th class="c">Approval</th><th class="c">Scoped</th><th>Risk</th></tr></thead><tbody>${r.matrix.map((m) => `<tr><td><b>${esc(m.name)}</b>${m.agent ? ` <span class="meta">(${esc(m.agent)})</span>` : ''}</td>${MATRIX_COLUMNS.map(([k]) => `<td class="c">${m.kinds.includes(k) ? '<span class="dotc" aria-label="yes">●</span>' : '<span class="meta" aria-hidden="true">·</span>'}</td>`).join('')}<td class="c">${m.readsUntrusted ? '<span class="dotc" aria-label="yes">●</span>' : '<span class="meta">·</span>'}</td><td class="c">${m.confirmed === null ? '<span class="meta">n/a</span>' : m.confirmed ? '<span class="yes">yes</span>' : '<span class="no">no</span>'}</td><td class="c">${m.scoped === null ? '<span class="meta">n/a</span>' : m.scoped ? '<span class="yes">yes</span>' : '<span class="no">no</span>'}</td><td>${m.risk === 'none' ? '<span class="meta">none</span>' : sevChip(m.risk)}</td></tr>`).join('')}</tbody></table></div>`
}

// ----- attack tests -----
function panelAttacks() {
  if (state.shared || !state.raw) return '<div class="empty"><h3>Attack tests need the original config</h3><p>Shared reports do not include it. Paste the configuration again to generate tests tailored to its tools.</p></div>'
  const cases = attackCases(state.raw)
  return `<div class="alert info">${esc(ATTACK_NOTICE)}</div><div class="row" style="margin-bottom:12px"><button class="btn small" data-action="copy-attacks">Copy all</button><button class="btn small" data-action="dl-attacks">Download .txt</button><span class="meta">${cases.length} tests tailored to this config. Canary string: <code>ASC-CANARY-7421</code></span></div>` +
    cases.map((c, i) => `<article class="case"><h3><span>${esc(c.id)} · ${esc(c.title)}</span><button class="btn small" data-action="copy-case" data-i="${i}">Copy prompt</button></h3><div>${c.rules.map((x) => `<a class="tag" href="#rule=${esc(x)}" data-action="rule" data-id="${esc(x)}">${esc(x)}</a>`).join('')}<span class="tag">OWASP ${esc(c.owasp)}</span></div><pre class="code" tabindex="0">${esc(c.prompt)}</pre><dl><div><dt>Safe if:</dt><dd>${esc(c.expectSafe)}</dd></div><div><dt>Fail if:</dt><dd>${esc(c.failIf)}</dd></div></dl></article>`).join('')
}

// ----- export -----
function shareUrl() { return `${location.href.split('#')[0]}#r=${encodeReport(state.report)}` }
function panelExport() {
  const r = state.report
  const svg = badgeSvg(r.score, r.grade)
  const embed = `![Agent security](agent-security-badge.svg)`
  return `<div class="two"><div><h2 style="font-size:15px">Reports</h2><div class="row">
    <button class="btn small" data-action="copy-md">Copy Markdown</button><button class="btn small" data-action="dl-md">.md</button><button class="btn small" data-action="dl-json">.json</button><button class="btn small" data-action="dl-sarif">.sarif</button><button class="btn small" data-action="dl-html">.html</button><button class="btn small" data-action="print">Print / save as PDF</button></div>
    <p class="meta">SARIF 2.1.0 loads in GitHub code scanning and most security tools. Reports never contain the pasted config; secret evidence is masked.</p>
    <h2 style="font-size:15px;margin-top:18px">Share link</h2><div class="row"><button class="btn small" data-action="copy-share">Copy share link</button></div>
    <p class="meta">The link carries the report only (score, rule IDs, short finding text). The pasted config is never encoded into it.</p></div>
    <div><h2 style="font-size:15px">Badge</h2><div class="badge-prev" id="badge-prev" aria-label="Badge preview">${svg}</div>
    <div class="row"><button class="btn small" data-action="copy-badge-md">Copy Markdown embed</button><button class="btn small" data-action="dl-badge">Download SVG</button><button class="btn small" data-action="copy-badge-svg">Copy SVG</button></div>
    <p class="meta">Commit the SVG next to your README and embed it with <code>${esc(embed)}</code>. It is a static snapshot, not a live check.</p></div></div>`
}

// ---------- compare ----------
function renderCompare() {
  const sel = (id) => `<select id="${id}" aria-label="Load a sample into ${id === 'cmp-sa' ? 'A' : 'B'}"><option value="">Load a sample…</option>${Object.keys(GALLERY).map((f) => `<option value="${esc(f)}">${esc(GALLERY[f][0])}</option>`).join('')}</select>`
  let res = '<div class="empty"><h3>Compare two configurations</h3><p>Paste an original and a revised config (or load samples), then press Compare to see score change, category deltas and which findings were fixed or introduced.</p><button class="btn small" data-action="cmp-demo">Load weak vs hardened example</button></div>'
  const x = state.cmp.result
  if (x) {
    const d = x.delta, list = (arr, label, cls) => `<details ${arr.length ? 'open' : ''} style="margin:10px 0"><summary style="cursor:pointer;font-weight:700">${label} (${arr.length})</summary>${arr.length ? arr.map((f) => `<article class="finding ${esc(f.severity)}"><div class="row">${sevChip(f.severity)}<span class="tag">${esc(f.id)}</span></div><h3>${esc(f.title)}</h3><p class="meta">${esc(f.detail)}</p></article>`).join('') : '<p class="meta">None</p>'}</details>`
    res = `<div class="cmp-sum"><div>${gaugeSvg(x.ra.score, x.ra.grade, { size: 170, label: 'Config A score' })}<b>A</b></div><div><div class="bigdelta delta ${d > 0 ? 'up' : d < 0 ? 'down' : 'flat'}">${d > 0 ? '+' : ''}${d}</div><span class="meta">score change A → B</span></div><div>${gaugeSvg(x.rb.score, x.rb.grade, { size: 170, label: 'Config B score' })}<b>B</b></div></div>
    <div class="tw" style="margin:14px 0"><table><thead><tr><th>Category</th><th class="c">A</th><th class="c">B</th><th class="c">Change</th></tr></thead><tbody>${x.cmp.categories.map((c) => `<tr><td>${esc(c.label)}</td><td class="c">${c.a}</td><td class="c">${c.b}</td><td class="c"><span class="delta ${c.delta > 0 ? 'up' : c.delta < 0 ? 'down' : 'flat'}">${c.delta > 0 ? '+' : ''}${c.delta}</span></td></tr>`).join('')}</tbody></table></div>
    ${list(x.cmp.fixed, 'Fixed in B')}${list(x.cmp.added, 'New in B')}${list(x.cmp.unchanged, 'Unchanged')}`
  }
  $('#view-compare').innerHTML = `<div class="hero"><div><h1>Compare configs</h1><p>See exactly what a change did to the score and the findings, side by side.</p></div></div>
  <div class="cmp"><div class="card"><h2>A: original</h2><textarea id="cmp-a" aria-label="Configuration A" spellcheck="false">${esc(state.cmp.a)}</textarea><div style="margin-top:8px">${sel('cmp-sa')}</div></div>
  <div class="card"><h2>B: revised</h2><textarea id="cmp-b" aria-label="Configuration B" spellcheck="false">${esc(state.cmp.b)}</textarea><div style="margin-top:8px">${sel('cmp-sb')}</div></div></div>
  <div class="row" style="margin:14px 0"><button class="btn primary" data-action="cmp-run">Compare</button><button class="btn" data-action="cmp-swap">Swap A and B</button></div><div id="cmp-err" role="alert"></div><div class="card" id="cmp-res">${res}</div>`
}
function runCompare() {
  state.cmp.a = $('#cmp-a').value; state.cmp.b = $('#cmp-b').value
  if (!state.cmp.a.trim() || !state.cmp.b.trim()) { $('#cmp-err').innerHTML = '<div class="alert err">Both A and B need a configuration.</div>'; return }
  const ra = analyze(state.cmp.a, opts()), rb = analyze(state.cmp.b, opts())
  state.cmp.result = { ra, rb, cmp: compareReports(ra, rb), delta: rb.score - ra.score }
  state.cmp.result.delta = rb.score - ra.score
  renderCompare(); animateGauge(true)
}

// ---------- history ----------
function renderHistory() {
  const h = state.history, tr = trend(h)
  const rows = [...h].reverse().map((e) => `<tr><td>${esc(fmtDate(e.t))}</td><td>${esc(e.name)}</td><td class="c"><b style="color:var(--${scoreClass(e.score)})">${e.score}</b></td><td class="c">${esc(e.grade)}</td><td class="c">${(e.counts.critical || 0)}/${(e.counts.high || 0)}/${(e.counts.medium || 0)}/${(e.counts.low || 0)}</td></tr>`).join('')
  $('#view-history').innerHTML = `<div class="hero"><div><h1>History</h1><p>Scores of your past runs, stored only in this browser. The configuration text itself is never saved.</p></div>
    <div class="row"><label class="row" style="gap:8px"><input type="checkbox" id="hist-on" ${state.saveHistory ? 'checked' : ''}> Save new runs</label><button class="btn small" data-action="hist-clear" ${h.length ? '' : 'disabled'}>Clear history</button></div></div>
  ${h.length ? `<div class="hist-grid"><div class="card"><h2>All runs <span class="sub">${h.length} saved (latest first). Counts are critical/high/medium/low.</span></h2><div class="tw"><table><thead><tr><th>When</th><th>Name</th><th class="c">Score</th><th class="c">Grade</th><th class="c">C/H/M/L</th></tr></thead><tbody>${rows}</tbody></table></div></div>
  <div class="card"><h2>Score trend</h2>${sparklineSvg(tr.points)}<p style="margin:10px 0 0">Latest vs previous: <span class="delta ${tr.direction}">${tr.delta > 0 ? '+' : ''}${tr.delta}</span> <span class="meta">${tr.direction === 'up' ? 'improving' : tr.direction === 'down' ? 'getting worse' : 'unchanged or only one run'}</span></p></div></div>`
  : '<div class="card"><div class="empty"><h3>No runs yet</h3><p>Analyze an agent and it will show up here with its score, so you can watch the trend as you fix things.</p><button class="btn primary small" data-action="go-analyze">Analyze an agent</button></div></div>'}`
}

// ---------- rules docs ----------
function renderRules() {
  const q = state.rulesQ.toLowerCase()
  const ids = Object.keys(CATALOG).filter((id) => { const c = CATALOG[id]; return (!state.rulesCat || c.cat === state.rulesCat) && (!q || `${id} ${c.title} ${c.why} ${c.fix} ${(c.owasp || []).join(' ')}`.toLowerCase().includes(q)) })
  const owaspCounts = Object.keys(OWASP).map((o) => [o, Object.entries(CATALOG).filter(([, c]) => (c.owasp || []).includes(o)).map(([id]) => id)])
  $('#view-rules').innerHTML = `<div class="hero"><div><h1>Rule reference</h1><p>${Object.keys(CATALOG).length} rules. Each one explains why it matters, shows a weak and a better example, and maps to the OWASP LLM Top 10 (2025) and MITRE ATLAS.</p></div></div>
  <div class="owasp" aria-label="OWASP LLM Top 10 coverage">${owaspCounts.map(([o, r]) => `<div><b>${o}</b> ${esc(OWASP[o])}<br><span class="meta">${r.length ? esc(r.join(', ')) : 'no static rule (needs runtime testing)'}</span></div>`).join('')}</div>
  <div class="filters"><input type="search" id="rq" placeholder="Search rules…" aria-label="Search rules" value="${esc(state.rulesQ)}"><select id="rcat" aria-label="Filter rules by category"><option value="">All categories</option>${Object.entries(CATEGORIES).map(([k, v]) => `<option value="${k}" ${state.rulesCat === k ? 'selected' : ''}>${esc(v)}</option>`).join('')}</select></div>
  <div id="rlist">${ids.length ? ids.map((id) => { const c = CATALOG[id]; return `<article class="rulecard" id="rule-${esc(id)}"><h3>${esc(id)} · ${esc(c.title)} ${sevChip(c.sev)}</h3><div>${(c.owasp || []).map((o) => `<span class="tag" title="${esc(OWASP[o])}">OWASP ${esc(o)} · ${esc(OWASP[o])}</span>`).join('')}${(c.atlas || []).map((a) => `<span class="tag" title="${esc(ATLAS[a])}">ATLAS ${esc(a)}</span>`).join('')}<span class="tag">${esc(CATEGORIES[c.cat])}</span><span class="tag">effort: ${['', 'one line', 'config change', 'redesign'][c.effort]}</span></div><p>${esc(c.why)}</p><div class="two"><div><h4 class="b">Weak</h4><pre class="code">${esc(c.bad)}</pre></div><div><h4 class="g">Better</h4><pre class="code">${esc(c.good)}</pre></div></div><p class="fix finding" style="border-left-width:1px;margin:8px 0 0"><b>Fix:</b> ${esc(c.fix)}</p></article>` }).join('') : '<div class="empty"><h3>No rules match</h3></div>'}</div>`
}
function scrollToRule(id) {
  setView('rules')
  const el = document.getElementById(`rule-${id}`)
  if (el) { el.classList.add('hl'); el.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' }); setTimeout(() => el.classList.remove('hl'), 2500) }
}

// ---------- settings ----------
function renderSettings() {
  const s = state.settings
  $('#view-settings').innerHTML = `<div class="hero"><div><h1>Settings</h1><p>Turn rules off or change severity weights. Saved in this browser only. Reports made with custom settings are marked as customized.</p></div><button class="btn" data-action="settings-reset">Reset to defaults</button></div>
  <div class="card"><h2>Severity weights <span class="sub">points deducted per finding (0–50). Each category loses at most 40 points.</span></h2><div class="wgrid">${SEVERITY_ORDER.map((k) => `<div><label class="lbl" for="w-${k}">${k}</label><input type="number" min="0" max="50" step="1" id="w-${k}" data-weight="${k}" value="${s.weights[k]}"></div>`).join('')}</div></div>
  <div class="card" style="margin-top:16px"><h2>Rules <span class="sub">untick a rule to skip it</span></h2>${Object.entries(CATEGORIES).map(([cat, label]) => `<h3 style="font-size:13px;color:var(--muted);margin:14px 0 4px">${esc(label)}</h3>${Object.entries(CATALOG).filter(([, c]) => c.cat === cat).map(([id, c]) => `<div class="rulerow"><input type="checkbox" id="r-${esc(id)}" data-rule="${esc(id)}" ${s.disabled.includes(id) ? '' : 'checked'}><label for="r-${esc(id)}"><b>${esc(id)}</b> ${esc(c.title)} ${sevChip(c.sev)}</label></div>`).join('')}`).join('')}</div>`
}
function applySettings() {
  saveSettings(store, state.settings)
  if (state.raw && !state.shared) { state.report = analyze(state.raw, opts()); state.hardened = null }
}

// ---------- events ----------
const actions = {
  run: () => runAnalysis($('#in').value),
  clear: () => { $('#in').value = ''; $('#runname').value = ''; $('#fmt-chip').innerHTML = ''; state.raw = ''; state.report = null; state.shared = false; updateMeta(); setError(''); renderEmpty() },
  sample: (el) => { const s = loadSample(el.dataset.file); if (!s) return; $('#in').value = s.text; updateMeta(); $('#runname').value = s.title; runAnalysis(s.text, { name: s.title }) },
  theme: () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'),
  help: () => { const d = $('#help'); if (d.showModal && !d.open) d.showModal() },
  'close-help': () => $('#help').close(),
  sev: (el) => { const s = el.dataset.sev; state.sev.has(s) ? state.sev.delete(s) : state.sev.add(s); el.setAttribute('aria-pressed', state.sev.has(s)); renderFindingList() },
  'clear-filters': () => { state.sev.clear(); state.q = ''; state.cat = ''; renderPanel() },
  rule: (el, e) => { e.preventDefault(); scrollToRule(el.dataset.id) },
  apply: (el) => { el.checked ? state.applied.add(el.dataset.id) : state.applied.delete(el.dataset.id); const y = window.scrollY; renderPanel(); window.scrollTo(0, y); const again = document.getElementById(`fx-${el.dataset.id}`); if (again) again.focus({ preventScroll: true }) },
  'apply-top': () => { for (const g of rankFixes(state.report, state.settings.weights).slice(0, 5)) state.applied.add(g.id); renderPanel() },
  'apply-all': () => { for (const g of rankFixes(state.report, state.settings.weights)) state.applied.add(g.id); renderPanel() },
  'apply-none': () => { state.applied.clear(); renderPanel() },
  'copy-hardened': () => copyText(state.hardened.prompt, 'Hardened prompt copied'),
  'dl-hardened': () => download('hardened-prompt.txt', state.hardened.prompt),
  'copy-attacks': () => copyText(attackCasesToText(attackCases(state.raw)), 'All attack tests copied'),
  'dl-attacks': () => download('attack-tests.txt', attackCasesToText(attackCases(state.raw))),
  'copy-case': (el) => copyText(attackCases(state.raw)[+el.dataset.i].prompt, 'Test prompt copied'),
  'copy-md': () => copyText(reportToMarkdown(state.report, state.name || 'Agent security report'), 'Markdown copied'),
  'dl-md': () => download(`${slug(state.name)}-security-report.md`, reportToMarkdown(state.report, state.name || 'Agent security report'), 'text/markdown'),
  'dl-json': () => download(`${slug(state.name)}-security-report.json`, reportToJson(state.report), 'application/json'),
  'dl-sarif': () => download(`${slug(state.name)}-security-report.sarif`, reportToSarif(state.report, { uri: `${slug(state.name)}.json` }), 'application/sarif+json'),
  'dl-html': () => download(`${slug(state.name)}-security-report.html`, reportToHtml(state.report, state.name || 'Agent security report'), 'text/html'),
  print: () => { const doc = new DOMParser().parseFromString(reportToHtml(state.report, state.name || 'Agent security report'), 'text/html'); const root = $('#print-root'); root.innerHTML = ''; const st = document.createElement('style'); st.textContent = doc.querySelector('style').textContent.replace(/body\{[^}]*\}/, ''); root.appendChild(st); for (const n of [...doc.body.childNodes]) root.appendChild(document.importNode(n, true)); window.print() },
  'copy-share': () => copyText(shareUrl(), 'Share link copied (report only, no config)'),
  'copy-badge-md': () => copyText('![Agent security](agent-security-badge.svg)', 'Badge Markdown copied'),
  'dl-badge': () => download('agent-security-badge.svg', badgeSvg(state.report.score, state.report.grade), 'image/svg+xml'),
  'copy-badge-svg': () => copyText(badgeSvg(state.report.score, state.report.grade), 'Badge SVG copied'),
  'cmp-run': runCompare,
  'cmp-swap': () => { state.cmp.a = $('#cmp-b').value; state.cmp.b = $('#cmp-a').value; state.cmp.result = null; renderCompare() },
  'cmp-demo': () => { state.cmp.a = loadSample('01-support-bot-open.json').text; state.cmp.b = loadSample('03-ops-agent-hardened.json').text; runCompare() },
  'hist-clear': () => { clearHistory(store); state.history = []; renderHistory(); toast('History cleared') },
  'go-analyze': () => setView('analyze'),
  'settings-reset': () => { state.settings = sanitizeSettings(DEFAULT_SETTINGS); applySettings(); renderSettings(); toast('Settings reset') },
}
document.addEventListener('click', (e) => {
  const t = e.target.closest('[data-action]'); if (t && actions[t.dataset.action] && t.type !== 'checkbox') { actions[t.dataset.action](t, e); return }
  const tab = e.target.closest('[data-tab]'); if (tab) { state.tab = tab.dataset.tab; renderPanel(); return }
  const nav = e.target.closest('#mainnav [data-view]'); if (nav) setView(nav.dataset.view)
})
document.addEventListener('change', (e) => {
  const t = e.target
  if (t.matches('[data-action=apply]')) { actions.apply(t, e); return }
  if (t.id === 'fcat') { state.cat = t.value; renderFindingList() }
  if (t.id === 'rcat') { state.rulesCat = t.value; renderRules(); $('#rcat').focus() }
  if (t.id === 'cmp-sa' || t.id === 'cmp-sb') { const s = loadSample(t.value); if (s) $(t.id === 'cmp-sa' ? '#cmp-a' : '#cmp-b').value = s.text; t.value = '' }
  if (t.id === 'hist-on') state.saveHistory = t.checked
  if (t.dataset.weight) { state.settings.weights[t.dataset.weight] = t.value; state.settings = sanitizeSettings(state.settings); t.value = state.settings.weights[t.dataset.weight]; applySettings(); toast('Weight saved') }
  if (t.dataset.rule) { const d = new Set(state.settings.disabled); t.checked ? d.delete(t.dataset.rule) : d.add(t.dataset.rule); state.settings.disabled = [...d]; applySettings(); toast(t.checked ? 'Rule enabled' : 'Rule disabled') }
  if (t.id === 'file') { readFile(t.files && t.files[0]); t.value = '' }
})
document.addEventListener('input', (e) => {
  const t = e.target
  if (t.id === 'in') updateMeta()
  if (t.id === 'fq') { state.q = t.value; renderFindingList() }
  if (t.id === 'rq') { state.rulesQ = t.value; const pos = t.selectionStart; renderRules(); const n = $('#rq'); n.focus(); n.setSelectionRange(pos, pos) }
})
// drag and drop
const dropEl = $('#drop')
for (const ev of ['dragenter', 'dragover']) dropEl.addEventListener(ev, (e) => { e.preventDefault(); dropEl.classList.add('over') })
for (const ev of ['dragleave', 'drop']) dropEl.addEventListener(ev, () => dropEl.classList.remove('over'))
dropEl.addEventListener('drop', (e) => { e.preventDefault(); const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]; if (f) readFile(f); else { const t = e.dataTransfer && e.dataTransfer.getData('text'); if (t) { $('#in').value = t.slice(0, MAX_FILE_BYTES); updateMeta() } } })
window.addEventListener('dragover', (e) => e.preventDefault()); window.addEventListener('drop', (e) => e.preventDefault())
// roving tabs
function arrowNav(e, sel, pick) {
  if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(e.key)) return
  const items = $$(sel, e.currentTarget); const i = items.indexOf(document.activeElement); if (i < 0) return
  e.preventDefault(); const n = e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1 : (i + (e.key === 'ArrowRight' ? 1 : -1) + items.length) % items.length
  items[n].focus(); pick(items[n])
}
$('#mainnav').addEventListener('keydown', (e) => arrowNav(e, '[data-view]', (b) => setView(b.dataset.view)))
document.addEventListener('keydown', (e) => { const tl = e.target.closest && e.target.closest('.tabs'); if (tl) arrowNav({ ...e, currentTarget: tl, key: e.key, preventDefault: () => e.preventDefault() }, '[data-tab]', (b) => { state.tab = b.dataset.tab; renderPanel(); b.focus() }) })
// keyboard shortcuts
let gPending = false
document.addEventListener('keydown', (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); if (state.view === 'compare') runCompare(); else { setView('analyze'); runAnalysis($('#in').value) } return }
  if (e.key === 'Escape') { const d = $('#help'); if (d.open) d.close(); return }
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return
  if (gPending) { gPending = false; const v = { a: 'analyze', c: 'compare', h: 'history', r: 'rules', s: 'settings' }[e.key]; if (v) { e.preventDefault(); setView(v) } return }
  if (e.key === 'g') { gPending = true; setTimeout(() => { gPending = false }, 1200); return }
  if (e.key === '?') { e.preventDefault(); actions.help() }
  else if (e.key === 't') actions.theme()
  else if (e.key === '/' && state.report) { e.preventDefault(); setView('analyze'); state.tab = 'findings'; renderPanel(); const q = $('#fq'); if (q) q.focus() }
  else if (/^[1-5]$/.test(e.key) && state.report && state.view === 'analyze') { state.tab = ['findings', 'roadmap', 'matrix', 'attacks', 'export'][+e.key - 1]; renderPanel() }
  else if (e.key === 'm' && state.report) actions['copy-md']()
})
window.addEventListener('hashchange', route)

function setTheme(t) {
  document.documentElement.dataset.theme = t
  const b = $('#theme-btn'); b.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme')
  try { store && store.setItem('asc.theme', t) } catch { /* ignore */ }
}
function route() {
  const h = location.hash
  if (h.startsWith('#rule=')) { const id = decodeURIComponent(h.slice(6)); if (Object.prototype.hasOwnProperty.call(CATALOG, id)) scrollToRule(id); return }
  if (h === '#rules') { setView('rules'); return }
  if (h.startsWith('#r=')) {
    const d = decodeReport(h)
    setView('analyze')
    if (!d) { $('#results').innerHTML = '<div class="card"><div class="alert err">This share link is invalid or damaged, so no report could be rebuilt.</div></div>'; return }
    state.report = d; state.shared = true; state.raw = ''; state.name = 'Shared report'; state.tab = 'findings'; renderResults(true)
  }
}

// ---------- init ----------
{
  let t = null
  try { t = store && store.getItem('asc.theme') } catch { /* ignore */ }
  setTheme(t === 'light' || t === 'dark' ? t : (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'))
  updateMeta(); renderEmpty(); route()
}
