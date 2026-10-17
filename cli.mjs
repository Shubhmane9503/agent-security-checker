#!/usr/bin/env node
// Agent Security Checker CLI. Usage: node cli.mjs <config.(json|yaml|yml|txt|md)|-> [options]
// Exit codes: 0 ok, 1 score below --fail-under or findings at/above --fail-on, 2 usage or input error.
import { readFileSync, writeFileSync, statSync } from 'node:fs'
import { analyze, reportToMarkdown, SEVERITY_ORDER, SEVERITY_WEIGHT, CATALOG, ENGINE_VERSION } from './engine.js'
import { hardenPrompt } from './lib/advice.js'
import { reportToJson, reportToSarif, reportToHtml, badgeSvg } from './lib/report.js'

const MAX_BYTES = 2000000
const HELP = `agent-security-checker ${ENGINE_VERSION}
Static security review of an LLM agent configuration (prompt, tools, MCP servers). Runs offline.

Usage:
  node cli.mjs <config-file | -> [options]

Options:
  --format <text|json|markdown|sarif|html|badge>   output format (default: text)
  --out <file>             write the output to a file instead of stdout
  --fail-under <0-100>     exit 1 if the score is below this number
  --fail-on <severity>     exit 1 if any finding is at or above: critical|high|medium|low
  --disable <IDs>          comma-separated rule IDs to skip, e.g. RL-1,AU-1
  --weights <k=v,...>      override severity weights, e.g. critical=30,high=12
  --harden                 print a hardened version of the prompt (idempotent) instead of a report; summary goes to stderr
  --name <label>           title used in reports
  --list-rules             print all rule IDs and titles
  -h, --help               show this help

Examples:
  node cli.mjs agent.json --format sarif --out results.sarif --fail-under 70
  node cli.mjs mcp.json --fail-on high
  cat prompt.txt | node cli.mjs - --format markdown
`

function die(msg) { process.stderr.write(`error: ${msg}\n`); process.exit(2) }

export function parseArgs(argv) {
  const o = { format: 'text', files: [] }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    const val = () => { if (i + 1 >= argv.length) die(`${a} needs a value`); return argv[++i] }
    if (a === '-h' || a === '--help') o.help = true
    else if (a === '--list-rules') o.list = true
    else if (a === '--harden') o.harden = true
    else if (a === '--format') o.format = val()
    else if (a === '--out') o.out = val()
    else if (a === '--fail-under') { const n = Number(val()); if (!Number.isFinite(n) || n < 0 || n > 100) die('--fail-under must be a number from 0 to 100'); o.failUnder = n }
    else if (a === '--fail-on') { const s = val(); if (!SEVERITY_ORDER.includes(s)) die('--fail-on must be one of ' + SEVERITY_ORDER.join(', ')); o.failOn = s }
    else if (a === '--disable') o.disable = val().split(',').map((x) => x.trim()).filter(Boolean)
    else if (a === '--weights') { o.weights = {}; for (const kv of val().split(',')) { const [k, v] = kv.split('='); if (!(k in SEVERITY_WEIGHT) || !Number.isFinite(Number(v))) die(`bad weight "${kv}"`); o.weights[k] = Number(v) } }
    else if (a === '--name') o.name = val()
    else if (a === '-' || !a.startsWith('-')) o.files.push(a)
    else die(`unknown option ${a}`)
  }
  return o
}

export function run(argv, { stdin = () => readFileSync(0, 'utf8') } = {}) {
  const o = parseArgs(argv)
  if (o.help || (!argv.length)) return { code: argv.length ? 0 : 2, out: HELP }
  if (o.list) return { code: 0, out: Object.entries(CATALOG).map(([id, c]) => `${id}\t${c.sev}\t${c.title}`).join('\n') + '\n' }
  if (o.files.length !== 1) die('give exactly one config file (or - for stdin)')
  if (!['text', 'json', 'markdown', 'sarif', 'html', 'badge'].includes(o.format)) die(`unknown format "${o.format}"`)
  const file = o.files[0]
  let raw
  try {
    if (file === '-') raw = stdin()
    else { if (statSync(file).size > MAX_BYTES) die('file is larger than 2 MB'); raw = readFileSync(file, 'utf8') }
  } catch (e) { die(`cannot read ${file}: ${e.message}`) }
  if (/\u0000/.test(raw.slice(0, 2000))) die('input looks like a binary file')
  if (o.harden) {
    const h = hardenPrompt(raw)
    const notes = [`score ${h.before} -> ${h.projected} (findings ${h.findingsBefore} -> ${h.findingsAfter}), ${h.blocks} rule(s) added`, ...h.changes.map((x) => `- ${x}`)].join('\n') + '\n'
    return { code: 0, out: h.prompt, notes, hardened: h }
  }
  const report = analyze(raw, { disabled: o.disable, weights: o.weights })
  const title = o.name || (file === '-' ? 'Agent security report' : file)
  let out
  if (o.format === 'json') out = reportToJson(report) + '\n'
  else if (o.format === 'markdown') out = reportToMarkdown(report, title) + '\n'
  else if (o.format === 'sarif') out = reportToSarif(report, { uri: file === '-' ? 'agent-config' : file }) + '\n'
  else if (o.format === 'html') out = reportToHtml(report, title)
  else if (o.format === 'badge') out = badgeSvg(report.score, report.grade)
  else {
    const L = [`Agent security score: ${report.score}/100 (grade ${report.grade})  [${report.format}]`, '']
    for (const f of report.findings) L.push(`  ${f.severity.toUpperCase().padEnd(8)} ${f.id.padEnd(6)} ${f.title}`, `           ${f.detail}`)
    if (!report.findings.length) L.push('  No findings from the rule set (this does not prove the agent is safe).')
    out = L.join('\n') + '\n'
  }
  let code = 0
  const reasons = []
  if (o.failUnder !== undefined && report.score < o.failUnder) { code = 1; reasons.push(`score ${report.score} is below --fail-under ${o.failUnder}`) }
  if (o.failOn) {
    const lim = SEVERITY_ORDER.indexOf(o.failOn)
    const hit = report.findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= lim)
    if (hit.length) { code = 1; reasons.push(`${hit.length} finding(s) at or above ${o.failOn}`) }
  }
  return { code, out, report, reasons, outFile: o.out }
}

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  const res = run(process.argv.slice(2))
  if (res.outFile) { writeFileSync(res.outFile, res.out); process.stderr.write(`wrote ${res.outFile}\n`) } else process.stdout.write(res.out)
  if (res.notes) process.stderr.write(res.notes)
  if (res.reasons && res.reasons.length) process.stderr.write(`FAIL: ${res.reasons.join('; ')}\n`)
  process.exit(res.code)
}
