// Input parsing: JSON, a safe YAML subset, plain-text sections, and autodetection of common agent/tool schemas
// (OpenAI, Anthropic, LangChain, MCP server configs, multi-agent configs). Pure functions, no I/O.

export const MAX_INPUT_CHARS = 200000
export const MAX_TOOLS = 200
export const MAX_SAMPLES = 50
const MAX_AGENTS = 30
const MAX_YAML_LINES = 20000
const MAX_YAML_DEPTH = 40
const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

// ---------------- safe YAML subset ----------------
// Supports mappings, sequences, nested blocks, quoted/plain scalars, | and > block scalars, simple flow [] and {}.
// Anchors, aliases, tags, merge keys, multi-document files and tab indentation are rejected (throws). Output is plain data.
export function parseYaml(src) {
  const text = String(src).replace(/^\uFEFF/, '')
  if (/^\t/m.test(text)) throw new Error('tabs are not allowed for indentation')
  const raw = text.split(/\r?\n/)
  if (raw.length > MAX_YAML_LINES) throw new Error('too many lines')
  const lines = []
  let seenContent = false
  for (const l of raw) {
    if (/^\s*(#.*)?$/.test(l)) { lines.push({ blank: true, raw: l, indent: 0, text: '' }); continue }
    if (/^---\s*$/.test(l) && !seenContent) { lines.push({ blank: true, raw: '', indent: 0, text: '' }); continue }
    if (/^(---|\.\.\.)\s*$/.test(l)) throw new Error('multi-document YAML is not supported')
    seenContent = true
    lines.push({ blank: false, raw: l, indent: l.length - l.trimStart().length, text: l.trim() })
  }
  let pos = 0
  const skipBlank = () => { while (pos < lines.length && lines[pos].blank) pos++ }

  function stripComment(s) {
    let q = null
    for (let i = 0; i < s.length; i++) {
      const c = s[i]
      if (q) { if (c === q && s[i - 1] !== '\\') q = null } else if (c === '"' || c === "'") { if (i === 0 || /[\s[{,:]/.test(s[i - 1])) q = c } else if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i).trimEnd()
    }
    return s
  }
  function scalar(s) {
    s = s.trim()
    if (s === '') return null
    if (/^[&*!]/.test(s) || s.startsWith('<<')) throw new Error('anchors, aliases and tags are not supported')
    if (s[0] === '"') { if (!/"$/.test(s) || s.length < 2) throw new Error('bad quoted string'); return s.slice(1, -1).replace(/\\(["\\nt/])/g, (_, c) => ({ n: '\n', t: '\t' }[c] || c)) }
    if (s[0] === "'") { if (!/'$/.test(s) || s.length < 2) throw new Error('bad quoted string'); return s.slice(1, -1).replace(/''/g, "'") }
    if (s[0] === '[' || s[0] === '{') return flow(s)
    if (/^(true|True|TRUE)$/.test(s)) return true
    if (/^(false|False|FALSE)$/.test(s)) return false
    if (/^(null|Null|NULL|~)$/.test(s)) return null
    if (/^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(s) && s.length < 20) return Number(s)
    return s
  }
  function flow(s) {
    let i = 0
    const ws = () => { while (i < s.length && /\s/.test(s[i])) i++ }
    function val(depth) {
      if (depth > MAX_YAML_DEPTH) throw new Error('too deep')
      ws()
      if (s[i] === '[') {
        i++; const a = []
        for (;;) { ws(); if (s[i] === ']') { i++; return a } if (i >= s.length) throw new Error('unterminated ['); a.push(val(depth + 1)); ws(); if (s[i] === ',') i++; else if (s[i] !== ']') throw new Error('bad flow sequence') }
      }
      if (s[i] === '{') {
        i++; const o = {}
        for (;;) {
          ws(); if (s[i] === '}') { i++; return o } if (i >= s.length) throw new Error('unterminated {')
          const k = key(); ws(); if (s[i] !== ':') throw new Error('bad flow mapping'); i++
          const v = val(depth + 1); if (!BAD_KEYS.has(k)) o[k] = v
          ws(); if (s[i] === ',') i++; else if (s[i] !== '}') throw new Error('bad flow mapping')
        }
      }
      if (s[i] === '"' || s[i] === "'") { const q = s[i]; let j = i + 1; while (j < s.length && !(s[j] === q && s[j - 1] !== '\\')) j++; if (j >= s.length) throw new Error('unterminated string'); const lit = s.slice(i, j + 1); i = j + 1; return scalar(lit) }
      let j = i; while (j < s.length && !/[,\]}]/.test(s[j])) j++
      const lit = s.slice(i, j); i = j; return scalar(lit)
    }
    function key() {
      ws()
      if (s[i] === '"' || s[i] === "'") return String(val(0))
      let j = i; while (j < s.length && s[j] !== ':' && s[j] !== ',' && s[j] !== '}') j++
      const k = s.slice(i, j).trim(); i = j; return k
    }
    const v = val(0); ws()
    if (i < s.length) throw new Error('trailing characters in flow value')
    return v
  }
  function blockScalar(parentIndent, style) {
    const chunk = []
    let blockIndent = null
    while (pos < lines.length) {
      const ln = lines[pos]
      if (!/\S/.test(ln.raw)) { chunk.push(''); pos++; continue }
      const ind = ln.raw.length - ln.raw.trimStart().length
      if (ind <= parentIndent) break
      if (blockIndent === null) blockIndent = ind
      chunk.push(ln.raw.slice(Math.min(blockIndent, ind))); pos++
    }
    while (chunk.length && chunk[chunk.length - 1] === '') chunk.pop()
    const folded = style[0] === '>'
    let out = folded ? chunk.join('\n').replace(/([^\n])\n(?=[^\n])/g, '$1 ') : chunk.join('\n')
    if (style.includes('+') || !style.includes('-')) out += '\n'
    return out
  }
  const KEY_RE = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s:#\-?[\]{}&*!|>'"%@`][^:]*?|-[^\s:][^:]*?)\s*:(?:\s+(.*))?$/
  function block(indent, depth) {
    if (depth > MAX_YAML_DEPTH) throw new Error('too deep')
    skipBlank()
    if (pos >= lines.length) return null
    const first = lines[pos]
    if (/^-(\s|$)/.test(first.text)) return sequence(first.indent, depth)
    if (KEY_RE.test(stripComment(first.text))) return mapping(first.indent, depth)
    pos++
    return scalar(stripComment(first.text))
  }
  function sequence(indent, depth) {
    const arr = []
    for (;;) {
      skipBlank()
      if (pos >= lines.length) break
      const ln = lines[pos]
      if (ln.indent !== indent || !/^-(\s|$)/.test(ln.text)) { if (ln.indent > indent) throw new Error('unexpected indentation'); break }
      const rest = ln.text.replace(/^-\s*/, '')
      if (rest === '' || /^#/.test(rest)) { pos++; skipBlank(); const nx = lines[pos]; arr.push(nx && nx.indent > indent ? block(nx.indent, depth + 1) : null); continue }
      const body = stripComment(rest)
      if (KEY_RE.test(body) && !/^["'[{]/.test(body)) {
        const col = indent + (ln.text.length - rest.length)
        lines[pos] = { blank: false, raw: ' '.repeat(col) + rest, indent: col, text: rest }
        arr.push(mapping(col, depth + 1))
      } else { pos++; arr.push(scalar(body)) }
    }
    return arr
  }
  function mapping(indent, depth) {
    const obj = {}
    for (;;) {
      skipBlank()
      if (pos >= lines.length) break
      const ln = lines[pos]
      if (ln.indent < indent) break
      if (ln.indent > indent) throw new Error('unexpected indentation at line ' + (pos + 1))
      const m = stripComment(ln.text).match(KEY_RE)
      if (!m) throw new Error('not a mapping line: ' + (pos + 1))
      let k = m[1]
      if (k[0] === '"' || k[0] === "'") k = String(scalar(k))
      const rest = m[2] === undefined ? '' : m[2].trim()
      pos++
      let v
      if (/^[|>][+-]?\d?$/.test(rest)) v = blockScalar(indent, rest)
      else if (rest === '') {
        skipBlank()
        const nx = lines[pos]
        if (nx && (nx.indent > indent || (nx.indent === indent && /^-(\s|$)/.test(nx.text)))) v = block(nx.indent, depth + 1)
        else v = null
      } else v = scalar(rest)
      if (!BAD_KEYS.has(k)) obj[k] = v
    }
    return obj
  }
  const result = block(0, 0)
  skipBlank()
  if (pos < lines.length) throw new Error('unparsed content at line ' + (pos + 1))
  return result
}

// ---------------- schema autodetect + normalisation ----------------
function asBool(v) {
  if (v === true) return true
  return /^(true|yes|1|required|always)$/i.test(String(v ?? ''))
}
const str = (v, n) => (typeof v === 'string' ? v : v == null ? '' : typeof v === 'object' ? safeJson(v) : String(v)).slice(0, n)
function safeJson(v) { try { return JSON.stringify(v) ?? '' } catch { return '' } }

const BUILTIN_TYPES = [
  [/^code_interpreter/, 'code interpreter: executes code'],
  [/^file_search/, 'file search: retrieval of uploaded documents'],
  [/^web_search/, 'web search: browse the internet'],
  [/^computer/, 'computer use: browser and desktop control'],
  [/^bash/, 'bash: shell command execution'],
  [/^text_editor|^str_replace/, 'text editor: write file and edit file'],
  [/^mcp$/, 'remote MCP server'],
]
const MCP_HINTS = [
  [/filesystem|\bfs\b|file-system/i, 'filesystem: write file, delete file'],
  [/fetch|puppeteer|playwright|browser|brave|search|firecrawl|scrape|crawl/i, 'web fetch: browse url'],
  [/postgres|mysql|sqlite|database|supabase|mongo|\bsql\b/i, 'database: sql write query'],
  [/slack/i, 'slack: send message, read message'],
  [/gmail|\bmail\b|smtp|outlook/i, 'email: send email, read email inbox'],
  [/github|gitlab/i, 'git hosting: issue, pull request, create'],
  [/shell|terminal|command|\bexec|\bssh\b/i, 'shell: run command'],
  [/stripe|payment|paypal/i, 'payments: charge, refund'],
  [/kubernetes|k8s|terraform|\baws\b|azure|gcp|docker|cloudflare/i, 'infrastructure: deploy, admin, kubectl'],
  [/memory|mem0|zep|knowledge/i, 'memory: remember, save'],
]

function normTool(t) {
  if (typeof t === 'string') return { name: t.slice(0, 200), description: t.slice(0, 2000) }
  if (!t || typeof t !== 'object' || Array.isArray(t)) return null
  const fn = (t.function && typeof t.function === 'object') ? t.function : t
  const tname = typeof fn.name === 'string' && fn.name ? fn.name : typeof t.type === 'string' && t.type !== 'function' ? t.type : 'unnamed'
  const extra = []
  const skip = new Set(['name', 'description', 'parameters', 'input_schema', 'args_schema', 'args', 'function'])
  for (const k of Object.keys(fn)) if (!skip.has(k)) extra.push(`${k}: ${typeof fn[k] === 'object' ? safeJson(fn[k]) : fn[k]}`)
  const builtin = BUILTIN_TYPES.find(([re]) => re.test(String(t.type || '')))
  const confirm = fn.requires_confirmation ?? fn.require_confirmation ?? fn.confirmation ?? fn.human_approval ?? fn.approval ?? fn.require_approval ?? fn.needs_approval ?? fn.needsApproval ?? fn.confirm
  const params = fn.parameters ?? fn.input_schema ?? fn.args_schema ?? fn.args
  return {
    name: String(tname).slice(0, 200),
    description: [typeof fn.description === 'string' ? fn.description : '', builtin ? builtin[1] : '', ...extra].filter(Boolean).join(' ').trim().slice(0, 5000),
    confirm: confirm === undefined ? undefined : (/^never$/i.test(String(confirm)) ? false : asBool(confirm)),
    readOnly: fn.read_only === true || fn.readonly === true || fn.readOnly === true,
    params: params ? safeJson(params).slice(0, 5000) : '',
    ...(Array.isArray(fn.handoffs) ? { handoffs: fn.handoffs.slice(0, 20).map((x) => str(x, 80)) } : {}),
  }
}

function mcpServersToTools(servers) {
  const out = []
  for (const [key, s] of Object.entries(servers).slice(0, MAX_TOOLS)) {
    if (!s || typeof s !== 'object' || BAD_KEYS.has(key)) continue
    const args = Array.isArray(s.args) ? s.args.map((a) => str(a, 300)).slice(0, 40) : []
    const cmd = str(s.command, 200)
    const url = str(s.url ?? s.serverUrl ?? s.endpoint, 500)
    const launch = [cmd, ...args].join(' ')
    const hay = `${key} ${launch} ${url}`
    const hints = MCP_HINTS.filter(([re]) => re.test(hay)).map(([, h]) => h)
    const env = s.env && typeof s.env === 'object' ? Object.entries(s.env).slice(0, 40).map(([k, v]) => `${k}=${str(v, 300)}`) : []
    const hdr = s.headers && typeof s.headers === 'object' ? Object.entries(s.headers).slice(0, 20).map(([k, v]) => `${k}: ${str(v, 300)}`) : []
    const auto = Array.isArray(s.autoApprove) ? s.autoApprove : Array.isArray(s.alwaysAllow) ? s.alwaysAllow : []
    out.push({
      name: `mcp:${key}`.slice(0, 200),
      description: ['MCP server', hints.join('; '), auto.length ? `auto-approved tools: ${auto.slice(0, 10).map((x) => str(x, 40)).join(', ')} (no approval)` : ''].filter(Boolean).join(' ').slice(0, 2000),
      confirm: auto.length ? false : undefined,
      readOnly: false,
      params: [launch, ...env, ...hdr].join('\n').slice(0, 5000),
      mcp: { key: key.slice(0, 100), command: cmd, args, url, hasAuth: hdr.some((h) => /^authorization|x-api-key/i.test(h)) || /token|key|auth/i.test(env.map((e) => e.split('=')[0]).join(' ')) },
    })
  }
  return out
}

function systemFrom(o) {
  const direct = o.system_prompt ?? o.systemPrompt ?? o.prompt ?? o.instructions ?? o.system ?? o.system_message ?? o.systemMessage ?? o.developer_prompt ?? ''
  if (Array.isArray(direct)) return direct.map((b) => (typeof b === 'string' ? b : str(b && b.text, MAX_INPUT_CHARS))).join('\n')
  if (direct && typeof direct === 'object') return str(direct.text ?? direct.content ?? direct, MAX_INPUT_CHARS)
  return str(direct, MAX_INPUT_CHARS)
}
function contentText(c) {
  if (typeof c === 'string') return c
  if (Array.isArray(c)) return c.map((p) => (typeof p === 'string' ? p : str(p && p.text, 20000))).join('\n')
  return ''
}

const KNOWN_KEYS = new Set(['system_prompt', 'systemPrompt', 'prompt', 'instructions', 'system', 'system_message', 'systemMessage', 'developer_prompt', 'tools', 'functions', 'permissions', 'sample_outputs', 'sampleOutputs', 'outputs', 'samples', 'name', '_label', 'messages', 'agents', 'mcpServers', 'servers', 'mcp', 'model', 'agent'])
const RECOGNIZED = ['system_prompt', 'systemPrompt', 'prompt', 'instructions', 'system', 'system_message', 'tools', 'functions', 'permissions', 'mcpServers', 'servers', 'agents', 'messages', 'mcp', 'agent']

export function hasRecognizedKeys(o) {
  return !!o && typeof o === 'object' && !Array.isArray(o) && Object.keys(o).some((k) => RECOGNIZED.includes(k))
}

export function normalize(input) {
  let o = input
  const empty = { systemPrompt: '', tools: [], samples: [], agents: [], configText: '', format: 'empty' }
  if (Array.isArray(o)) o = { tools: o }
  if (!o || typeof o !== 'object') return empty
  const fmts = []
  if (o.agent && typeof o.agent === 'object' && !Array.isArray(o.agent) && !o.system_prompt && !o.tools) o = { ...o, ...o.agent }
  let servers = null
  for (const cand of [o.mcpServers, o.servers, o.mcp && o.mcp.servers, o.mcp && o.mcp.mcpServers]) if (cand && typeof cand === 'object' && !Array.isArray(cand)) { servers = cand; break }
  let sp = systemFrom(o)
  const samples = []
  if (Array.isArray(o.messages)) {
    const sys = []
    for (const m of o.messages.slice(0, 200)) {
      if (!m || typeof m !== 'object') continue
      const txt = contentText(m.content).slice(0, MAX_INPUT_CHARS)
      if ((m.role === 'system' || m.role === 'developer') && txt) sys.push(txt)
      else if (m.role === 'assistant' && txt) samples.push(txt)
    }
    if (sys.length) { sp = [sp, ...sys].filter(Boolean).join('\n'); fmts.push('chat-messages') }
  }
  const tl = o.tools ?? o.functions ?? o.permissions ?? []
  const rawTools = Array.isArray(tl) ? tl : (tl && typeof tl === 'object' ? Object.entries(tl).map(([k, v]) => (v && typeof v === 'object' ? { name: k, ...v } : { name: k, description: String(v) })) : [])
  const tools = rawTools.slice(0, MAX_TOOLS).map(normTool).filter(Boolean)
  const sniff = rawTools.find((t) => t && typeof t === 'object')
  if (sniff) {
    if (sniff.input_schema || /^(bash|computer|text_editor)_\d/.test(String(sniff.type || ''))) fmts.push('anthropic-tools')
    else if (sniff.args_schema || sniff.return_direct !== undefined || (sniff.args && !sniff.parameters)) fmts.push('langchain-tools')
    else if (sniff.type === 'function' || sniff.function || ['code_interpreter', 'file_search', 'web_search', 'mcp'].includes(sniff.type)) fmts.push('openai-tools')
  }
  if (servers) { tools.push(...mcpServersToTools(servers)); fmts.push('mcp-config') }
  const agents = []
  const ag = o.agents
  const agList = Array.isArray(ag) ? ag : ag && typeof ag === 'object' ? Object.entries(ag).map(([k, v]) => (v && typeof v === 'object' ? { name: k, ...v } : null)) : []
  for (const a of agList.slice(0, MAX_AGENTS)) {
    if (!a || typeof a !== 'object') continue
    const aname = str(a.name, 80) || `agent-${agents.length + 1}`
    const ap = systemFrom(a)
    const at = (Array.isArray(a.tools) ? a.tools : []).slice(0, MAX_TOOLS).map(normTool).filter(Boolean)
    const handoffs = [...(Array.isArray(a.handoffs) ? a.handoffs : []), ...(Array.isArray(a.delegates) ? a.delegates : []), ...(Array.isArray(a.can_delegate_to) ? a.can_delegate_to : [])].slice(0, 20).map((h) => str(typeof h === 'object' && h ? h.name : h, 80))
    agents.push({ name: aname, handoffs, tools: at.map((t) => t.name), prompt: ap })
    if (ap) sp = [sp, `## Agent: ${aname}\n${ap}`].filter(Boolean).join('\n')
    for (const t of at) if (tools.length < MAX_TOOLS) tools.push({ ...t, agent: aname })
  }
  if (agents.length) fmts.push('multi-agent')
  const so = o.sample_outputs ?? o.sampleOutputs ?? o.outputs ?? o.samples ?? []
  for (const x of (Array.isArray(so) ? so : [so]).slice(0, MAX_SAMPLES)) samples.push(typeof x === 'string' ? x : safeJson(x))
  const cfgParts = []
  for (const [k, v] of Object.entries(o)) {
    if (KNOWN_KEYS.has(k) || BAD_KEYS.has(k)) continue
    cfgParts.push(`${k}: ${typeof v === 'object' ? safeJson(v) : String(v)}`)
  }
  if (o.mcp && typeof o.mcp === 'object') { const { servers: _s, mcpServers: _m, ...restMcp } = o.mcp; if (Object.keys(restMcp).length) cfgParts.push('mcp: ' + safeJson(restMcp)) }
  if (!fmts.length) fmts.push('generic')
  return {
    systemPrompt: sp.slice(0, MAX_INPUT_CHARS),
    tools: tools.slice(0, MAX_TOOLS),
    samples: samples.slice(0, MAX_SAMPLES).map((x) => x.slice(0, MAX_INPUT_CHARS)),
    agents,
    configText: cfgParts.join('\n').slice(0, 20000),
    format: fmts.join('+'),
  }
}

function parseText(text) {
  const sec = { prompt: [], tools: [], samples: [] }
  let cur = 'prompt'
  let sawHeader = false
  for (const line of text.split(/\r?\n/)) {
    const h = line.match(/^\s*#{0,3}\s*(system[ _-]?prompt|prompt|tools?|tool list|permissions|sample[ _-]?outputs?|outputs?|examples?)\s*:?\s*$/i)
    if (h) {
      sawHeader = true
      const k = h[1].toLowerCase()
      cur = /tool|permission/.test(k) ? 'tools' : /output|example|sample/.test(k) ? 'samples' : 'prompt'
      continue
    }
    const inline = line.match(/^\s*(system[ _-]?prompt|tools?|sample[ _-]?outputs?)\s*:\s*(.+)$/i)
    if (inline && !sawHeader) {
      sawHeader = true
      cur = /tool/i.test(inline[1]) ? 'tools' : /sample/i.test(inline[1]) ? 'samples' : 'prompt'
      sec[cur].push(inline[2]); continue
    }
    sec[cur].push(line)
  }
  const tools = sec.tools.map((l) => l.trim()).filter((l) => l && !/^[-*•\s]*(none|n\/a|na|no tools?|nil|-+)\.?$/i.test(l)).map((l) => {
    const m = l.replace(/^[-*•\d.)\s]+/, '').match(/^`?([A-Za-z0-9_.\-/ ]{1,60}?)`?\s*(?:[:\u2014\u2013]|\s-\s|\()\s*(.*)$/)
    return m ? { name: m[1].trim(), description: m[2].replace(/\)\s*$/, '') } : { name: l.replace(/^[-*•\d.)\s]+/, '').slice(0, 60), description: l }
  })
  const samples = sec.samples.join('\n').split(/\n\s*---+\s*\n/).map((s) => s.trim()).filter(Boolean).slice(0, MAX_SAMPLES)
  return { systemPrompt: sec.prompt.join('\n').trim(), tools: tools.slice(0, MAX_TOOLS), samples, agents: [], configText: '', format: 'text' }
}

export function parseInput(raw) {
  let text = String(raw ?? '').slice(0, MAX_INPUT_CHARS * 10).trim()
  if (!text) return { systemPrompt: '', tools: [], samples: [], agents: [], configText: '', format: 'empty' }
  if (text[0] === '{' || text[0] === '[') {
    try { const j = JSON.parse(text); if (j && typeof j === 'object') { const n = normalize(j); n.format = 'json:' + n.format; return n } } catch { /* fall through */ }
  }
  text = text.slice(0, MAX_INPUT_CHARS)
  if (/^[\w"'.-][^\n]*:(\s|$)|^---/.test(text.split(/\r?\n/).find((l) => l.trim() && !l.trim().startsWith('#')) || '')) {
    try {
      const y = parseYaml(text)
      if (hasRecognizedKeys(y)) { const n = normalize(y); n.format = 'yaml:' + n.format; return n }
    } catch { /* not YAML, treat as text */ }
  }
  return parseText(text)
}
