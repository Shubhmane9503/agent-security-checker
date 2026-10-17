// AI Agent Security Checker: deterministic rule engine (v2).
// Pure functions, no I/O, no network. Runs in the browser and in Node (tests, CLI, sample generation).
import { SEVERITY_WEIGHT, SEVERITY_ORDER, CATEGORIES, CATALOG, OWASP, ATLAS } from './lib/meta.js'
import { parseInput, normalize, MAX_INPUT_CHARS } from './lib/parse.js'

export { SEVERITY_WEIGHT, SEVERITY_ORDER, CATEGORIES, CATALOG, OWASP, ATLAS, parseInput, MAX_INPUT_CHARS }
export const ENGINE_VERSION = '2.0.0'
export const LOSS_SCALE = 0.6
export const CATEGORY_CAP = 40

// ---------- secret / PII patterns (all bounded, linear-time) ----------
export const SECRET_PATTERNS = [
  ['AWS access key ID', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['AWS secret access key', /\baws_?secret_?access_?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}\b/i],
  ['Stripe secret key', /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/],
  ['OpenAI/Anthropic-style API key', /\bsk-[A-Za-z0-9_-]{16,}\b/],
  ['GitHub fine-grained token', /\bgithub_pat_[A-Za-z0-9_]{22,}\b/],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{20,}\b/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/],
  ['Slack webhook URL', /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]{6,}\/[A-Z0-9]{6,}\/[A-Za-z0-9]{16,}/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{30,}\b/],
  ['SendGrid API key', /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/],
  ['Azure storage account key', /\bAccountKey=[A-Za-z0-9+/=]{40,}/],
  ['Private key block', /-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----/],
  ['Bearer token', /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/],
  ['JWT', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/],
  ['Database URL with password', /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/]{1,100}:[^\s@/]{1,200}@[^\s/]{1,200}/i],
  ['Inline password or secret', /\b(?:password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*["']?(?!\s)(?!\d+["']?(?:\s|$|[.,;]))(?!(?:<|\{|\$|your|xxx|\*\*\*|redacted|placeholder|changeme|true\b|false\b|null\b|none\b))[^\s"']{6,}/i],
  ['Inline token', /\btoken\s*[:=]\s*["']?(?!(?:<|\{|\$|your|xxx|\*\*\*|redacted|placeholder|changeme))(?=[^\s"']*[A-Za-z])(?=[^\s"']*\d)[^\s"']{16,}/i],
]
const PII_PATTERNS = [
  ['email address', /\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,255}\.[A-Z]{2,24}\b/i],
  ['US SSN', /\b\d{3}-\d{2}-\d{4}\b/],
  ['payment card number', /\b(?:\d[ -]?){13,16}\b/],
  ['IBAN', /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/],
  ['phone number', /\b\+?\d{1,3}[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}\b/],
]

export function maskSecret(s) {
  const t = String(s)
  return t.length <= 8 ? '****' : t.slice(0, 3) + '…' + '*'.repeat(4) + ' (' + t.length + ' chars)'
}
function maskPii(label, s) {
  const t = String(s)
  if (label === 'email address') { const [u, d] = t.split('@'); return `${u.slice(0, 1)}***@${d}` }
  const digits = t.replace(/\D/g, '')
  if (digits.length >= 4) return '*'.repeat(Math.max(0, digits.length - 4)) + digits.slice(-4)
  return '****'
}

/** Find secrets in text. Returns one entry per pattern with the match masked. */
export function scanSecrets(text) {
  const out = []
  const s = String(text ?? '')
  for (const [label, re] of SECRET_PATTERNS) { const m = s.match(re); if (m) out.push({ label, masked: maskSecret(m[0]) }) }
  return out
}
function mod97(iban) {
  const r = (iban.slice(4) + iban.slice(0, 4)).replace(/[A-Z]/g, (c) => c.charCodeAt(0) - 55)
  let rem = 0
  for (const ch of r) rem = (rem * 10 + +ch) % 97
  return rem === 1
}
/** Find personal data in text (email, SSN, Luhn-valid card, IBAN with checksum, phone). One entry per kind, masked. */
export function scanPII(text) {
  const out = []
  const s = String(text ?? '')
  for (const [label, re] of PII_PATTERNS) {
    let hit = null
    if (label === 'payment card number' || label === 'IBAN') {
      let n = 0
      for (const m of s.matchAll(new RegExp(re.source, 'g'))) {
        if (++n > 100) break
        if (label === 'payment card number' ? luhn(m[0]) : mod97(m[0])) { hit = m[0]; break }
      }
    } else { const m = s.match(re); if (m) hit = m[0] }
    if (hit) out.push({ label, masked: maskPii(label, hit) })
  }
  return out
}

const TOOL_KINDS = [
  ['shell', 'shell / code execution', /\b(shell|bash|terminal|exec(ute)?|run[_ -]?(command|code|script)|subprocess|eval|python[_ -]?repl|code[_ -]?interpreter|ssh)\b/i, 'critical'],
  ['payment', 'payment / money movement', /\b(pay(ment)?s?|transfer|refund|charge|wire|purchase|checkout|invoice|stripe|paypal|billing)\b/i, 'critical'],
  ['file_write', 'file write / delete', /\b(write[_ -]?file|file[_ -]?write|edit[_ -]?file|save[_ -]?file|delete[_ -]?file|remove[_ -]?file|rm\b|filesystem|file[_ -]?system|upload|overwrite|append[_ -]?file|create[_ -]?file)\b/i, 'high'],
  ['email', 'email / messaging send', /\b(send[_ -]?(email|mail|message|sms|slack)|email[_ -]?send|post[_ -]?message|smtp|notify|reply[_ -]?all|forward)\b/i, 'high'],
  ['network', 'network / HTTP request', /\b(http[_ -]?request|fetch[_ -]?url|web[_ -]?request|curl|webhook|post[_ -]?request|http[_ -]?post|api[_ -]?call|browse|browser|navigate|web[_ -]?(search|fetch|browse))\b/i, 'high'],
  ['db_write', 'database write', /\b(sql|database|db)[_ -]?(write|update|insert|delete|exec(ute)?|query)\b|\b(update|delete|drop)[_ -]?(record|row|table|user)s?\b/i, 'high'],
  ['admin', 'identity / admin changes', /\b(create[_ -]?user|grant|iam|set[_ -]?role|reset[_ -]?password|deploy|terraform|kubectl|admin)\b/i, 'high'],
]
const READ_ONLY = /\b(read[- ]?only|readonly|no write|cannot (write|modify|send)|search[_ -]?only)\b/i
const CONFIRM = /\b(confirm(ation)?|approv(e|al|ed)|human[- ]in[- ]the[- ]loop|hitl|ask(s)? (the )?user|user (must )?(approve|consent)|manual review|review before)\b/i
const SCOPE = /\b(allow[- ]?list(ed)?|whitelist(ed)?|scoped?|restricted to|limited to|only (to|within|in|for)|sandbox(ed)?|read[- ]?only|chroot|jail(ed)?|max(imum)?[_ -]?(amount|spend)|cap(ped)? at|under \$?\d|domain[s]? (allowed|limited)|least[- ]privilege|directory\s*[:=]|path\s*[:=]|allowed_(paths|domains|commands|recipients))\b/i
const UNTRUSTED_TOOL = /\b(browse|browser|web[_ -]?(search|fetch|browse|page)|fetch[_ -]?url|scrape|read[_ -]?(email|inbox|mail)|inbox|search[_ -]?(email|mail)|rag|retriev(e|al)|knowledge[_ -]?base|read[_ -]?file|open[_ -]?file|ticket|issue[s]?|pull[_ -]?request|document|pdf|transcript|rss|slack[_ -]?read|read[_ -]?message)\b/i
const EXFIL_KINDS = ['email', 'network']

// ---------- helpers ----------
const F = (id, severity, detail, evidence) => ({ id, severity, title: CATALOG[id].title, cat: CATALOG[id].cat, fix: CATALOG[id].fix, owasp: CATALOG[id].owasp, atlas: CATALOG[id].atlas, detail, ...(evidence ? { evidence } : {}) })

const PRIVATE_DATA = /\b(customers?|patients?|employees?|accounts?|user data|personal|pii|credentials?|secrets?|confidential|internal|private|records?|crm|ticket|email|inbox|database|payroll|medical|financial|invoices?|salesforce)\b/i
const toolText = (t) => `${t.name} ${t.description}`
const allText = (inp) => [inp.systemPrompt, inp.configText || '', ...inp.tools.map((t) => `${toolText(t)} ${t.params || ''}`)].join('\n')
const isGuarded = (t) => t.confirm === true || CONFIRM.test(toolText(t)) || SCOPE.test(toolText(t))

function classifyTool(t) {
  const hay = `${t.name} ${t.description}`
  const kinds = []
  for (const [k, label, re, sev] of TOOL_KINDS) if (re.test(t.name) || re.test(hay)) kinds.push({ k, label, sev })
  return kinds
}

function checkInjection(inp, tools, ctx = {}) {
  const out = []
  const p = inp.systemPrompt
  const hierarchy = /(system|developer)\s+(instructions?|prompt|messages?)\s+(take|have|override|supersede|outrank)|(never|do not|don't|must not)\s+(follow|obey|execute|act on)\s+(any\s+)?(instructions?|commands?|directives?)\s+(found|contained|embedded|that appear|inside|in|from)|(treat|consider)\s+[^.]{0,80}\s+as\s+(untrusted|data|information only)|ignore\s+(any\s+)?instructions?\s+(in|inside|within|from)|(only|solely)\s+(follow|obey)\s+(the\s+)?(system|developer|operator)/i
  if (p && !hierarchy.test(p)) out.push(F('PI-1', 'high', 'The prompt never says system instructions outrank content the agent reads, or that embedded instructions must be ignored.'))
  if (!p) out.push(F('PI-1', 'medium', 'No system prompt supplied, so no instruction hierarchy can be confirmed.'))

  const untrustedVars = [...p.matchAll(/\{\{?\s*([a-z_][a-z0-9_.]*?(?:doc|document|content|email|message|page|web|input|query|text|ticket|retriev\w*|context|file|body|transcript|user\w*)[a-z0-9_.]*)\s*\}?\}|\$\{\s*([a-z_][\w.]*)\s*\}|<<\s*([a-z_]\w*)\s*>>/gi)]
  const VARNAME = /doc|content|email|message|page|web|input|query|text|ticket|retriev|context|file|body|transcript|user|result|data|comment|issue/i
  const vars = untrustedVars.map((m) => m[1] || (VARNAME.test(m[2] || '') ? m[2] : '') || (VARNAME.test(m[3] || '') ? m[3] : '')).filter(Boolean)
  const inlineMention = /\b(here is|below is|the following|paste[sd]?|attached|insert(ed)?)\b[^\n]{0,60}\b(email|document|web ?page|ticket|message|content|file|transcript)\b/i.test(p) && !vars.length
  const uniq = [...new Set(vars)]
  ctx.vars = uniq
  if (uniq.length) out.push(F('PI-2', 'high', `Template placeholders inject external text into the prompt: ${uniq.slice(0, 5).map((v) => '{' + v + '}').join(', ')}.`))
  const delim = /(<\/?[a-z_][\w-]*>|```|"""|'''|={3,}|-{3,}\s*(begin|start|end)|\[\/?(document|content|data|untrusted)[^\]]*\]|BEGIN [A-Z ]+|END [A-Z ]+)/i
  if ((uniq.length || inlineMention) && !delim.test(p)) out.push(F('PI-3', 'high', 'External content is referenced but no delimiter (XML tags, fences, begin/end markers) separates it from instructions.'))
  else if (uniq.length && !/(untrusted|data only|not instructions|do not (follow|execute))/i.test(p)) out.push(F('PI-3', 'medium', 'Delimiters exist, but the prompt does not say the delimited text is data only.'))

  const reads = tools.filter((t) => UNTRUSTED_TOOL.test(`${t.name} ${t.description}`))
  if (reads.length && !/(untrusted|data only|not instructions|ignore (any )?instructions|never (follow|act on)|do not (follow|act on))/i.test(p))
    out.push(F('PI-4', 'medium', `Tools that bring in outside content (${reads.slice(0, 4).map((t) => t.name).join(', ')}) but the prompt gives no handling rules for it.`))

  inp.samples.forEach((s, i) => {
    if (/ignore (all |any )?(previous|prior|above) instructions|as instructed in the (document|email|page)|new instructions:|(my|the) system prompt (is|says|reads)|here (is|are) my (system )?(prompt|instructions)|i('| a)m now in (developer|dan|debug) mode/i.test(s))
      out.push(F('PI-5', 'high', `Sample output #${i + 1} contains injection-style phrasing or discloses the prompt.`))
  })
  return out
}

function checkPermissions(inp, tools) {
  const out = []
  const risky = []
  for (const t of tools) {
    const kinds = classifyTool(t)
    if (!kinds.length) continue
    const hay = `${t.name} ${t.description}`
    const lookupName = /^(get|list|view|read|lookup|look[_ -]?up|show|check|find|search)[_ -]/i.test(t.name)
    const writeVerb = /\b(transfer|refund|charge|wire|pay|purchase|create|update|delete|send|grant|reset|deploy|set)\b/i.test(hay.replace(/\bread[- ]?only\b/ig, ''))
    if (t.readOnly || (READ_ONLY.test(hay) && !kinds.some((k) => k.k === 'shell')) || (lookupName && !writeVerb && kinds.every((k) => ['payment', 'admin'].includes(k.k)))) continue
    const top = kinds.sort((a, b) => SEVERITY_ORDER.indexOf(a.sev) - SEVERITY_ORDER.indexOf(b.sev))[0]
    const confirmed = t.confirm === true || (t.confirm === undefined && CONFIRM.test(hay) && !/\b(no|without|never|skip)\s+(human\s+)?(confirm|approv)/i.test(hay))
    const scoped = SCOPE.test(hay)
    risky.push({ t, kinds, top })
    const lowRiskScoped = scoped && top.sev === 'high'
    if (!confirmed && !lowRiskScoped) out.push(F('TP-1', top.sev, `Tool "${t.name}" (${top.label}) has no confirmation or approval step.`))
    if (!scoped) out.push(F('TP-2', top.sev === 'critical' ? 'high' : 'medium', `Tool "${t.name}" (${top.label}) shows no scoping such as an allowlist, sandbox, path or amount limit.`))
    if (/^(run_?any|exec(ute)?_?(any|arbitrary)|shell|bash|http_?request|fetch_?any|any_?url)\b|\b(any|arbitrary|unrestricted|unlimited)\s+(command|shell|url|code|file|sql|query)s?\b/i.test(hay) || (/^(shell|bash|terminal|run_command|execute|exec)$/i.test(t.name) && !scoped))
      out.push(F('TP-5', 'high', `Tool "${t.name}" looks general-purpose and unrestricted.`))
  }
  const reads = tools.filter((t) => UNTRUSTED_TOOL.test(`${t.name} ${t.description}`) )
  const exfil = risky.filter((r) => r.kinds.some((k) => EXFIL_KINDS.includes(k.k)))
  if (reads.length && exfil.length) {
    const unguarded = exfil.filter((r) => !(r.t.confirm === true || CONFIRM.test(`${r.t.name} ${r.t.description}`) || SCOPE.test(`${r.t.name} ${r.t.description}`)))
    if (unguarded.length) out.push(F('TP-3', 'critical', `Can read outside content (${reads.slice(0, 3).map((t) => t.name).join(', ')}) and send data out (${unguarded.slice(0, 3).map((r) => r.t.name).join(', ')}) without approval.`))
  }
  if (/\b(never|don't|do not|without)\s+(ask(ing)?|request(ing)?|wait(ing)?)\b[^.\n]{0,40}\b(confirm|permission|approv|user)|\bfully\s+autonomous(ly)?\b|\bact\s+autonomously\b|\bwithout\s+(asking|confirmation|approval)\b|\bno\s+need\s+to\s+(ask|confirm)\b/i.test(inp.systemPrompt))
    out.push(F('TP-4', risky.length ? 'high' : 'medium', 'The system prompt tells the agent to act without confirmation.'))
  return out
}


function checkLeakage(inp, tools) {
  const out = []
  const all = [['system prompt', inp.systemPrompt], ...(inp.configText ? [['config', inp.configText]] : []), ...tools.map((t) => [`tool "${t.name}"`, `${t.description} ${t.params || ''}`])]
  const seen = new Set()
  for (const [where, txt] of all) {
    for (const s of scanSecrets(txt)) {
      if (!seen.has(s.label + where)) { seen.add(s.label + where); out.push(F('DL-1', 'critical', `${s.label} found in the ${where}.`, s.masked)) }
    }
  }
  const filterRe = /(redact|mask(ing)?|sanitis|sanitiz|output (filter|guard|check|validation)|dlp|pii (filter|scrub)|content filter|post-?process|block(ed)? (patterns|secrets|domains)|allowlisted? (domains|links)|strip (links|images))/i
  const touchesData = /\b(customer|patient|employee|account|user data|personal|pii|credential|secret|confidential|internal|private|records?|crm|ticket|email|inbox|database)\b/i.test(inp.systemPrompt + ' ' + tools.map((t) => t.description).join(' '))
  const hasOutbound = tools.some((t) => classifyTool(t).some((k) => EXFIL_KINDS.includes(k.k)))
  if (!filterRe.test(inp.systemPrompt + ' ' + tools.map((t) => t.description).join(' ')) && (touchesData || hasOutbound || tools.length))
    out.push(F('DL-2', touchesData || hasOutbound ? 'high' : 'medium', 'No output filtering, redaction or link/image allowlisting is described.'))
  const piiHandling = /(minimi[sz]|mask|redact|anonymi[sz]|pseudonymi[sz]|do not (log|store|share|repeat|include)[^.]{0,40}(pii|personal|ssn|card)|only (the )?(last|first) \d)/i
  if (/\b(pii|personal (data|information)|ssn|social security|date of birth|dob|card number|medical|health|patient|customer[_ ](data|records?|details|history)|credit card|card number)\b/i.test(inp.systemPrompt + ' ' + tools.map((t) => t.description).join(' ')) && !piiHandling.test(inp.systemPrompt))
    out.push(F('DL-3', 'medium', 'PII is in scope but the prompt has no minimisation, masking or logging rules.'))
  if (/\b(do not|don't|never)\s+(reveal|disclose|share|repeat|show|output)\b[^.\n]{0,50}\b(system prompt|instructions|these rules|prompt)\b|\bkeep\b[^.\n]{0,30}\b(prompt|instructions)\b[^.\n]{0,20}\b(secret|confidential)\b|\b(confidential|secret)\b[^.\n]{0,30}\b(do not|never)\b/i.test(inp.systemPrompt)
      && (touchesData || /\b(internal|discount|pricing|api|endpoint|policy|rules?)\b/i.test(inp.systemPrompt)))
    out.push(F('DL-4', 'low', 'The prompt relies on "do not reveal" wording as its only protection.'))
  inp.samples.forEach((s, i) => {
    for (const x of scanSecrets(s)) out.push(F('DL-5', 'critical', `Sample output #${i + 1} contains a ${x.label}.`, x.masked))
    for (const x of scanPII(s)) out.push(F('DL-5', 'high', `Sample output #${i + 1} contains a ${x.label}.`, x.masked))
  })
  // personal identifiers embedded in the prompt/config themselves (emails are normal there, so only high-risk kinds count)
  const embedded = scanPII(inp.systemPrompt + '\n' + (inp.configText || '')).filter((x) => ['US SSN', 'payment card number', 'IBAN'].includes(x.label))
  for (const x of embedded) out.push(F('DL-6', 'high', `A ${x.label} appears in the prompt or config.`, x.masked))
  return out
}

function checkAgentic(inp, tools, ctx) {
  const out = []
  const p = `${inp.systemPrompt}\n${inp.configText || ''}`
  const names = tools.map((t) => t.name)
  const hasRisky = tools.some((t) => classifyTool(t).length)
  const multi = (inp.agents && inp.agents.length > 1) || /\b(hand[- ]?offs?|sub-?agents?|delegat(e|es|ed|ion)\s+to|orchestrator|multi-?agent|transfer[_ ]to[_ ]\w+|route[sd]?\s+to\s+(the\s+)?\w+\s+agent|another agent|other agents)\b/i.test(p) || names.some((n) => /^(transfer_to_|handoff|delegate|call_agent|ask_agent)/i.test(n))
  const handoffMitigated = /(messages?|output|text|results?|requests?|responses?)\s+(from|of)\s+(other|another|sub|upstream|peer)\s*-?agents?\s+(is|are|as|must be|should be)\s+(untrusted|data|unverified)|treat\s+[^.]{0,60}\bagents?\b[^.]{0,40}\b(untrusted|data|unverified)|validate[^.]{0,40}(hand-?off|agent)|structured[^.]{0,30}(hand-?off|fields)|re-?check[^.]{0,30}permissions/i.test(p)
  if (multi && !handoffMitigated) out.push(F('MA-1', hasRisky ? 'high' : 'medium', `Multi-agent or handoff behaviour is present${inp.agents && inp.agents.length ? ` (${inp.agents.length} agents)` : ''} but nothing says messages from other agents are untrusted or validated.`))
  const spawners = tools.filter((t) => /\b(spawn|create[_ -]?agent|start[_ -]?agent|sub-?agents?|delegate|fork[_ -]?agent)\b/i.test(toolText(t)))
  if (spawners.length && !/\b(max(imum)?[_ -]?(depth|agents?|sub-?agents?)|depth (limit|of \d)|at most \d+ (sub-?)?agents?|limited to \d+ (sub-?)?agents?)\b/i.test(p + spawners.map(toolText).join(' ')))
    out.push(F('MA-2', 'medium', `Tool "${spawners[0].name}" can start or delegate to other agents with no stated depth or count limit.`))
  const memTools = tools.filter((t) => /\b(memory|remember|save[_ -]?memory|store[_ -]?memory|vector[_ -]?(store|db)|upsert|long[- ]term)\b/i.test(toolText(t)) && /\b(save|store|write|remember|add|upsert|update|append|persist)\b/i.test(toolText(t)))
  const memPrompt = /\b(long[- ]term memory|persistent memory|remember\s+(anything|things|facts|what|information|details|preferences)|remember[^.\n]{0,40}\b(web|page|email|document)s?\b|save[^.\n]{0,30}to memory|store[^.\n]{0,30}\bmemory\b|memory (is|are) (written|updated))\b/i.test(p)
  const memWritable = memTools.length > 0 || memPrompt
  const memMitigated = /(only (store|save|remember)[^.]{0,60}(user|confirmed|stated)|never (store|save|remember)[^.]{0,60}(instructions?|content|web|email)|validate[^.]{0,30}memor|memory[^.]{0,40}(review|approval|confirm)|tag[^.]{0,30}source|user[^.]{0,20}(review|delete)[^.]{0,20}memor)/i.test(p)
  if (memWritable && !memMitigated) {
    const untrusted = (ctx.reads && ctx.reads.length > 0) || (ctx.vars && ctx.vars.length > 0)
    out.push(F('MM-1', untrusted ? 'high' : 'medium', untrusted ? 'Persistent memory can be written while the agent also reads untrusted content, and no write validation is described.' : 'Persistent memory is writable and no validation of what gets stored is described.'))
  }
  if (/\bshared (memory|vector|index|knowledge base|store)\b|memory (is )?shared (across|between|among) (all )?(users|customers|tenants|sessions)|(all|every) (users|customers|tenants)[^.\n]{0,40}(same|shared) (memory|index|store)|global memory/i.test(p) && !/(per[- ](user|tenant|customer)|isolated|partition|namespace)/i.test(p))
    out.push(F('MM-2', 'high', 'Memory or retrieval is described as shared across users, tenants or sessions, with no isolation described.'))
  const tri = ctx.trifecta
  if (tri && tri.complete && !tri.gated) out.push(F('LT-1', 'critical', `Private data (${tri.privateData.evidence.slice(0, 2).join(', ')}), untrusted content (${tri.untrusted.evidence.slice(0, 2).join(', ')}) and an outbound channel (${tri.external.evidence.slice(0, 2).join(', ')}) are all reachable, with the outbound channel unguarded.`))
  return out
}

function checkGovernance(inp, tools, ctx) {
  const out = []
  const p = `${inp.systemPrompt}\n${inp.configText || ''}`
  for (const t of tools) {
    const m = t.mcp
    if (!m) continue
    const cmd = (m.command || '').split(/[\\/]/).pop().toLowerCase().replace(/\.(cmd|exe)$/, '')
    const args = m.args || []
    const pkg = args.find((a) => a && !a.startsWith('-') && !/^(run|dlx|exec|--)$/.test(a))
    let unpinned = false
    if (['npx', 'bunx'].includes(cmd) || (cmd === 'pnpm' && args.includes('dlx'))) unpinned = !!pkg && !/@\d[\w.+-]*$/.test(pkg)
    else if (cmd === 'uvx' || (cmd === 'pipx' && args.includes('run'))) unpinned = !!pkg && !/(==|@)\d[\w.+-]*$/.test(pkg)
    else if (cmd === 'docker' && args.includes('run')) { const img = [...args].reverse().find((a) => /^[a-z0-9][\w./-]*(:[\w.-]+)?(@sha256:[0-9a-f]{64})?$/i.test(a) && a.includes('/') || /@sha256:/.test(a)); unpinned = !!img && !/@sha256:/.test(img) && (!/:/.test(img) || /:latest$/.test(img)) }
    if (unpinned) out.push(F('MCP-1', 'medium', `MCP server "${m.key}" runs "${cmd} ${pkg || ''}" without a pinned version${args.includes('-y') ? ' and with auto-install (-y)' : ''}.`))
    if (m.url) {
      let host = ''
      try { host = new URL(m.url).hostname } catch { /* ignore */ }
      const local = /^(localhost|127\.0\.0\.1|\[::1\]|::1)$/.test(host)
      if (/^http:\/\//i.test(m.url) && !local) out.push(F('MCP-2', 'high', `MCP server "${m.key}" is reached over plain HTTP (${host || 'invalid URL'}).`))
      else if (!local && !m.hasAuth) out.push(F('MCP-2', 'medium', `Remote MCP server "${m.key}" shows no authentication header or token.`))
    }
    if (/filesystem|file-system|\bfs\b/i.test(`${m.key} ${args.join(' ')}`) && args.some((a) => /^(\/|~|\$HOME|%USERPROFILE%|\/home|\/Users|\/root|[A-Za-z]:[\\/]?)$/.test(a)))
      out.push(F('MCP-3', 'high', `MCP filesystem server "${m.key}" is rooted at a broad path (${args.find((a) => /^(\/|~|\$HOME|%USERPROFILE%|\/home|\/Users|\/root|[A-Za-z]:[\\/]?)$/.test(a))}).`))
  }
  const hay = allText(inp)
  const risky = ctx.risky || []
  if ((tools.length >= 3 || risky.length) && !/\b(max(imum)?[_ -]?(steps?|iterations?|turns?|tool[_ -]?calls?|loops?|actions?)|step (limit|cap)|iteration limit|budget|timeout|time[- ]?limit|rate[- ]?limit|spend (limit|cap)|token (limit|budget)|at most \d+ (steps?|tool calls?|actions?|iterations?))\b/i.test(hay))
    out.push(F('RL-1', 'low', 'No maximum number of steps, tool calls, time or spend is stated.'))
  if (risky.length && !/\b(audit[- ]?(log|trail)|log(s|ged)? (every|all|each)|append-only|every (tool )?call (is )?logged|logging (of|for))\b/i.test(hay))
    out.push(F('AU-1', 'low', 'High-impact tools are present but no audit logging of their calls is described.'))
  const wild = /\b(allow(ed)?[_-]?(tools|actions|commands|paths|domains|permissions)?|permissions?|auto[_-]?approve|always[_-]?allow)\b["']?\s*[:=]\s*(\[\s*)?["']\*["']|\ballow[_-]?all\b["']?\s*[:=]\s*["']?true|\b(dangerously[_-]?skip[_-]?permissions|bypass[_-]?permissions|skip[_-]?permissions)\b|\bpermissions?\b["']?\s*[:=]\s*["']?(all|\*|any)\b/i
  const starTool = tools.find((t) => t.name === '*' || /^\*$/.test(t.name))
  if (starTool || wild.test(hay)) out.push(F('TP-6', 'high', starTool ? 'A tool or permission entry is the wildcard "*".' : 'The config grants all permissions (wildcard, allow-all or skip-permissions setting).'))
  return out
}

/** The "lethal trifecta": private data + untrusted content + external communication in one agent. */
export function computeTrifecta(inp, tools = inp.tools, vars = []) {
  const privTools = tools.filter((t) => /\b(read[_ -]?(email|inbox|mail|file|record|customer)|crm|database|sql|query|customer|employee|payroll|salesforce|file[_ -]?system|filesystem|drive|vault|secrets?)\b/i.test(toolText(t)))
  const privEvidence = privTools.map((t) => `tool ${t.name}`)
  if (PRIVATE_DATA.test(inp.systemPrompt)) privEvidence.push('prompt mentions private data')
  const reads = tools.filter((t) => UNTRUSTED_TOOL.test(toolText(t)))
  const untrustedEvidence = [...reads.map((t) => `tool ${t.name}`), ...vars.map((v) => `placeholder {${v}}`)]
  const exfil = tools.filter((t) => !t.readOnly && classifyTool(t).some((k) => EXFIL_KINDS.includes(k.k)))
  const externalEvidence = exfil.map((t) => `tool ${t.name}`)
  const unguarded = exfil.filter((t) => !isGuarded(t))
  const leg = (ev) => ({ present: ev.length > 0, evidence: ev.slice(0, 6) })
  const complete = privEvidence.length > 0 && untrustedEvidence.length > 0 && externalEvidence.length > 0
  return { privateData: leg(privEvidence), untrusted: leg(untrustedEvidence), external: leg(externalEvidence), complete, gated: complete && unguarded.length === 0, legs: [privEvidence.length > 0, untrustedEvidence.length > 0, externalEvidence.length > 0].filter(Boolean).length }
}

/** Tool x risk matrix for the excessive-agency view. */
export function buildMatrix(inp, tools = inp.tools) {
  return tools.map((t) => {
    const kinds = classifyTool(t)
    const hay = toolText(t)
    const lookupName = /^(get|list|view|read|lookup|look[_ -]?up|show|check|find|search)[_ -]/i.test(t.name)
    const ro = t.readOnly || (READ_ONLY.test(hay) && !kinds.some((k) => k.k === 'shell'))
    const active = ro ? [] : kinds.filter((k) => !(lookupName && ['payment', 'admin'].includes(k.k)))
    const top = [...active].sort((a, b) => SEVERITY_ORDER.indexOf(a.sev) - SEVERITY_ORDER.indexOf(b.sev))[0]
    const readsUntrusted = UNTRUSTED_TOOL.test(hay)
    const confirmed = t.confirm === true || (t.confirm === undefined && CONFIRM.test(hay) && !/\b(no|without|never|skip)\s+(human\s+)?(confirm|approv)/i.test(hay))
    return { name: t.name, kinds: active.map((k) => k.k), labels: active.map((k) => k.label), readsUntrusted, readOnly: !!ro, confirmed: active.length ? confirmed : null, scoped: active.length ? SCOPE.test(hay) : null, risk: top ? top.sev : readsUntrusted ? 'low' : 'none', agent: t.agent || undefined }
  })
}
export const MATRIX_COLUMNS = [['shell', 'Shell'], ['payment', 'Payment'], ['file_write', 'File write'], ['email', 'Messaging'], ['network', 'Network'], ['db_write', 'DB write'], ['admin', 'Admin']]

// ---------- scoring ----------
export function grade(score) { return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F' }

export function scoreFindings(findings, weights = SEVERITY_WEIGHT) {
  const w = { ...SEVERITY_WEIGHT, ...(weights || {}) }
  const by = Object.fromEntries(Object.keys(CATEGORIES).map((k) => [k, 0]))
  for (const f of findings) by[f.cat] += Math.max(0, Number(w[f.severity]) || 0)
  // Each category loses at most 40 points so one weak area cannot dominate. With five categories the summed loss is
  // scaled by 0.6 (the same 120-point ceiling the original three-category model had), and the total floor is 0.
  const cat = Object.fromEntries(Object.entries(by).map(([k, v]) => [k, Math.max(0, 100 - Math.min(v, 100))]))
  const lost = Object.values(by).reduce((a, v) => a + Math.min(v, CATEGORY_CAP), 0)
  return { score: Math.max(0, Math.round(100 - lost * LOSS_SCALE)), categories: cat }
}

/**
 * analyze(raw, opts). opts.disabled = rule IDs to skip, opts.weights = severity weight overrides.
 * Input may be a string (JSON, YAML, text sections) or an already-parsed object.
 */
export function analyze(raw, opts = {}) {
  const truncated = typeof raw === 'string' && raw.length > MAX_INPUT_CHARS && !/^\s*[{[]/.test(raw.slice(0, 50))
  const inp = (raw && typeof raw === 'object') ? normalize(raw) : parseInput(raw)
  return analyzeInput(inp, opts, truncated)
}

/** Analyze an already-parsed input ({systemPrompt, tools, samples, agents, configText, format}). */
export function analyzeInput(inp, opts = {}, truncated = false) {
  const tools = inp.tools
  const ctx = {}
  const inj = checkInjection(inp, tools, ctx)
  ctx.reads = tools.filter((t) => UNTRUSTED_TOOL.test(toolText(t)))
  const perm = checkPermissions(inp, tools)
  ctx.risky = tools.filter((t) => { const k = classifyTool(t); return k.length && !t.readOnly && !(READ_ONLY.test(toolText(t)) && !k.some((x) => x.k === 'shell')) && k.some((x) => ['critical', 'high'].includes(x.sev)) })
  ctx.trifecta = computeTrifecta(inp, tools, ctx.vars || [])
  let findings = [...inj, ...perm, ...checkLeakage(inp, tools), ...checkAgentic(inp, tools, ctx), ...checkGovernance(inp, tools, ctx)]
  const disabled = new Set(Array.isArray(opts.disabled) ? opts.disabled.filter((x) => typeof x === 'string') : [])
  if (disabled.size) findings = findings.filter((f) => !disabled.has(f.id))
  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
  const weights = opts.weights && typeof opts.weights === 'object' ? opts.weights : null
  const { score, categories } = scoreFindings(findings, weights)
  const customized = disabled.size > 0 || (weights && Object.keys(weights).some((k) => weights[k] !== SEVERITY_WEIGHT[k]))
  return {
    version: 2, engine: ENGINE_VERSION, score, grade: grade(score), categories, findings,
    trifecta: ctx.trifecta, matrix: buildMatrix(inp, tools), format: inp.format || 'unknown',
    summary: { promptChars: inp.systemPrompt.length, tools: tools.length, samples: inp.samples.length, agents: (inp.agents || []).length, mcpServers: tools.filter((t) => t.mcp).length, ...(truncated ? { truncated: true } : {}) },
    ...(customized ? { customized: true, disabled: [...disabled] } : {}),
  }
}
function luhn(s) {
  const d = s.replace(/\D/g, '')
  if (d.length < 13 || d.length > 16) return false
  let sum = 0, alt = false
  for (let i = d.length - 1; i >= 0; i--) { let n = +d[i]; if (alt) { n *= 2; if (n > 9) n -= 9 } sum += n; alt = !alt }
  return sum % 10 === 0
}


// ---------- shareable hash (report only; the pasted config is never encoded) ----------
export function encodeReport(report) {
  const slim = { v: 1, s: report.score, c: report.categories, n: report.summary, f: report.findings.slice(0, 60).map((f) => [f.id, f.severity[0], String(f.detail).slice(0, 300), String(f.evidence || '').slice(0, 80)]) }
  const json = JSON.stringify(slim)
  const b64 = typeof btoa === 'function' ? btoa(unescape(encodeURIComponent(json))) : Buffer.from(json, 'utf8').toString('base64')
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function decodeReport(hash) {
  try {
    const h = String(hash)
    if (h.length > 60000) return null
    const b64 = h.replace(/^#?r=/, '').replace(/-/g, '+').replace(/_/g, '/')
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) return null
    const bare = b64.replace(/=+$/, '')
    const pad = bare + '='.repeat((4 - (bare.length % 4)) % 4)
    const json = typeof atob === 'function' ? decodeURIComponent(escape(atob(pad))) : Buffer.from(pad, 'base64').toString('utf8')
    const o = JSON.parse(json)
    if (!o || typeof o !== 'object' || o.v !== 1 || typeof o.s !== 'number' || !Number.isFinite(o.s) || !Array.isArray(o.f)) return null
    const sevMap = { c: 'critical', h: 'high', m: 'medium', l: 'low' }
    const own = (obj, k) => Object.prototype.hasOwnProperty.call(obj, k)
    const findings = o.f.slice(0, 60).filter((x) => Array.isArray(x) && typeof x[0] === 'string' && own(CATALOG, x[0]) && typeof x[1] === 'string' && own(sevMap, x[1]))
      .map(([id, s, detail, ev]) => ({ id, severity: sevMap[s], title: CATALOG[id].title, cat: CATALOG[id].cat, fix: CATALOG[id].fix, owasp: CATALOG[id].owasp, atlas: CATALOG[id].atlas, detail: String(typeof detail === 'string' ? detail : '').slice(0, 400), ...(typeof ev === 'string' && ev ? { evidence: ev.slice(0, 80) } : {}) }))
    const score = Math.max(0, Math.min(100, Math.round(o.s)))
    const c = o.c && typeof o.c === 'object' ? o.c : {}
    // categories added in v2 are absent from older links: treat a missing value as untouched (100), not as zero
    const num = (v, dflt) => (typeof v === 'number' && Number.isFinite(v) ? Math.max(0, Math.min(100, Math.round(v))) : dflt)
    const categories = Object.fromEntries(Object.keys(CATEGORIES).map((k) => [k, num(Object.prototype.hasOwnProperty.call(c, k) ? c[k] : undefined, Object.prototype.hasOwnProperty.call(c, k) ? 0 : 100)]))
    const n = o.n && typeof o.n === 'object' ? o.n : {}
    const big = (v) => (typeof v === 'number' && Number.isFinite(v) ? Math.max(0, Math.min(1e7, Math.round(v))) : 0)
    const summary = { promptChars: big(n.promptChars), tools: big(n.tools), samples: big(n.samples), agents: big(n.agents), mcpServers: big(n.mcpServers) }
    return { version: 2, score, grade: grade(score), categories, findings, summary, shared: true, trifecta: null, matrix: [], format: 'shared' }
  } catch { return null }
}

export function reportToMarkdown(report, title = 'Agent security report') {
  const L = [`# ${title}`, '', `**Score: ${report.score}/100 (grade ${report.grade})**`, '',
    `| Check | Sub-score |`, `|---|---|`,
    ...Object.entries(CATEGORIES).map(([k, v]) => `| ${v} | ${report.categories[k]}/100 |`), '']
  if (report.trifecta && report.trifecta.complete) L.push(`> Lethal trifecta: all three legs present${report.trifecta.gated ? ' (outbound channel is gated)' : ' and the outbound channel is not gated'}.`, '')
  if (!report.findings.length) L.push('No findings from the rule set. That does not prove the agent is safe; see the limits in the README.')
  for (const f of report.findings) {
    const tags = [...(f.owasp || []).map((o) => `OWASP ${o}`), ...(f.atlas || [])].join(', ')
    L.push(`### [${f.severity.toUpperCase()}] ${f.id} ${f.title}`, '', f.detail + (f.evidence ? ` Evidence (masked): \`${f.evidence}\`` : ''), '', ...(tags ? [`Tags: ${tags}`, ''] : []), `**Fix:** ${f.fix}`, '')
  }
  L.push('---', '_Static pattern review of the configuration text. It cannot observe model behaviour; see the README for limits._')
  return L.join('\n')
}
