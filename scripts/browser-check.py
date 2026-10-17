#!/usr/bin/env python3
"""Browser checks + screenshots with Playwright (python). Not part of `npm test` because it needs a browser.
Usage: python3 scripts/browser-check.py [out_dir] [chrome_path]
Serves the repo over HTTP, drives index.html and (via file://) standalone.html, fails on any console error,
and writes desktop + mobile screenshots of every view in dark and light themes."""
import sys, os, threading, http.server, socketserver, json, functools
from playwright.sync_api import sync_playwright

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'screenshots')
CHROME = sys.argv[2] if len(sys.argv) > 2 else None
os.makedirs(OUT, exist_ok=True)
errors, checks = [], []

def ok(cond, msg):
    checks.append((bool(cond), msg))
    print(('PASS ' if cond else 'FAIL ') + msg)

class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
srv = socketserver.TCPServer(('127.0.0.1', 0), functools.partial(Quiet, directory=ROOT)); srv.allow_reuse_address = True
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f'http://127.0.0.1:{srv.server_address[1]}/'

def watch(pg, tag):
    pg.on('console', lambda m: errors.append((tag, m.type, m.text)) if m.type in ('error', 'warning') else None)
    pg.on('pageerror', lambda e: errors.append((tag, 'pageerror', str(e))))
    pg.on('requestfailed', lambda r: errors.append((tag, 'requestfailed', r.url)))

def tour(pg, tag, shots):
    def shot(name, full=True):
        if shots: pg.screenshot(path=f'{OUT}/{tag}-{name}.png', full_page=full)
    pg.wait_for_timeout(500); shot('01-analyze-empty')
    pg.click('button[data-file="06-inbox-copilot.json"]'); pg.wait_for_timeout(1700)
    ok(pg.text_content('svg.gauge .num').strip().isdigit(), f'{tag}: gauge shows a number')
    shot('02-overview-findings')
    pg.click('[data-tab=roadmap]'); pg.click('[data-action=apply-top]'); pg.wait_for_timeout(300); shot('03-roadmap')
    pg.click('[data-tab=matrix]'); pg.wait_for_timeout(200); shot('04-matrix')
    pg.click('[data-tab=attacks]'); pg.wait_for_timeout(200); shot('05-attack-tests')
    pg.click('[data-tab=export]'); pg.wait_for_timeout(200); shot('06-export-badge')
    pg.click('button[data-view=compare]'); pg.click('[data-action=cmp-demo]'); pg.wait_for_timeout(1700); shot('07-compare')
    pg.click('button[data-view=history]'); pg.wait_for_timeout(300); shot('08-history')
    pg.click('button[data-view=rules]'); pg.wait_for_timeout(300); shot('09-rules')
    pg.click('button[data-view=settings]'); pg.wait_for_timeout(300); shot('10-settings')
    pg.click('button[data-view=analyze]'); pg.keyboard.press('?'); pg.wait_for_timeout(300); shot('11-shortcuts', full=False); pg.keyboard.press('Escape')

def functional(pg, tag):
    pg.click('button[data-file="01-support-bot-open.json"]'); pg.wait_for_timeout(1500)
    before = int(pg.text_content('svg.gauge .num'))
    ok(before <= 20, f'{tag}: weak sample scores low ({before})')
    n_all = pg.locator('#flist .finding').count()
    pg.click('[data-action=sev][data-sev=critical]'); n_crit = pg.locator('#flist .finding').count()
    ok(0 < n_crit < n_all, f'{tag}: severity filter narrows {n_all} -> {n_crit}')
    pg.click('[data-action=sev][data-sev=critical]'); pg.fill('#fq', 'LLM07'); ok(pg.locator('#flist .finding').count() >= 1, f'{tag}: search by OWASP id works')
    pg.fill('#fq', 'zzzz-nothing'); ok('No findings match' in pg.inner_text('#flist'), f'{tag}: empty filter state shown'); pg.fill('#fq', '')
    pg.click('[data-tab=roadmap]'); pg.click('[data-action=apply-all]'); pg.wait_for_timeout(1300)
    ok('100' in pg.inner_text('.sim'), f'{tag}: applying all fixes projects 100')
    # downloads
    pg.click('[data-tab=export]')
    for sel, ext in [('dl-md', '.md'), ('dl-json', '.json'), ('dl-sarif', '.sarif'), ('dl-html', '.html'), ('dl-badge', '.svg')]:
        with pg.expect_download() as d: pg.click(f'[data-action={sel}]')
        ok(d.value.suggested_filename.endswith(ext), f'{tag}: download {ext}')
    # theme + shortcuts
    th = pg.evaluate('document.documentElement.dataset.theme'); pg.keyboard.press('t'); ok(pg.evaluate('document.documentElement.dataset.theme') != th, f'{tag}: t toggles theme'); pg.keyboard.press('t')
    pg.keyboard.press('2'); ok(pg.get_attribute('#tab-roadmap', 'aria-selected') == 'true', f'{tag}: number key switches tab')
    pg.keyboard.press('g'); pg.keyboard.press('r'); pg.wait_for_timeout(200); ok(pg.is_visible('#view-rules'), f'{tag}: g r opens rules')
    pg.goto(pg.url.split('#')[0]); pg.wait_for_timeout(300)
    # upload yaml via file input + drag-drop path
    pg.set_input_files('#file', os.path.join(ROOT, 'samples', '05-support-crew.yaml')); pg.wait_for_timeout(1500)
    ok('YAML' in pg.inner_text('#fmt-chip'), f'{tag}: YAML upload detected')
    pg.set_input_files('#file', os.path.join(ROOT, 'samples', '04-mcp-dev-workstation.json')); pg.wait_for_timeout(1500)
    ok('MCP' in pg.inner_text('#fmt-chip'), f'{tag}: MCP config upload detected')
    # error state
    pg.click('[data-action=clear]'); pg.click('#run'); ok('Paste or upload' in pg.inner_text('#in-error'), f'{tag}: empty input error shown')
    # XSS probe
    pg.fill('#in', '{"system_prompt":"x","tools":[{"name":"<img src=x onerror=window.__xss=1>","description":"send_email"}]}'); pg.click('#run'); pg.wait_for_timeout(500)
    pg.click('[data-tab=matrix]'); ok(pg.evaluate('window.__xss') is None, f'{tag}: hostile tool name stays inert')
    # share link carries no config
    pg.fill('#in', '{"system_prompt":"CANARY-CONFIG-TEXT"}'); pg.click('#run'); pg.wait_for_timeout(300); pg.click('[data-tab=export]')
    pg.evaluate("navigator.clipboard.writeText = async (t) => { window.__copied = t }"); pg.click('[data-action=copy-share]'); pg.wait_for_timeout(200)
    link = pg.evaluate('window.__copied') or ''
    ok('#r=' in link and 'CANARY' not in link, f'{tag}: share link has report only')
    pg.goto(link); pg.wait_for_timeout(1200); ok('Shared report' in pg.inner_text('#results'), f'{tag}: share link rebuilds a report')
    pg.goto('about:blank')

with sync_playwright() as p:
    kw = {'args': ['--no-sandbox']}
    if CHROME: kw['executable_path'] = CHROME
    b = p.chromium.launch(**kw)
    for tag, vp, theme in [('desktop-dark', {'width': 1360, 'height': 900}, 'dark'), ('desktop-light', {'width': 1360, 'height': 900}, 'light'),
                           ('mobile-dark', {'width': 390, 'height': 844}, 'dark'), ('mobile-light', {'width': 390, 'height': 844}, 'light')]:
        ctx = b.new_context(viewport=vp, color_scheme=theme); pg = ctx.new_page(); watch(pg, tag)
        pg.goto(BASE + 'index.html'); tour(pg, tag, True)
        if tag == 'desktop-dark':
            pg.goto(BASE + 'index.html'); functional(pg, 'http')
        ctx.close()
    # file:// standalone (no server, no modules)
    ctx = b.new_context(viewport={'width': 1360, 'height': 900}); pg = ctx.new_page(); watch(pg, 'file')
    pg.goto('file://' + os.path.join(ROOT, 'standalone.html')); functional(pg, 'file'); ctx.close()
    # horizontal overflow on mobile
    ctx = b.new_context(viewport={'width': 390, 'height': 844}); pg = ctx.new_page(); watch(pg, 'overflow'); pg.goto(BASE + 'index.html')
    pg.click('button[data-file="05-support-crew.yaml"]'); pg.wait_for_timeout(1500)
    for t in ['findings', 'roadmap', 'matrix', 'attacks', 'export']:
        pg.click(f'[data-tab={t}]'); pg.wait_for_timeout(150)
        ok(pg.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 1'), f'mobile: no horizontal page overflow on {t}')
    ctx.close(); b.close()
srv.shutdown()
print('console errors:', errors)
failed = [m for c, m in checks if not c]
print(f'{len(checks) - len(failed)}/{len(checks)} browser checks passed')
sys.exit(1 if failed or errors else 0)
