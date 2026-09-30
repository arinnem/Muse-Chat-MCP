/**
 * muse-driver.mjs
 * ------------------------------------------------------------------
 * Browser driver for Meta Muse (https://muse.ai) — the "Hatch" agent VM.
 *
 * WHY THIS EXISTS
 *   Muse chat is NOT a REST/SSE API. It is an RPC gateway over an
 *   *encrypted* WebSocket ("noise" transport: X25519 + HKDF + AES-GCM),
 *   with Ed25519-signed auth_token/notary_token in the WS URL. See
 *   https://hatch.metaaivm.com/v1/noise and methods like chat.stream.
 *
 *   Rather than reimplementing the Noise handshake (phase 2), this driver
 *   drives the REAL client in a real Chrome so the app performs all crypto
 *   itself. It then reads the rendered assistant reply from the DOM.
 *
 * SELECTORS (harvested from the captured client JS / HAR)
 *   composer root : [data-hatch-composer-root]
 *   editor        : [data-lexical-editor="true"]   (Lexical contenteditable)
 *   send          : Enter key (analytics event "composer_enter_key")
 *   streaming     : [data-testid="hatch-composer-stop-button"]
 *   messages      : [data-message-item] (data-message-role = user|assistant)
 *   error         : [data-testid="assistant-response-error-notice"]
 *   auth check    : POST /api/auth/check  -> { ok, viewer_id, access_token }
 * ------------------------------------------------------------------
 */
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export const SELECTORS = {
  composerRoot: '[data-hatch-composer-root]',
  editor: '[data-lexical-editor="true"], [data-hatch-composer-root] textarea, [data-hatch-composer-prehydration-input], [data-hatch-composer-root] [contenteditable="true"]',
  stopButton: '[data-testid="hatch-composer-stop-button"]',
  actionSlot: '[data-hatch-composer-action-slot]',
  fileInput: '[data-hatch-composer-root] input[type="file"]',
  attachButton: '[data-hatch-composer-root] button[aria-label="Attach file"]',
  message: '[data-message-item]',
  assistant: '[data-message-item][data-message-role="assistant"]',
  user: '[data-message-item][data-message-role="user"]',
  errorNotice: '[data-testid="assistant-response-error-notice"]',
  approvalStack: '[data-hatch-composer-approval-stack]',
}

const APP_URL = process.env.MUSE_URL || 'https://muse.ai/'
const PROFILE_DIR =
  process.env.MUSE_PROFILE_DIR || path.join(__dirname, '.muse-profile')
const HEADLESS = process.env.MUSE_HEADLESS === '1'
const CHANNEL = process.env.MUSE_CHANNEL || 'chrome'
const LAUNCH_TIMEOUT = Number(process.env.MUSE_LAUNCH_TIMEOUT_MS || 60000)
// Streaming: only surface text that has been stable this long, so we never emit
// a mid-generation "skeleton" that Muse later rewrites (which would duplicate in
// an append-only SSE stream).
const STREAM_QUIET_MS = Number(process.env.MUSE_STREAM_QUIET_MS || 600)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

class MuseDriver {
  constructor() {
    this.ctx = null
    this.page = null
    this.browser = null
    this.lastError = null
    this._queue = Promise.resolve()
  }

  /** Serialize browser actions (one window = one action at a time). */
  _serial(fn) {
    const run = this._queue.then(fn, fn)
    this._queue = run.then(() => {}, () => {})
    return run
  }

  isRunning() {
    return !!(this.ctx && this.page && !this.page.isClosed())
  }

  async launch() {
    if (this.isRunning()) return this.page
    const { chromium } = await import('playwright-core')

    const launchPersistent = () =>
      chromium.launchPersistentContext(PROFILE_DIR, {
        channel: CHANNEL,
        headless: HEADLESS,
        viewport: { width: 1366, height: 900 },
        acceptDownloads: false,
        ignoreDefaultArgs: ['--enable-automation'],
        args: [
          '--no-first-run',
          '--no-default-browser-check',
          '--disable-blink-features=AutomationControlled',
          '--disable-features=Translate,OptimizationGuideModelDownloading',
        ],
      })
    const attachCDP = async (url) => {
      this.browser = await chromium.connectOverCDP(url)
      this.ctx = this.browser.contexts()[0] || (await this.browser.newContext())
    }

    if (process.env.MUSE_CDP) {
      // Escape hatch: attach to a Chrome you already started with
      //   chrome.exe --remote-debugging-port=9222
      // Reuses all your existing logins; the driver will not own the browser.
      try {
        await attachCDP(process.env.MUSE_CDP)
      } catch (e) {
        this.browser = null
        this.ctx = null
        this.ctx = await launchPersistent()
      }
    } else {
      try {
        this.ctx = await launchPersistent()
      } catch (e) {
        // The profile is probably locked by an already-running Chrome (e.g. one
        // started with --remote-debugging-port=9222). Attach to it instead of
        // failing; only if nothing is listening on the CDP port do we rethrow.
        const msg = String((e && e.message) || e)
        if (!/singleton|lock|profile|already running|browser is already/i.test(msg)) throw e
        try {
          await attachCDP('http://127.0.0.1:9222')
        } catch {
          throw new Error(
            `Could not open the Muse Chrome profile (${PROFILE_DIR}): it is locked by ` +
              `another Chrome window, and no debugger is listening on 127.0.0.1:9222. ` +
              `Close the Chrome window using this profile, or restart it with ` +
              `--remote-debugging-port=9222 and set MUSE_CDP=http://127.0.0.1:9222.`,
          )
        }
      }
    }

    this.ctx.on('close', () => {
      this.ctx = null
      this.page = null
      this.browser = null
    })
    const pages = this.ctx.pages()
    this.page = pages.find((p) => p.url().includes('muse.ai')) || pages[0] || (await this.ctx.newPage())
    this.page.setDefaultTimeout(LAUNCH_TIMEOUT)
    await this.gotoApp()
    return this.page
  }

  async gotoApp() {
    const p = await this.requirePage()
    if (!p.url().startsWith('https://muse.ai')) {
      await p.goto(APP_URL, { waitUntil: 'domcontentloaded', timeout: LAUNCH_TIMEOUT })
    }
    return p
  }

  async requirePage() {
    if (!this.isRunning()) await this.launch()
    return this.page
  }

  /** Cookie-based auth probe performed from inside the page origin. */
  async checkAuth() {
    const p = await this.requirePage()
    try {
      const r = await p.evaluate(async () => {
        try {
          const res = await fetch('/api/auth/check', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: '{}',
            credentials: 'same-origin',
          })
          const j = await res.json().catch(() => null)
          return { status: res.status, ok: !!(j && j.ok), viewerId: (j && j.viewer_id) || null }
        } catch (e) {
          return { status: 0, ok: false, error: String(e) }
        }
      })
      return r
    } catch (e) {
      return { status: 0, ok: false, error: String(e) }
    }
  }

  async hasComposer() {
    const p = await this.requirePage()
    try {
      await p.locator(SELECTORS.editor).first().waitFor({ state: 'visible', timeout: 8000 })
      return true
    } catch {
      return false
    }
  }

  async status() {
    const running = this.isRunning()
    const url = running ? this.page.url() : null
    if (!running) {
      return { browserRunning: false, url: null, loggedIn: false, composerReady: false, profileDir: PROFILE_DIR, headless: HEADLESS }
    }
    const auth = await this.checkAuth()
    const composerReady = await this.hasComposer()
    return {
      browserRunning: true,
      url,
      loggedIn: auth.ok,
      viewerId: auth.viewerId || null,
      composerReady,
      profileDir: PROFILE_DIR,
      headless: HEADLESS,
    }
  }

  /** Open the app and, if needed, wait for the user to complete Meta login. */
  async login(timeoutMs = 300000) {
    await this.gotoApp()
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      const auth = await this.checkAuth()
      if (auth.ok) return { loggedIn: true, viewerId: auth.viewerId || null }
      await sleep(2000)
    }
    return { loggedIn: false, hint: 'Complete the Meta sign-in in the opened Chrome window, then call muse_login again or muse_status.' }
  }

  async _newChat() {
    const p = await this.requirePage()
    await p.goto(APP_URL, { waitUntil: 'domcontentloaded', timeout: LAUNCH_TIMEOUT })
    await this.waitForComposer()
    return { ok: true, url: p.url() }
  }

  async newChat() {
    return this._serial(() => this._newChat())
  }

  /**
   * Normalize attachment entries into Playwright file payloads.
   * Accepts: "C:\\path\\img.png" | { path } | { url } (http/https/data:) |
   *          { name, mimeType, buffer } (Buffer or base64 string).
   */
  async _toFilePayloads(files) {
    const out = []
    for (const f of files || []) {
      if (!f) continue
      let e = f
      if (typeof e === 'string') e = /^(https?:|data:)/i.test(e) ? { url: e } : { path: e }

      if (e.buffer) {
        const buf = Buffer.isBuffer(e.buffer) ? e.buffer : Buffer.from(e.buffer, 'base64')
        out.push({ name: e.name || 'file', mimeType: e.mimeType || 'application/octet-stream', buffer: buf })
        continue
      }
      if (e.url && /^data:/i.test(e.url)) {
        const m = e.url.match(/^data:([^;,]*)(;base64)?,(.*)$/s)
        if (m) {
          const buf = Buffer.from(m[3], m[2] ? 'base64' : 'utf8')
          out.push({ name: e.name || `attachment`, mimeType: m[1] || e.mimeType || 'application/octet-stream', buffer: buf })
          continue
        }
      }
      if (e.url && /^file:\/\//i.test(e.url)) { out.push(fileURLToPath(e.url)); continue }
      if (e.url && /^https?:\/\//i.test(e.url)) {
        const res = await fetch(e.url)
        if (!res.ok) throw new Error(`failed to fetch attachment ${e.url}: ${res.status}`)
        const buf = Buffer.from(await res.arrayBuffer())
        let name = e.name
        if (!name) { try { name = decodeURIComponent(new URL(e.url).pathname.split('/').pop()) || 'attachment' } catch { name = 'attachment' } }
        out.push({ name, mimeType: res.headers.get('content-type') || e.mimeType || 'application/octet-stream', buffer: buf })
        continue
      }
      if (e.url) { out.push(e.url); continue } // bare local path passed via `url`
      if (e.path) out.push(e.path)
    }
    return out
  }

  /** Attach files/images/videos to the composer (no send). */
  async attachFiles(files) {
    return this._serial(() => this._attachFiles(files))
  }

  async _attachFiles(files) {
    const payloads = await this._toFilePayloads(files)
    if (!payloads.length) return { ok: true, count: 0 }
    const p = await this.requirePage()
    await this.gotoApp()
    await this.waitForComposer()
    await p.locator(SELECTORS.fileInput).first().setInputFiles(payloads)
    await sleep(600) // let the app register the attachment(s)
    return { ok: true, count: payloads.length }
  }

  async waitForComposer(timeoutMs = 90000) {
    const p = await this.requirePage()
    await p.locator(SELECTORS.editor).first().waitFor({ state: 'visible', timeout: timeoutMs })
    // wait until not busy (aria-busy on composer root)
    const root = p.locator(SELECTORS.composerRoot).first()
    try {
      await root.waitFor({ state: 'visible', timeout: 10000 })
      const start = Date.now()
      while (Date.now() - start < 15000) {
        const busy = await root.getAttribute('aria-busy')
        if (busy !== 'true') break
        await sleep(250)
      }
    } catch {
      /* composer root optional */
    }
  }

  async composerText() {
    const p = await this.requirePage()
    try {
      const el = p.locator(SELECTORS.editor).first()
      const tag = await el.evaluate((e) => e.tagName)
      if (tag === 'TEXTAREA' || tag === 'INPUT') return await el.inputValue()
      return await el.innerText()
    } catch {
      return ''
    }
  }

  /**
   * Send a prompt and wait for the assistant reply to finish streaming.
   * @returns {Promise<{reply:string, messages:string[], threadUrl:string, elapsedMs:number, error?:string, timedOut?:boolean, needsApproval?:boolean}>}
   */
  async _run(prompt, { timeoutMs = 240000, newThread = false, onDelta, files } = {}) {
    const hasFiles = Array.isArray(files) && files.length > 0
    if ((!prompt || !prompt.trim()) && !hasFiles) throw new Error('prompt is empty')
    const p = await this.requirePage()
    if (newThread) await this._newChat()
    await this.gotoApp()
    await this.waitForComposer()

    // Clear any transient error notice.
    this.lastError = null

    // Attach images/videos/files (if any) before typing the prompt.
    if (hasFiles) {
      const payloads = await this._toFilePayloads(files)
      if (payloads.length) {
        await p.locator(SELECTORS.fileInput).first().setInputFiles(payloads)
        await sleep(800) // let the app ingest + preview the attachment(s)
      }
    }

    const before = await p.locator(SELECTORS.assistant).count()

    // Focus + fill the composer. insertText is O(1) for big prompts;
    // fall back to per-key typing if the editor ignores it.
    const editor = p.locator(SELECTORS.editor).first()
    await editor.click()
    await p.keyboard.press('Control+A').catch(() => {})
    await p.keyboard.press('Delete').catch(() => {})
    try { if (prompt) await p.keyboard.insertText(prompt) } catch { /* fall back below */ }
    await sleep(120)
    if (prompt && !(await this.composerText()).trim()) {
      await p.keyboard.type(prompt, { delay: 1 })
    }
    await sleep(150)

    const t0 = Date.now()
    await p.keyboard.press('Enter')

    // Confirm the message actually left the composer; else click the send action.
    let sent = false
    for (let i = 0; i < 10; i++) {
      await sleep(300)
      const txt = (await this.composerText()).trim()
      const stop = await p.locator(SELECTORS.stopButton).count()
      if (txt.length === 0 || stop > 0) { sent = true; break }
    }
    if (!sent) {
      const slot = p.locator(`${SELECTORS.actionSlot} button`).last()
      if (await slot.count()) { await slot.click({ timeout: 5000 }).catch(() => {}) }
      await p.keyboard.press('Control+Enter').catch(() => {})
    }

    // Wait for the reply to complete.
    const deadline = t0 + timeoutMs
    let started = false
    let lastText = ''
    let committed = ''
    let stableSince = Date.now()
    let timedOut = false

    while (Date.now() < deadline) {
      const stop = await p.locator(SELECTORS.stopButton).count()
      if (stop > 0) started = true
      const n = await p.locator(SELECTORS.assistant).count()
      if (n > before) {
        const txt = await p.locator(SELECTORS.assistant).last().innerText().catch(() => '')
        if (txt !== lastText) {
          lastText = txt
          stableSince = Date.now()
        }
        const idle = Date.now() - stableSince
        // Commit only stable + monotonic growth (never a re-written draft).
        if (onDelta && txt && txt !== committed && txt.startsWith(committed) && idle >= STREAM_QUIET_MS) {
          committed = txt
          try { onDelta(committed) } catch { /* ignore */ }
        }
        if (stop === 0 && ((started && idle > 1200) || (!started && idle > 2500))) break
      }
      if (await p.locator(SELECTORS.errorNotice).count()) {
        this.lastError = await p.locator(SELECTORS.errorNotice).first().innerText().catch(() => 'assistant error')
      }
      await sleep(300)
    }
    if (Date.now() >= deadline) timedOut = true

    const items = await p.locator(SELECTORS.assistant).evaluateAll(
      (els, start) => els.slice(start).map((e) => (e.innerText || '').trim()).filter(Boolean),
      before,
    )
    const reply = (items.length ? items[items.length - 1] : lastText).trim()
    const needsApproval = (await p.locator(SELECTORS.approvalStack).count()) > 0

    // Flush any remainder that arrived after the last stable commit.
    if (onDelta && reply && reply !== committed && reply.startsWith(committed)) {
      try { onDelta(reply) } catch { /* ignore */ }
    }

    return {
      reply,
      messages: items,
      threadUrl: p.url(),
      elapsedMs: Date.now() - t0,
      ...(this.lastError ? { error: this.lastError } : {}),
      ...(timedOut ? { timedOut: true } : {}),
      ...(needsApproval ? { needsApproval: true } : {}),
    }
  }

  /** Send a prompt and wait for the full assistant reply. */
  async chat(prompt, opts = {}) {
    return this._serial(() => this._run(prompt, opts))
  }

  /**
   * Same as chat(), but streams incremental text.
   * @param {(fullText:string)=>void} opts.onDelta called with the cumulative reply text
   */
  async chatStream(prompt, opts = {}) {
    return this._serial(() => this._run(prompt, opts))
  }

  async readLast() {
    return this._serial(() => this._readLast())
  }

  async _readLast() {
    const p = await this.requirePage()
    await this.gotoApp()
    const n = await p.locator(SELECTORS.assistant).count()
    if (!n) return { reply: '', messages: [], threadUrl: p.url() }
    const reply = await p.locator(SELECTORS.assistant).last().innerText().catch(() => '')
    return { reply: reply.trim(), messages: [reply.trim()], threadUrl: p.url() }
  }

  /** Diagnostic: dump transcript HTML so selectors can be re-verified. */
  async dumpDom(maxChars = 20000) {
    return this._serial(() => this._dumpDom(maxChars))
  }

  async _dumpDom(maxChars = 20000) {
    const p = await this.requirePage()
    await this.gotoApp()
    const info = await p.evaluate((sels) => {
      const pick = (s) => document.querySelector(s)
      const log = pick('[role="log"]')
      const first = pick('[data-message-item]')
      const container = log || (first && first.parentElement) || document.body
      return {
        url: location.href,
        title: document.title,
        counts: {
          messages: document.querySelectorAll(sels.message).length,
          assistant: document.querySelectorAll(sels.assistant).length,
          user: document.querySelectorAll(sels.user).length,
          editor: document.querySelectorAll(sels.editor).length,
        },
        hasApproval: !!document.querySelector(sels.approvalStack),
        html: container.outerHTML,
      }
    }, SELECTORS)
    return { ...info, html: (info.html || '').slice(0, maxChars) }
  }

  async close() {
    if (this.browser) {
      // CDP-attached: disconnect only, never kill the user's browser.
      await this.browser.close().catch(() => {})
      this.browser = null
      this.ctx = null
      this.page = null
      return { ok: true, disconnected: true }
    }
    if (this.ctx) {
      await this.ctx.close().catch(() => {})
      this.ctx = null
      this.page = null
    }
    return { ok: true }
  }
}

export const driver = new MuseDriver()
export default driver
