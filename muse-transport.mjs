/**
 * muse-transport.mjs
 * ------------------------------------------------------------------
 * Unified transport manager providing an identical surface to muse-driver.mjs
 * with automated headless Noise execution (Phase 2) and seamless, zero-crash
 * Playwright browser fallback.
 *
 * Configuration (env):
 *   MUSE_TRANSPORT='noise' | 'browser'   (default: 'noise')
 *
 * Circuit-breaker fallback:
 *   When configured for 'noise', requests attempt the headless WebSocket
 *   Noise transport. If token extraction, handshake, or connection fails
 *   (e.g., AuthSessionExpiredError, ECONNREFUSED, handshake timeout),
 *   the transport logs a diagnostic warning:
 *     "[muse-transport] Noise transport unavailable (...), falling back to browser driver"
 *   and seamlessly delegates the pending operation to the Playwright
 *   browser driver without throwing unhandled rejections or crashing.
 * ------------------------------------------------------------------
 */

import { driver as defaultDriver } from './muse-driver.mjs'
import { NoiseClient as DefaultNoiseClient } from './lib/noise/noise-client.mjs'
import { TokenManager as DefaultTokenManager, AuthSessionExpiredError } from './lib/noise/token-manager.mjs'

export { AuthSessionExpiredError }

export class MuseTransport {
  /**
   * @param {object} [options={}]
   * @param {string} [options.transport] Explicit transport mode ('noise' | 'browser')
   * @param {object} [options.driver] Injected browser driver (defaults to singleton driver)
   * @param {Function} [options.NoiseClientClass] Injected NoiseClient constructor
   * @param {object} [options.noiseClient] Injected NoiseClient instance
   * @param {object} [options.tokenManager] Injected TokenManager instance
   */
  constructor(options = {}) {
    const rawTransport = options.transport || process.env.MUSE_TRANSPORT || 'noise'
    this.configTransport = String(rawTransport).toLowerCase().trim()
    this.activeTransport = this.configTransport === 'browser' ? 'browser' : 'noise'

    this.fallbackState = {
      active: false,
      reason: null,
      failedAt: null,
      count: 0,
    }

    this.browserDriver = options.driver || defaultDriver
    this.NoiseClientClass = options.NoiseClientClass || DefaultNoiseClient
    this.tokenManager = options.tokenManager || null
    this.noiseClient = options.noiseClient || null

    this._connectingPromise = null
  }

  get fallbackActive() {
    return this.fallbackState.active
  }

  get fallbackReason() {
    return this.fallbackState.reason
  }

  /**
   * Resets the circuit breaker back to the initial configured transport.
   */
  resetFallback() {
    this.fallbackState.active = false
    this.fallbackState.reason = null
    this.fallbackState.failedAt = null
    this.activeTransport = this.configTransport === 'browser' ? 'browser' : 'noise'
  }

  /**
   * Internal circuit-breaker trigger. Sets activeTransport to 'browser'
   * and records diagnostic state.
   */
  _triggerFallback(reason) {
    const reasonStr = typeof reason === 'string' ? reason : (reason && reason.message) || String(reason)
    this.fallbackState.active = true
    this.fallbackState.reason = reasonStr
    this.fallbackState.failedAt = Date.now()
    this.fallbackState.count++
    this.activeTransport = 'browser'
  }

  /**
   * Cleanly closes and clears active Noise client resources.
   */
  async _cleanupNoise() {
    if (this.noiseClient) {
      try {
        await this.noiseClient.close()
      } catch {}
      this.noiseClient = null
    }
  }

  /**
   * Resolves or instantiates an active, connected NoiseClient.
   * If connection fails, throws so caller can initiate fallback.
   */
  async _getNoiseClient() {
    if (this.noiseClient && this.noiseClient.connected) {
      return this.noiseClient
    }

    if (this._connectingPromise) {
      return this._connectingPromise
    }

    this._connectingPromise = (async () => {
      try {
        if (!this.noiseClient) {
          if (!this.tokenManager) {
            this.tokenManager = new DefaultTokenManager({
              driver: this.browserDriver,
            })
          }
          this.noiseClient = new this.NoiseClientClass({
            tokenManager: this.tokenManager,
          })
        }
        await this.noiseClient.connect()
        return this.noiseClient
      } finally {
        this._connectingPromise = null
      }
    })()

    return this._connectingPromise
  }

  /**
   * Returns unified status satisfying MCP muse_status and OpenAI /health.
   */
  async status() {
    let browserStatus = {
      browserRunning: false,
      url: null,
      loggedIn: false,
      viewerId: null,
      composerReady: false,
      profileDir: '',
      headless: false,
    }

    try {
      if (typeof this.browserDriver.status === 'function') {
        browserStatus = await this.browserDriver.status()
      }
    } catch (err) {
      browserStatus.error = err && err.message ? err.message : String(err)
    }

    const noiseConnected = Boolean(this.noiseClient && this.noiseClient.connected)
    const noiseStatus = {
      connected: noiseConnected,
      endpointUrl: this.noiseClient?.credentials?.endpoint_url || null,
      vmId: this.noiseClient?.credentials?.vm_id || null,
    }

    const isNoiseActive = this.activeTransport === 'noise' && !this.fallbackState.active

    return {
      ...browserStatus,
      transport: this.configTransport,
      activeTransport: this.activeTransport,
      fallbackActive: this.fallbackState.active,
      fallbackReason: this.fallbackState.reason,
      fallbackAvailable: true,
      noiseStatus,
      // If Noise is the active connected transport, report unified loggedIn and composer readiness
      loggedIn: isNoiseActive ? (noiseConnected || browserStatus.loggedIn) : browserStatus.loggedIn,
      composerReady: isNoiseActive ? (noiseConnected || browserStatus.composerReady) : browserStatus.composerReady,
      viewerId: isNoiseActive ? (this.noiseClient?.credentials?.viewer_id || browserStatus.viewerId || null) : browserStatus.viewerId,
      url: isNoiseActive && noiseConnected ? (noiseStatus.endpointUrl || 'wss://hatch.metaaivm.com/v1/noise') : browserStatus.url,
    }
  }

  /**
   * Unary chat: sends prompt and returns assistant reply.
   */
  async chat(prompt, opts = {}) {
    if (this.activeTransport === 'noise' && !this.fallbackState.active) {
      try {
        const client = await this._getNoiseClient()
        const result = await client.chatStream(prompt, opts)
        const text = result.reply || result.text || ''
        return {
          reply: text,
          text,
          messages: [text],
          toolCalls: result.toolCalls || [],
          finishReason: result.finishReason || 'stop',
          threadUrl: client.credentials?.endpoint_url || null,
          elapsedMs: 0,
        }
      } catch (err) {
        const reason = err && err.message ? err.message : String(err)
        console.warn(`[muse-transport] Noise transport unavailable (${reason}), falling back to browser driver`)
        this._triggerFallback(reason)
        await this._cleanupNoise()
        return await this.browserDriver.chat(prompt, opts)
      }
    }

    return await this.browserDriver.chat(prompt, opts)
  }

  /**
   * Streaming chat: emits monotonic deltas to opts.onDelta and returns assistant reply.
   */
  async chatStream(prompt, opts = {}) {
    if (this.activeTransport === 'noise' && !this.fallbackState.active) {
      let tokensEmitted = 0
      const wrappedOpts = {
        ...opts,
        onDelta: (chunk) => {
          tokensEmitted++
          if (typeof opts.onDelta === 'function') {
            opts.onDelta(chunk)
          }
        },
      }

      try {
        const client = await this._getNoiseClient()
        const result = await client.chatStream(prompt, wrappedOpts)
        const text = result.reply || result.text || ''
        return {
          reply: text,
          text,
          messages: [text],
          toolCalls: result.toolCalls || [],
          finishReason: result.finishReason || 'stop',
          threadUrl: client.credentials?.endpoint_url || null,
          elapsedMs: 0,
        }
      } catch (err) {
        const reason = err && err.message ? err.message : String(err)
        console.warn(`[muse-transport] Noise transport unavailable (${reason}), falling back to browser driver`)
        this._triggerFallback(reason)
        await this._cleanupNoise()

        if (tokensEmitted > 0) {
          // A partial response has already been transmitted to the client (e.g. over SSE in muse-openai-shim.mjs).
          // Do NOT silently restart from word 0 into the open SSE stream (which would emit duplicated text and violate monotonic streaming).
          throw new Error(`Noise stream interrupted mid-stream after ${tokensEmitted} token delta(s) emitted: ${reason}`)
        }

        return await this.browserDriver.chatStream(prompt, opts)
      }
    }

    return await this.browserDriver.chatStream(prompt, opts)
  }

  /**
   * Starts a fresh thread.
   */
  async newChat() {
    if (this.activeTransport === 'noise' && !this.fallbackState.active) {
      try {
        const client = await this._getNoiseClient()
        if (typeof client.newChat === 'function') {
          return await client.newChat()
        }
        return { ok: true, activeChat: null, transport: 'noise' }
      } catch (err) {
        const reason = err && err.message ? err.message : String(err)
        console.warn(`[muse-transport] Noise transport unavailable (${reason}), falling back to browser driver`)
        this._triggerFallback(reason)
        await this._cleanupNoise()
        return await this.browserDriver.newChat()
      }
    }

    return await this.browserDriver.newChat()
  }

  /**
   * Lists available chats in the sidebar.
   */
  async listChats(query) {
    if (this.activeTransport === 'noise' && !this.fallbackState.active) {
      try {
        const client = await this._getNoiseClient()
        if (typeof client.listChats === 'function') {
          return await client.listChats(query)
        }
      } catch (err) {
        const reason = err && err.message ? err.message : String(err)
        console.warn(`[muse-transport] Noise transport unavailable (${reason}), falling back to browser driver`)
        this._triggerFallback(reason)
        await this._cleanupNoise()
        return await this.browserDriver.listChats(query)
      }
    }

    return await this.browserDriver.listChats(query)
  }

  /**
   * Opens a specific chat thread.
   */
  async openChat(target) {
    if (this.activeTransport === 'noise' && !this.fallbackState.active) {
      try {
        const client = await this._getNoiseClient()
        if (typeof client.openChat === 'function') {
          return await client.openChat(target)
        }
      } catch (err) {
        const reason = err && err.message ? err.message : String(err)
        console.warn(`[muse-transport] Noise transport unavailable (${reason}), falling back to browser driver`)
        this._triggerFallback(reason)
        await this._cleanupNoise()
        return await this.browserDriver.openChat(target)
      }
    }

    return await this.browserDriver.openChat(target)
  }

  /**
   * Reads messages from the currently active chat.
   */
  async readChat(max = 100) {
    if (this.activeTransport === 'noise' && !this.fallbackState.active) {
      try {
        const client = await this._getNoiseClient()
        if (typeof client.readChat === 'function') {
          return await client.readChat(max)
        }
        if (typeof client.historyWindow === 'function') {
          const res = await client.historyWindow('', max)
          const msgs = (res.messages || []).map((m) => ({
            role: m.role || 'assistant',
            text: m.text || m.content || '',
          }))
          return { messages: msgs, count: msgs.length, transport: 'noise' }
        }
      } catch (err) {
        const reason = err && err.message ? err.message : String(err)
        console.warn(`[muse-transport] Noise transport unavailable (${reason}), falling back to browser driver`)
        this._triggerFallback(reason)
        await this._cleanupNoise()
        return await this.browserDriver.readChat(max)
      }
    }

    return await this.browserDriver.readChat(max)
  }

  /**
   * Reads the latest assistant reply.
   */
  async readLast() {
    if (this.activeTransport === 'noise' && !this.fallbackState.active) {
      try {
        const client = await this._getNoiseClient()
        if (typeof client.readLast === 'function') {
          return await client.readLast()
        }
        if (typeof client.historyWindow === 'function') {
          const res = await client.historyWindow('', 5)
          const msgs = res.messages || []
          const last = msgs.slice().reverse().find((m) => m.role === 'assistant') || msgs[msgs.length - 1]
          const reply = last ? (last.text || last.content || '') : ''
          return { reply, messages: [reply], transport: 'noise' }
        }
      } catch (err) {
        const reason = err && err.message ? err.message : String(err)
        console.warn(`[muse-transport] Noise transport unavailable (${reason}), falling back to browser driver`)
        this._triggerFallback(reason)
        await this._cleanupNoise()
        return await this.browserDriver.readLast()
      }
    }

    return await this.browserDriver.readLast()
  }

  /**
   * Extracts or downloads media from a chat.
   */
  async chatMedia(chat, opts = {}) {
    if (this.activeTransport === 'noise' && !this.fallbackState.active) {
      try {
        const client = await this._getNoiseClient()
        if (typeof client.chatMedia === 'function') {
          return await client.chatMedia(chat, opts)
        }
      } catch (err) {
        const reason = err && err.message ? err.message : String(err)
        console.warn(`[muse-transport] Noise transport unavailable (${reason}), falling back to browser driver`)
        this._triggerFallback(reason)
        await this._cleanupNoise()
        return await this.browserDriver.chatMedia(chat, opts)
      }
    }

    return await this.browserDriver.chatMedia(chat, opts)
  }

  /**
   * Interactive browser login helper.
   */
  async login(timeoutMs = 300000) {
    return await this.browserDriver.login(timeoutMs)
  }

  /**
   * Diagnostic DOM dump.
   */
  async dumpDom(maxChars = 20000) {
    return await this.browserDriver.dumpDom(maxChars)
  }

  /**
   * Self-test and initialization helper.
   */
  async launch() {
    if (this.activeTransport === 'browser') {
      return await this.browserDriver.launch()
    }

    try {
      await this._getNoiseClient()
    } catch (err) {
      const reason = err && err.message ? err.message : String(err)
      console.warn(`[muse-transport] Noise transport unavailable during launch (${reason}), falling back to browser driver`)
      this._triggerFallback(reason)
      await this._cleanupNoise()
      return await this.browserDriver.launch()
    }
    return null
  }

  /**
   * Closes active transport connections cleanly.
   */
  async close() {
    await this._cleanupNoise()
    return await this.browserDriver.close()
  }
}

export const transport = new MuseTransport()
export default transport
