/**
 * test/test-adversarial-m1-boundary.mjs
 * ------------------------------------------------------------------
 * Adversarial Stress Test Suite for Milestone 1:
 * Boundary Stress-Testing between MuseTransport and TokenManager.
 *
 * Authored by: challenger_m1_2 (Empirical Challenger)
 * Probing:
 *   1. TokenManager AuthSessionExpiredError Catch & Circuit Breaker:
 *      - In-browser 401 Unauthorized during session resolution
 *      - In-browser 403 Forbidden during session resolution
 *      - Offline/HTTP missing cookies AuthSessionExpiredError
 *      - Offline/HTTP 401/403 response AuthSessionExpiredError
 *      - Immediate fallback triggering (fallbackActive = true, activeTransport = 'browser')
 *      - Seamless routing to browserDriver without client crashes
 *      - Monotonic deltas and clean finish for streaming chat
 *   2. Zero Unhandled Rejections Guarantee:
 *      - Global process 'unhandledRejection' trap verifying 0 rejections
 *      - Concurrent calls (chat + chatStream + newChat) during AuthSessionExpiredError
 *   3. TokenManager Constructor Options Verification:
 *      - new TokenManager({ driver: d })
 *      - new TokenManager({ browserDriver: d })
 *      - new TokenManager({})
 *      - new TokenManager() (no args)
 *      - new TokenManager({ driver: d1, browserDriver: d2 }) (precedence check)
 *      - new TokenManager({ driver: null, browserDriver: d2 }) (falsy fallback)
 *      - MuseTransport default instantiation passing { driver: this.browserDriver }
 *   4. Circuit-Breaker Stickiness & Programmatic Recovery:
 *      - Subsequent calls bypass TokenManager/Noise when fallbackActive
 *      - resetFallback() allows retry; re-triggers if error persists
 *   5. All Auxiliary Methods under AuthSessionExpiredError:
 *      - newChat, listChats, openChat, readChat, readLast, chatMedia, launch
 * ------------------------------------------------------------------
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import {
  MuseTransport,
  AuthSessionExpiredError,
} from '../muse-transport.mjs'
import { TokenManager } from '../lib/noise/token-manager.mjs'
import { NoiseClient } from '../lib/noise/noise-client.mjs'

/**
 * Creates an instrumented mock browser driver to verify calls and isolation.
 */
function createMockDriver(overrides = {}) {
  const calls = []
  return {
    calls,
    ctx: overrides.ctx || {
      async cookies() {
        calls.push({ method: 'ctx.cookies' })
        return []
      },
    },
    async requirePage() {
      calls.push({ method: 'requirePage' })
      if (overrides.requirePage) return overrides.requirePage()
      return {
        async evaluate(fn) {
          calls.push({ method: 'page.evaluate' })
          if (overrides.evaluate) return overrides.evaluate(fn)
          return {
            vm_id: 'mock-vm-123',
            endpoint_url: 'wss://mock-vm-123.metaaivm.com/',
            auth_token: 'auth-token-123',
            notary_token: 'notary-token-123',
            expires_in: 3600,
          }
        },
      }
    },
    async gotoApp() {
      calls.push({ method: 'gotoApp' })
      if (overrides.gotoApp) return overrides.gotoApp()
    },
    async status() {
      calls.push({ method: 'status' })
      if (overrides.status) return overrides.status()
      return {
        browserRunning: true,
        url: 'https://muse.ai/',
        loggedIn: true,
        viewerId: '1315296991670251',
        composerReady: true,
        profileDir: '/tmp/.muse-profile',
        headless: true,
      }
    },
    async chat(prompt, opts = {}) {
      calls.push({ method: 'chat', prompt, opts })
      if (overrides.chat) return overrides.chat(prompt, opts)
      return {
        reply: `Mock browser response to: ${prompt}`,
        messages: [`Mock browser response to: ${prompt}`],
        threadUrl: 'https://muse.ai/t/test-mock',
        elapsedMs: 25,
      }
    },
    async chatStream(prompt, opts = {}) {
      calls.push({ method: 'chatStream', prompt, opts })
      if (overrides.chatStream) return overrides.chatStream(prompt, opts)
      if (typeof opts.onDelta === 'function') {
        opts.onDelta(`Stream delta 1: ${prompt}`)
        opts.onDelta(`Stream delta 2: ${prompt}`)
      }
      return {
        reply: `Full stream reply to: ${prompt}`,
        messages: [`Full stream reply to: ${prompt}`],
        threadUrl: 'https://muse.ai/t/test-stream',
        elapsedMs: 30,
      }
    },
    async newChat() {
      calls.push({ method: 'newChat' })
      if (overrides.newChat) return overrides.newChat()
      return { ok: true, activeChat: null, transport: 'browser' }
    },
    async listChats(query) {
      calls.push({ method: 'listChats', query })
      if (overrides.listChats) return overrides.listChats(query)
      return [{ id: 'chat-1', title: 'Test Chat' }]
    },
    async openChat(target) {
      calls.push({ method: 'openChat', target })
      if (overrides.openChat) return overrides.openChat(target)
      return { ok: true, opened: target }
    },
    async readChat(max = 100) {
      calls.push({ method: 'readChat', max })
      if (overrides.readChat) return overrides.readChat(max)
      return { messages: [{ role: 'assistant', text: 'Chat history' }], count: 1 }
    },
    async readLast() {
      calls.push({ method: 'readLast' })
      if (overrides.readLast) return overrides.readLast()
      return { reply: 'Last reply from browser', messages: ['Last reply from browser'] }
    },
    async chatMedia(chat, opts = {}) {
      calls.push({ method: 'chatMedia', chat, opts })
      if (overrides.chatMedia) return overrides.chatMedia(chat, opts)
      return { items: [], count: 0 }
    },
    async launch() {
      calls.push({ method: 'launch' })
      if (overrides.launch) return overrides.launch()
      return { ok: true }
    },
    async close() {
      calls.push({ method: 'close' })
      if (overrides.close) return overrides.close()
      return { ok: true }
    },
  }
}

test('Milestone 1 Boundary Suite: MuseTransport ↔ TokenManager Adversarial Probes', async (t) => {
  // Global unhandled rejection tracker for the entire suite
  const unhandledRejections = []
  const onUnhandled = (reason) => {
    unhandledRejections.push(reason)
  }
  process.on('unhandledRejection', onUnhandled)

  t.after(() => {
    process.off('unhandledRejection', onUnhandled)
    assert.equal(
      unhandledRejections.length,
      0,
      `Detected ${unhandledRejections.length} unhandled promise rejection(s): ${unhandledRejections.map(r => (r && r.message) || String(r)).join('; ')}`
    )
  })

  // =========================================================================
  // SECTION 1: CONSTRUCTOR OPTIONS VERIFICATION
  // =========================================================================

  await t.test('Constructor Option 1: new TokenManager({ driver: d }) sets browserDriver', () => {
    const d = { name: 'explicit-driver' }
    const tm = new TokenManager({ driver: d })
    assert.strictEqual(tm.browserDriver, d)
  })

  await t.test('Constructor Option 2: new TokenManager({ browserDriver: d }) sets browserDriver alias', () => {
    const d = { name: 'alias-driver' }
    const tm = new TokenManager({ browserDriver: d })
    assert.strictEqual(tm.browserDriver, d)
  })

  await t.test('Constructor Option 3: new TokenManager({}) sets browserDriver to null', () => {
    const tm = new TokenManager({})
    assert.strictEqual(tm.browserDriver, null)
  })

  await t.test('Constructor Option 4: new TokenManager() (no args) sets browserDriver to null', () => {
    const tm = new TokenManager()
    assert.strictEqual(tm.browserDriver, null)
  })

  await t.test('Constructor Option 5: new TokenManager({ driver: d1, browserDriver: d2 }) prioritizes driver', () => {
    const d1 = { name: 'primary-driver' }
    const d2 = { name: 'secondary-driver' }
    const tm = new TokenManager({ driver: d1, browserDriver: d2 })
    assert.strictEqual(tm.browserDriver, d1)
  })

  await t.test('Constructor Option 6: new TokenManager({ driver: null, browserDriver: d2 }) falls back to browserDriver', () => {
    const d2 = { name: 'secondary-driver' }
    const tm = new TokenManager({ driver: null, browserDriver: d2 })
    assert.strictEqual(tm.browserDriver, d2)
  })

  await t.test('Constructor Option 7: MuseTransport default instantiation wires driver to TokenManager', async () => {
    const testDriver = createMockDriver()
    const transport = new MuseTransport({
      driver: testDriver,
    })

    assert.strictEqual(transport.browserDriver, testDriver)
    assert.strictEqual(transport.tokenManager, null)

    // Trigger Noise client creation via _getNoiseClient failure
    class CapturingNoiseClient {
      constructor(opts) {
        this.tokenManager = opts.tokenManager
        this.connected = false
      }
      async connect() {
        throw new Error('Forced connect reject to inspect instantiated tokenManager')
      }
      async close() {}
    }

    transport.NoiseClientClass = CapturingNoiseClient

    try {
      await transport.chat('Probe default token manager wiring')
    } catch {}

    assert.ok(transport.tokenManager instanceof TokenManager)
    assert.strictEqual(transport.tokenManager.browserDriver, testDriver)
  })

  // =========================================================================
  // SECTION 2: AUTHSESSIONEXPIREDERROR CATCH & CIRCUIT BREAKER FALLBACK
  // =========================================================================

  await t.test('Fallback Probe 1: In-browser 401 Unauthorized AuthSessionExpiredError triggers immediate fallback in chat()', async () => {
    const testDriver = createMockDriver({
      requirePage: async () => ({
        async evaluate() {
          throw new Error('POST /api/hatch/token failed with HTTP 401: Unauthorized')
        },
      }),
    })

    const tm = new TokenManager({ driver: testDriver })
    const transport = new MuseTransport({
      transport: 'noise',
      tokenManager: tm,
      driver: testDriver,
    })

    assert.equal(transport.fallbackActive, false)
    assert.equal(transport.activeTransport, 'noise')

    const res = await transport.chat('Prompt during 401 expired session')

    assert.equal(transport.fallbackActive, true)
    assert.equal(transport.activeTransport, 'browser')
    assert.match(transport.fallbackReason, /Browser session resolution failed:.*401/)
    assert.equal(res.reply, 'Mock browser response to: Prompt during 401 expired session')

    // Verify browserDriver received the call
    const driverChatCalls = testDriver.calls.filter((c) => c.method === 'chat')
    assert.equal(driverChatCalls.length, 1)
    assert.equal(driverChatCalls[0].prompt, 'Prompt during 401 expired session')
  })

  await t.test('Fallback Probe 2: In-browser 403 Forbidden AuthSessionExpiredError triggers immediate fallback in chatStream()', async () => {
    const testDriver = createMockDriver({
      requirePage: async () => ({
        async evaluate() {
          throw new Error('GET /api/session failed with HTTP 403: Forbidden')
        },
      }),
    })

    const tm = new TokenManager({ driver: testDriver })
    const transport = new MuseTransport({
      transport: 'noise',
      tokenManager: tm,
      driver: testDriver,
    })

    const deltas = []
    const res = await transport.chatStream('Stream prompt during 403 forbidden', {
      onDelta: (d) => deltas.push(d),
    })

    assert.equal(transport.fallbackActive, true)
    assert.equal(transport.activeTransport, 'browser')
    assert.match(transport.fallbackReason, /Browser session resolution failed:.*403/)
    assert.equal(res.reply, 'Full stream reply to: Stream prompt during 403 forbidden')

    // Verify monotonic deltas were delivered from browser driver
    assert.ok(deltas.length >= 2)
    assert.equal(deltas[0], 'Stream delta 1: Stream prompt during 403 forbidden')
    assert.equal(deltas[1], 'Stream delta 2: Stream prompt during 403 forbidden')

    const driverStreamCalls = testDriver.calls.filter((c) => c.method === 'chatStream')
    assert.equal(driverStreamCalls.length, 1)
  })

  await t.test('Fallback Probe 3: Offline/HTTP mode with no cookies throws AuthSessionExpiredError and falls back', async () => {
    const emptyTempDir = path.join(os.tmpdir(), `muse-challenger-empty-${Date.now()}`)
    fs.mkdirSync(emptyTempDir, { recursive: true })

    try {
      const testDriver = createMockDriver()
      // TokenManager without driver, pointing to empty directory
      const tm = new TokenManager({
        profileDir: emptyTempDir,
        storageDir: emptyTempDir,
      })
      assert.equal(tm.browserDriver, null)

      const transport = new MuseTransport({
        transport: 'noise',
        tokenManager: tm,
        driver: testDriver,
      })

      const res = await transport.chat('Prompt with empty profile cookies')

      assert.equal(transport.fallbackActive, true)
      assert.equal(transport.activeTransport, 'browser')
      assert.match(transport.fallbackReason, /No valid session cookies found/)
      assert.equal(res.reply, 'Mock browser response to: Prompt with empty profile cookies')
    } finally {
      fs.rmSync(emptyTempDir, { recursive: true, force: true })
    }
  })

  await t.test('Fallback Probe 4: Explicitly thrown AuthSessionExpiredError in NoiseClient.connect() routes to browserDriver', async () => {
    const testDriver = createMockDriver()

    class AuthExpiredClient {
      constructor() {
        this.connected = false
      }
      async connect() {
        throw new AuthSessionExpiredError('Simulated session ticket expired 24h ago', { status: 401 })
      }
      async close() {}
    }

    const transport = new MuseTransport({
      transport: 'noise',
      driver: testDriver,
      NoiseClientClass: AuthExpiredClient,
    })

    const res = await transport.chat('Test custom AuthSessionExpiredError')
    assert.equal(transport.fallbackActive, true)
    assert.equal(transport.activeTransport, 'browser')
    assert.match(transport.fallbackReason, /Simulated session ticket expired 24h ago/)
    assert.equal(res.reply, 'Mock browser response to: Test custom AuthSessionExpiredError')
  })

  // =========================================================================
  // SECTION 3: CONCURRENT REQUESTS & ZERO UNHANDLED REJECTIONS
  // =========================================================================

  await t.test('Concurrency Probe 1: 15 concurrent chat() requests during AuthSessionExpiredError all resolve to browserDriver', async () => {
    const testDriver = createMockDriver({
      requirePage: async () => ({
        async evaluate() {
          // Slight simulated delay
          await new Promise((r) => setTimeout(r, 20))
          throw new Error('GET /api/session failed with HTTP 401: {"error":"Unauthorized"}')
        },
      }),
    })

    const tm = new TokenManager({ driver: testDriver })
    const transport = new MuseTransport({
      transport: 'noise',
      tokenManager: tm,
      driver: testDriver,
    })

    // Dispatch 15 concurrent chat calls
    const prompts = Array.from({ length: 15 }, (_, i) => `Concurrent prompt #${i}`)
    const promises = prompts.map((p) => transport.chat(p))
    const results = await Promise.all(promises)

    assert.equal(results.length, 15)
    for (let i = 0; i < 15; i++) {
      assert.equal(results[i].reply, `Mock browser response to: Concurrent prompt #${i}`)
    }

    assert.equal(transport.fallbackActive, true)
    assert.equal(transport.activeTransport, 'browser')

    // Ensure all 15 calls reached browser driver
    const driverChatCalls = testDriver.calls.filter((c) => c.method === 'chat')
    assert.equal(driverChatCalls.length, 15)
  })

  await t.test('Concurrency Probe 2: Mixed concurrent operations (chat, chatStream, newChat, readLast) during AuthSessionExpiredError', async () => {
    const testDriver = createMockDriver({
      requirePage: async () => ({
        async evaluate() {
          await new Promise((r) => setTimeout(r, 15))
          throw new Error('POST /api/hatch/vm/wake failed with HTTP 403: Forbidden')
        },
      }),
    })

    const tm = new TokenManager({ driver: testDriver })
    const transport = new MuseTransport({
      transport: 'noise',
      tokenManager: tm,
      driver: testDriver,
    })

    const mixedOps = [
      transport.chat('Mixed op 1 chat'),
      transport.chatStream('Mixed op 2 stream', { onDelta: () => {} }),
      transport.newChat(),
      transport.readLast(),
      transport.listChats('test'),
      transport.readChat(10),
    ]

    const results = await Promise.all(mixedOps)
    assert.equal(results.length, 6)

    assert.equal(results[0].reply, 'Mock browser response to: Mixed op 1 chat')
    assert.equal(results[1].reply, 'Full stream reply to: Mixed op 2 stream')
    assert.equal(results[2].ok, true)
    assert.equal(results[3].reply, 'Last reply from browser')
    assert.equal(results[4].length, 1)
    assert.equal(results[5].count, 1)

    assert.equal(transport.fallbackActive, true)
    assert.equal(transport.activeTransport, 'browser')
  })

  // =========================================================================
  // SECTION 4: CIRCUIT-BREAKER STICKINESS & RECOVERY
  // =========================================================================

  await t.test('Circuit-Breaker Probe 1: Sticky fallback bypasses TokenManager on subsequent calls', async () => {
    let evaluateCount = 0
    const testDriver = createMockDriver({
      requirePage: async () => ({
        async evaluate() {
          evaluateCount++
          throw new Error('GET /api/session failed with HTTP 401: Unauthorized')
        },
      }),
    })

    const tm = new TokenManager({ driver: testDriver })
    const transport = new MuseTransport({
      transport: 'noise',
      tokenManager: tm,
      driver: testDriver,
    })

    // Call 1: triggers fallback
    await transport.chat('Initial call')
    assert.equal(transport.fallbackActive, true)
    assert.equal(evaluateCount, 1)

    // Call 2, 3, 4: should go directly to browser driver, evaluateCount must not increment
    await transport.chat('Second call')
    await transport.chatStream('Third call', { onDelta: () => {} })
    await transport.newChat()

    assert.equal(evaluateCount, 1, 'TokenManager must not be called again once fallback is active')
    assert.equal(transport.fallbackActive, true)
  })

  await t.test('Circuit-Breaker Probe 2: resetFallback() allows recovery after TokenManager error clears', async () => {
    let shouldFail = true
    let evaluateCount = 0

    const testDriver = createMockDriver({
      requirePage: async () => ({
        async evaluate() {
          evaluateCount++
          if (shouldFail) {
            throw new Error('GET /api/session failed with HTTP 401: Unauthorized')
          }
          return {
            vm_id: 'recovered-vm-001',
            endpoint_url: 'wss://recovered-vm-001.metaaivm.com/',
            auth_token: 'valid-recovered-token',
            notary_token: 'valid-recovered-notary',
            expires_in: 3600,
          }
        },
      }),
    })

    class RecoverableNoiseClient {
      constructor(opts) {
        this.tokenManager = opts.tokenManager
        this.connected = false
        this.credentials = null
      }
      async connect() {
        const creds = await this.tokenManager.ensureValidSession()
        this.credentials = creds
        this.connected = true
      }
      async chatStream(prompt) {
        return {
          reply: `Noise recovered reply to: ${prompt}`,
          text: `Noise recovered reply to: ${prompt}`,
        }
      }
      async close() {
        this.connected = false
      }
    }

    const tm = new TokenManager({ driver: testDriver })
    const transport = new MuseTransport({
      transport: 'noise',
      tokenManager: tm,
      driver: testDriver,
      NoiseClientClass: RecoverableNoiseClient,
    })

    // Request 1: fails and triggers fallback
    const res1 = await transport.chat('Attempt 1 (fails)')
    assert.equal(res1.reply, 'Mock browser response to: Attempt 1 (fails)')
    assert.equal(transport.fallbackActive, true)
    assert.equal(transport.activeTransport, 'browser')
    assert.equal(evaluateCount, 1)

    // Reset fallback and fix session
    shouldFail = false
    tm.invalidateToken()
    transport.resetFallback()

    assert.equal(transport.fallbackActive, false)
    assert.equal(transport.activeTransport, 'noise')

    // Request 2: successfully connects via Noise
    const res2 = await transport.chat('Attempt 2 (succeeds via Noise)')
    assert.equal(res2.reply, 'Noise recovered reply to: Attempt 2 (succeeds via Noise)')
    assert.equal(transport.fallbackActive, false)
    assert.equal(transport.activeTransport, 'noise')
    assert.equal(evaluateCount, 2)
  })

  // =========================================================================
  // SECTION 5: ALL AUXILIARY METHODS UNDER AUTHSESSIONEXPIREDERROR
  // =========================================================================

  await t.test('Auxiliary Methods Probe: newChat, listChats, openChat, readChat, readLast, chatMedia, launch all fall back cleanly', async () => {
    const testDriver = createMockDriver({
      requirePage: async () => ({
        async evaluate() {
          throw new Error('GET /api/session failed with HTTP 403: Forbidden')
        },
      }),
    })

    const tm = new TokenManager({ driver: testDriver })

    // Test newChat
    const transport1 = new MuseTransport({ transport: 'noise', tokenManager: tm, driver: testDriver })
    const nc = await transport1.newChat()
    assert.equal(nc.ok, true)
    assert.equal(transport1.fallbackActive, true)

    // Test listChats
    const transport2 = new MuseTransport({ transport: 'noise', tokenManager: tm, driver: testDriver })
    const lc = await transport2.listChats('test-query')
    assert.equal(lc.length, 1)
    assert.equal(transport2.fallbackActive, true)

    // Test openChat
    const transport3 = new MuseTransport({ transport: 'noise', tokenManager: tm, driver: testDriver })
    const oc = await transport3.openChat('thread-123')
    assert.equal(oc.ok, true)
    assert.equal(transport3.fallbackActive, true)

    // Test readChat
    const transport4 = new MuseTransport({ transport: 'noise', tokenManager: tm, driver: testDriver })
    const rc = await transport4.readChat(50)
    assert.equal(rc.count, 1)
    assert.equal(transport4.fallbackActive, true)

    // Test readLast
    const transport5 = new MuseTransport({ transport: 'noise', tokenManager: tm, driver: testDriver })
    const rl = await transport5.readLast()
    assert.equal(rl.reply, 'Last reply from browser')
    assert.equal(transport5.fallbackActive, true)

    // Test chatMedia
    const transport6 = new MuseTransport({ transport: 'noise', tokenManager: tm, driver: testDriver })
    const cm = await transport6.chatMedia('chat-456')
    assert.equal(cm.count, 0)
    assert.equal(transport6.fallbackActive, true)

    // Test launch
    const transport7 = new MuseTransport({ transport: 'noise', tokenManager: tm, driver: testDriver })
    const ln = await transport7.launch()
    assert.equal(ln.ok, true)
    assert.equal(transport7.fallbackActive, true)
  })

  // =========================================================================
  // SECTION 6: UNIFIED STATUS REFLECTION UNDER TOKEN FAILURE
  // =========================================================================

  await t.test('Status Probe: status() reflects accurate telemetry before and after AuthSessionExpiredError', async () => {
    const testDriver = createMockDriver({
      requirePage: async () => ({
        async evaluate() {
          throw new Error('GET /api/session failed with HTTP 401: Unauthorized')
        },
      }),
    })

    const tm = new TokenManager({ driver: testDriver })
    const transport = new MuseTransport({
      transport: 'noise',
      tokenManager: tm,
      driver: testDriver,
    })

    // Before failure
    const stBefore = await transport.status()
    assert.equal(stBefore.transport, 'noise')
    assert.equal(stBefore.activeTransport, 'noise')
    assert.equal(stBefore.fallbackActive, false)
    assert.equal(stBefore.fallbackReason, null)
    assert.equal(stBefore.fallbackAvailable, true)
    assert.equal(stBefore.noiseStatus.connected, false)

    // Trigger failure via chat
    await transport.chat('Trigger status failure')

    // After failure
    const stAfter = await transport.status()
    assert.equal(stAfter.transport, 'noise')
    assert.equal(stAfter.activeTransport, 'browser')
    assert.equal(stAfter.fallbackActive, true)
    assert.match(stAfter.fallbackReason, /401/)
    assert.equal(stAfter.fallbackAvailable, true)
    assert.equal(stAfter.browserRunning, true)
    assert.equal(stAfter.loggedIn, true)
    assert.equal(stAfter.composerReady, true)
  })
})
