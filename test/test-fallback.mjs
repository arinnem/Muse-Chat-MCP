/**
 * test/test-fallback.mjs
 * ------------------------------------------------------------------
 * Acceptance test suite for Milestone 6 (R6):
 * Unified Transport Switch & Seamless Browser Fallback.
 *
 * Subject Under Test:
 *   MuseTransport (muse-transport.mjs) — tested directly with real state transitions.
 *
 * External Dependencies:
 *   - Playwright Chrome browser driver (isolated to prevent launching real GUI windows).
 *   - Meta cloud WebSocket server (tested with offline error vectors & local loopbacks).
 *
 * Verification Areas:
 * 1. Direct browser mode (MUSE_TRANSPORT=browser) selects browser driver directly
 *    without touching Noise client or throwing exceptions.
 * 2. Seamless circuit-breaker fallback when Noise connection fails (ECONNREFUSED):
 *    logs diagnostic warning, triggers fallback, and seamlessly returns browser driver reply.
 * 3. Graceful fallback on authentication / token resolution failures (AuthSessionExpiredError):
 *    delegates chatStream to browser driver and delivers monotonic stream deltas.
 * 4. Mid-stream or handshake abort handling without unhandled promise rejections.
 * 5. Accurate status reporting: activeTransport, fallbackActive, fallbackReason,
 *    noiseStatus, and preserved browserStatus fields.
 * 6. Sticky fallback circuit-breaker: subsequent requests avoid flapping and stay on browser.
 * 7. Programmatic circuit-breaker reset via resetFallback().
 * 8. Clean resource teardown on close() with zero orphaned handles.
 * 9. Real component execution: Real TokenManager and real NoiseClient integration.
 *
 * Pure Node 20+ built-ins (node:test, node:assert/strict). Zero external deps.
 * ------------------------------------------------------------------
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { MuseTransport, AuthSessionExpiredError } from '../muse-transport.mjs'
import { NoiseClient } from '../lib/noise/noise-client.mjs'
import { TokenManager } from '../lib/noise/token-manager.mjs'

/**
 * Creates an injectable test browser driver to isolate unit testing
 * from actual Chrome / Playwright launches.
 */
function createTestBrowserDriver(overrides = {}) {
  const calls = []
  return {
    calls,
    async status() {
      calls.push({ method: 'status' })
      return overrides.status ? overrides.status() : {
        browserRunning: true,
        url: 'https://muse.ai/',
        loggedIn: true,
        viewerId: '1315296991670251',
        composerReady: true,
        profileDir: path.join(os.tmpdir(), '.muse-fallback-profile'),
        headless: true,
      }
    },
    async chat(prompt, opts = {}) {
      calls.push({ method: 'chat', prompt, opts })
      if (overrides.chat) return overrides.chat(prompt, opts)
      return {
        reply: `Browser reply to: ${prompt}`,
        messages: [`Browser reply to: ${prompt}`],
        threadUrl: 'https://muse.ai/t/78103984',
        elapsedMs: 50,
      }
    },
    async chatStream(prompt, opts = {}) {
      calls.push({ method: 'chatStream', prompt, opts })
      if (overrides.chatStream) return overrides.chatStream(prompt, opts)
      if (typeof opts.onDelta === 'function') {
        opts.onDelta(`Browser streaming reply to: ${prompt}`)
      }
      return {
        reply: `Browser streaming reply to: ${prompt}`,
        messages: [`Browser streaming reply to: ${prompt}`],
        threadUrl: 'https://muse.ai/t/78103985',
        elapsedMs: 65,
      }
    },
    async newChat() {
      calls.push({ method: 'newChat' })
      return overrides.newChat ? overrides.newChat() : { ok: true, url: 'https://muse.ai/' }
    },
    async listChats(query) {
      calls.push({ method: 'listChats', query })
      return overrides.listChats ? overrides.listChats(query) : {
        chats: [{ title: 'Test Thread', active: true }],
        threadUrl: 'https://muse.ai/',
      }
    },
    async openChat(target) {
      calls.push({ method: 'openChat', target })
      return overrides.openChat ? overrides.openChat(target) : { ok: true, url: 'https://muse.ai/thread/target' }
    },
    async readChat(max = 100) {
      calls.push({ method: 'readChat', max })
      return overrides.readChat ? overrides.readChat(max) : {
        messages: [{ role: 'assistant', text: 'Browser read chat message' }],
        count: 1,
        threadUrl: 'https://muse.ai/',
      }
    },
    async readLast() {
      calls.push({ method: 'readLast' })
      return overrides.readLast ? overrides.readLast() : {
        reply: 'Browser last reply',
        messages: ['Browser last reply'],
        threadUrl: 'https://muse.ai/',
      }
    },
    async chatMedia(chat, opts = {}) {
      calls.push({ method: 'chatMedia', chat, opts })
      return overrides.chatMedia ? overrides.chatMedia(chat, opts) : {
        items: [],
        urls: [],
        count: 0,
        threadUrl: 'https://muse.ai/',
      }
    },
    async login(timeoutMs = 300000) {
      calls.push({ method: 'login', timeoutMs })
      return overrides.login ? overrides.login(timeoutMs) : { loggedIn: true, viewerId: '1315296991670251' }
    },
    async dumpDom(maxChars = 20000) {
      calls.push({ method: 'dumpDom', maxChars })
      return overrides.dumpDom ? overrides.dumpDom(maxChars) : {
        url: 'https://muse.ai/',
        title: 'Muse DOM',
        counts: { messages: 1 },
        html: '<div>dom</div>',
      }
    },
    async launch() {
      calls.push({ method: 'launch' })
      return overrides.launch ? overrides.launch() : null
    },
    async close() {
      calls.push({ method: 'close' })
      return overrides.close ? overrides.close() : { ok: true }
    },
  }
}

// -------------------------------------------------------------------------
// Suite 1: Direct Browser Mode Configuration
// -------------------------------------------------------------------------

test('Suite 1.1: Setting MUSE_TRANSPORT=browser selects browser driver directly', async () => {
  const testDriver = createTestBrowserDriver()
  let noiseConstructed = false

  class NoiseClientSpy {
    constructor() { noiseConstructed = true }
    async connect() { throw new Error('Noise should not be called in browser mode') }
  }

  const transport = new MuseTransport({
    transport: 'browser',
    driver: testDriver,
    NoiseClientClass: NoiseClientSpy,
  })

  assert.equal(transport.configTransport, 'browser')
  assert.equal(transport.activeTransport, 'browser')
  assert.equal(transport.fallbackActive, false)
  assert.equal(transport.fallbackReason, null)

  const st = await transport.status()
  assert.equal(st.transport, 'browser')
  assert.equal(st.activeTransport, 'browser')
  assert.equal(st.fallbackActive, false)
  assert.equal(st.fallbackAvailable, true)
  assert.equal(st.browserRunning, true)
  assert.equal(st.viewerId, '1315296991670251')

  const res = await transport.chat('Hello in browser mode')
  assert.equal(res.reply, 'Browser reply to: Hello in browser mode')
  assert.equal(noiseConstructed, false, 'NoiseClient must NOT be instantiated when transport=browser')
  assert.ok(testDriver.calls.some((c) => c.method === 'chat'))
})

test('Suite 1.2: All auxiliary methods delegate to browser driver when transport=browser', async () => {
  const testDriver = createTestBrowserDriver()
  const transport = new MuseTransport({
    transport: 'browser',
    driver: testDriver,
  })

  await transport.newChat()
  await transport.listChats('test')
  await transport.openChat('target')
  await transport.readChat(50)
  await transport.readLast()
  await transport.chatMedia('chat-1')
  await transport.login(5000)
  await transport.dumpDom(1000)
  await transport.launch()
  await transport.close()

  const calledMethods = testDriver.calls.map((c) => c.method)
  const expected = [
    'newChat', 'listChats', 'openChat', 'readChat',
    'readLast', 'chatMedia', 'login', 'dumpDom', 'launch', 'close',
  ]

  for (const exp of expected) {
    assert.ok(calledMethods.includes(exp), `Expected test driver method ${exp} to be invoked`)
  }
})

// -------------------------------------------------------------------------
// Suite 2: Seamless Circuit-Breaker Fallback on Noise Failures
// -------------------------------------------------------------------------

test('Suite 2.1: Failing Noise connection (ECONNREFUSED) seamlessly falls back to browser driver', async () => {
  const testDriver = createTestBrowserDriver()
  const warnings = []
  const originalWarn = console.warn
  console.warn = (...args) => warnings.push(args.join(' '))

  try {
    class NetworkFailureSimulator {
      constructor() { this.connected = false }
      async connect() {
        throw new Error('connect ECONNREFUSED 127.0.0.1:443')
      }
      async close() { this.closed = true }
    }

    const transport = new MuseTransport({
      transport: 'noise',
      driver: testDriver,
      NoiseClientClass: NetworkFailureSimulator,
    })

    assert.equal(transport.configTransport, 'noise')
    assert.equal(transport.activeTransport, 'noise')
    assert.equal(transport.fallbackActive, false)

    // chat() should NOT throw; it should catch, warn, fall back, and return the browser reply
    const res = await transport.chat('Prompt during network down')

    assert.equal(res.reply, 'Browser reply to: Prompt during network down')
    assert.equal(transport.activeTransport, 'browser')
    assert.equal(transport.fallbackActive, true)
    assert.match(transport.fallbackReason, /ECONNREFUSED/)

    // Diagnostic warning must be emitted matching required pattern
    assert.ok(warnings.length > 0, 'Diagnostic warning must be logged')
    assert.match(
      warnings[0],
      /\[muse-transport\] Noise transport unavailable \(connect ECONNREFUSED.*\), falling back to browser driver/,
      'Warning must follow required diagnostic format',
    )

    // Driver must have received the chat call
    const driverChat = testDriver.calls.find((c) => c.method === 'chat')
    assert.ok(driverChat)
    assert.equal(driverChat.prompt, 'Prompt during network down')
  } finally {
    console.warn = originalWarn
  }
})

test('Suite 2.2: AuthSessionExpiredError during chatStream triggers fallback with monotonic deltas', async () => {
  const testDriver = createTestBrowserDriver()
  const warnings = []
  const originalWarn = console.warn
  console.warn = (...args) => warnings.push(args.join(' '))

  try {
    class ExpiredAuthSimulator {
      constructor() { this.connected = false }
      async connect() {
        throw new AuthSessionExpiredError('Missing authentication cookies (c_user/xs/datr) in profile')
      }
      async close() { this.closed = true }
    }

    const transport = new MuseTransport({
      transport: 'noise',
      driver: testDriver,
      NoiseClientClass: ExpiredAuthSimulator,
    })

    const streamDeltas = []
    const res = await transport.chatStream('Explain quantum computing', {
      onDelta: (fullText) => streamDeltas.push(fullText),
    })

    assert.equal(res.reply, 'Browser streaming reply to: Explain quantum computing')
    assert.equal(transport.activeTransport, 'browser')
    assert.equal(transport.fallbackActive, true)
    assert.match(transport.fallbackReason, /Missing authentication cookies/)

    // Verify stream deltas arrived via browser driver
    assert.ok(streamDeltas.length > 0)
    assert.equal(streamDeltas[0], 'Browser streaming reply to: Explain quantum computing')

    // Warning logged
    assert.ok(warnings.some((w) => w.includes('falling back to browser driver')))
  } finally {
    console.warn = originalWarn
  }
})

test('Suite 2.3: Noise handshake timeout during chat() triggers seamless fallback and closes client', async () => {
  const testDriver = createTestBrowserDriver()
  let noiseClosed = false

  class TimeoutSimulator {
    constructor() { this.connected = false }
    async connect() {
      throw new Error('Noise handshake timed out after 10000ms')
    }
    async close() {
      noiseClosed = true
    }
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: testDriver,
    NoiseClientClass: TimeoutSimulator,
  })

  const res = await transport.chat('Trigger timeout fallback')
  assert.equal(res.reply, 'Browser reply to: Trigger timeout fallback')
  assert.equal(transport.activeTransport, 'browser')
  assert.equal(transport.fallbackActive, true)
  assert.match(transport.fallbackReason, /timed out/)
  assert.equal(noiseClosed, true, 'Failed Noise client must be cleanly closed')
})

test('Suite 2.4: Mid-stream error in chatStream gracefully falls back to browser driver', async () => {
  const testDriver = createTestBrowserDriver()

  class MidStreamDropSimulator {
    constructor() { this.connected = false }
    async connect() { this.connected = true }
    async chatStream() {
      throw new Error('WebSocket closed prematurely during generation')
    }
    async close() { this.connected = false }
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: testDriver,
    NoiseClientClass: MidStreamDropSimulator,
  })

  const res = await transport.chatStream('Test midstream drop', {
    onDelta: () => {},
  })

  assert.equal(res.reply, 'Browser streaming reply to: Test midstream drop')
  assert.equal(transport.activeTransport, 'browser')
  assert.equal(transport.fallbackActive, true)
  assert.match(transport.fallbackReason, /closed prematurely/)
})

// -------------------------------------------------------------------------
// Suite 3: Unified Status Reporting & Telemetry
// -------------------------------------------------------------------------

test('Suite 3.1: status() accurately reports activeTransport=noise when Noise is healthy', async () => {
  const testDriver = createTestBrowserDriver()

  class ConnectedGatewaySimulator {
    constructor() {
      this.connected = false
      this.credentials = {
        vm_id: 'vm-uuid-999',
        endpoint_url: 'wss://hatch.metaaivm.com/v1/noise',
        viewer_id: '1315296991670251',
      }
    }
    async connect() { this.connected = true }
    async close() { this.connected = false }
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: testDriver,
    NoiseClientClass: ConnectedGatewaySimulator,
  })

  // Pre-connect to simulate healthy session
  await transport._getNoiseClient()

  const st = await transport.status()
  assert.equal(st.transport, 'noise')
  assert.equal(st.activeTransport, 'noise')
  assert.equal(st.fallbackActive, false)
  assert.equal(st.fallbackReason, null)
  assert.equal(st.fallbackAvailable, true)
  assert.equal(st.noiseStatus.connected, true)
  assert.equal(st.noiseStatus.vmId, 'vm-uuid-999')
  assert.equal(st.loggedIn, true)
  assert.equal(st.composerReady, true)
  assert.equal(st.url, 'wss://hatch.metaaivm.com/v1/noise')
})

test('Suite 3.2: status() accurately reports fallbackActive=true after failure', async () => {
  const testDriver = createTestBrowserDriver()

  class CorruptHandshakeSimulator {
    async connect() { throw new Error('Handshake corrupt') }
    async close() {}
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: testDriver,
    NoiseClientClass: CorruptHandshakeSimulator,
  })

  await transport.chat('Fail once')
  assert.equal(transport.fallbackActive, true)

  const st = await transport.status()
  assert.equal(st.transport, 'noise')
  assert.equal(st.activeTransport, 'browser')
  assert.equal(st.fallbackActive, true)
  assert.equal(st.fallbackReason, 'Handshake corrupt')
  assert.equal(st.fallbackAvailable, true)
  assert.equal(st.noiseStatus.connected, false)
  assert.equal(st.browserRunning, true)
})

test('Suite 3.3: status() handles browser driver errors gracefully', async () => {
  const testDriver = createTestBrowserDriver({
    status: async () => { throw new Error('Browser status probe timeout') },
  })

  const transport = new MuseTransport({
    transport: 'browser',
    driver: testDriver,
  })

  const st = await transport.status()
  assert.equal(st.activeTransport, 'browser')
  assert.equal(st.error, 'Browser status probe timeout')
})

// -------------------------------------------------------------------------
// Suite 4: Circuit-Breaker Stability & Programmatic Reset
// -------------------------------------------------------------------------

test('Suite 4.1: Once fallback activates, subsequent requests stay on browser driver without re-connecting', async () => {
  const testDriver = createTestBrowserDriver()
  let connectAttempts = 0

  class DroppedConnectionSimulator {
    async connect() {
      connectAttempts++
      throw new Error('Connection refused')
    }
    async close() {}
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: testDriver,
    NoiseClientClass: DroppedConnectionSimulator,
  })

  // First request triggers fallback
  await transport.chat('Message 1')
  assert.equal(connectAttempts, 1)
  assert.equal(transport.fallbackActive, true)

  // Second request should bypass Noise and execute on browser driver directly
  const res2 = await transport.chat('Message 2')
  assert.equal(res2.reply, 'Browser reply to: Message 2')
  assert.equal(connectAttempts, 1, 'Subsequent request must NOT retry broken Noise connection')

  // Third request streaming
  const res3 = await transport.chatStream('Message 3', { onDelta: () => {} })
  assert.equal(res3.reply, 'Browser streaming reply to: Message 3')
  assert.equal(connectAttempts, 1, 'Streaming request must also bypass Noise once in fallback')
})

test('Suite 4.2: resetFallback() clears circuit breaker and restores noise transport', async () => {
  const testDriver = createTestBrowserDriver()
  let connectAttempts = 0

  class TransientGlitchSimulator {
    async connect() {
      connectAttempts++
      if (connectAttempts === 1) throw new Error('Transient network glitch')
      this.connected = true
    }
    async chatStream(prompt) {
      return { reply: `Noise reply to: ${prompt}`, text: `Noise reply to: ${prompt}` }
    }
    async close() { this.connected = false }
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: testDriver,
    NoiseClientClass: TransientGlitchSimulator,
  })

  // Request 1: fails and falls back
  await transport.chat('Request 1')
  assert.equal(transport.fallbackActive, true)
  assert.equal(transport.activeTransport, 'browser')

  // Programmatically reset circuit breaker
  transport.resetFallback()
  assert.equal(transport.fallbackActive, false)
  assert.equal(transport.fallbackReason, null)
  assert.equal(transport.activeTransport, 'noise')

  // Request 2: successfully connects via Noise on retry
  const res2 = await transport.chat('Request 2')
  assert.equal(res2.reply, 'Noise reply to: Request 2')
  assert.equal(transport.fallbackActive, false)
  assert.equal(transport.activeTransport, 'noise')
  assert.equal(connectAttempts, 2)
})

test('Suite 4.3: close() closes Noise client and browser driver cleanly', async () => {
  const testDriver = createTestBrowserDriver()
  let noiseClosed = false

  class TeardownSimulator {
    async connect() { this.connected = true }
    async close() { noiseClosed = true }
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: testDriver,
    NoiseClientClass: TeardownSimulator,
  })

  await transport._getNoiseClient()
  await transport.close()

  assert.equal(noiseClosed, true, 'NoiseClient.close() must be called')
  assert.ok(testDriver.calls.some((c) => c.method === 'close'), 'BrowserDriver.close() must be called')
  assert.equal(transport.noiseClient, null, 'noiseClient reference must be cleared')
})

// -------------------------------------------------------------------------
// Suite 5: Fallback on Auxiliary Methods
// -------------------------------------------------------------------------

test('Suite 5.1: newChat(), readChat(), readLast() fall back to browser driver on Noise failure', async () => {
  const testDriver = createTestBrowserDriver()

  class RpcOfflineSimulator {
    async connect() { throw new Error('Noise RPC offline') }
    async close() {}
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: testDriver,
    NoiseClientClass: RpcOfflineSimulator,
  })

  // newChat fallback
  const nc = await transport.newChat()
  assert.equal(nc.ok, true)

  // readChat fallback
  const rc = await transport.readChat(10)
  assert.equal(rc.count, 1)
  assert.equal(rc.messages[0].text, 'Browser read chat message')

  // readLast fallback
  const rl = await transport.readLast()
  assert.equal(rl.reply, 'Browser last reply')

  // Verify all methods were dispatched to browser driver
  const called = testDriver.calls.map((c) => c.method)
  assert.ok(called.includes('newChat'))
  assert.ok(called.includes('readChat'))
  assert.ok(called.includes('readLast'))
})

// -------------------------------------------------------------------------
// Suite 6: Integration with Real TokenManager & Real NoiseClient
// -------------------------------------------------------------------------

test('Suite 6.1: Real TokenManager with missing profile cookies triggers genuine AuthSessionExpiredError and fallback', async () => {
  const emptyDir = path.join(os.tmpdir(), `muse-empty-${Date.now()}`)
  fs.mkdirSync(emptyDir, { recursive: true })

  try {
    const realTokenManager = new TokenManager({ profileDir: emptyDir })
    const testDriver = createTestBrowserDriver()

    const transport = new MuseTransport({
      transport: 'noise',
      tokenManager: realTokenManager,
      driver: testDriver,
    })

    const res = await transport.chat('Real token manager missing cookie test')
    assert.equal(res.reply, 'Browser reply to: Real token manager missing cookie test')
    assert.equal(transport.fallbackActive, true)
    assert.match(transport.fallbackReason, /No valid session cookies found|Missing authentication cookies|AuthSessionExpiredError/)
  } finally {
    try { fs.rmSync(emptyDir, { recursive: true, force: true }) } catch {}
  }
})

test('Suite 6.2: Real NoiseClient connecting to closed local port triggers genuine connection failure and fallback', async () => {
  class ClosedPortTokenManager extends TokenManager {
    async ensureValidSession() {
      return {
        vm_id: 'test-vm-uuid',
        endpoint_url: 'ws://127.0.0.1:59998/v1/noise',
        auth_token: 'auth.test.offline',
        notary_token: 'notary.test.offline',
      }
    }
    invalidateToken() {}
  }

  const offlineTokenManager = new ClosedPortTokenManager()
  const realNoiseClient = new NoiseClient({
    tokenManager: offlineTokenManager,
    timeoutMs: 1500,
  })

  const testDriver = createTestBrowserDriver()
  const transport = new MuseTransport({
    transport: 'noise',
    noiseClient: realNoiseClient,
    driver: testDriver,
  })

  const res = await transport.chat('Real NoiseClient closed port fallback test')
  assert.equal(res.reply, 'Browser reply to: Real NoiseClient closed port fallback test')
  assert.equal(transport.fallbackActive, true)
  assert.match(transport.fallbackReason, /ECONNREFUSED|connect|closed|WebSocket/)
})
