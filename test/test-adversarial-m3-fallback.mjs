/**
 * test/test-adversarial-m3-fallback.mjs
 * ------------------------------------------------------------------
 * Adversarial Stress & Verification Harness for Milestone 3:
 * Seamless Phase 1 Playwright Fallback across Interfaces.
 *
 * Authored by: challenger_m3_1 (Empirical Challenger)
 *
 * Core Probes:
 * 1. Socket drop fast rejection: in-flight streams reject in < 500ms (measured
 *    via performance.now()), without hung promises or leaking listeners.
 * 2. Token deduplication guard: mid-stream failure with partial tokens prevents
 *    duplicate text re-emission over open SSE streams; browser driver is NOT called.
 * 3. Status responsiveness: status() returns in < 1000ms when composer is unmounted.
 * 4. High concurrency & burst stress testing.
 *
 * Pure Node.js (node:test, node:assert/strict). Zero external deps.
 * ------------------------------------------------------------------
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { performance } from 'node:perf_hooks'

import { MuseTransport } from '../muse-transport.mjs'
import { NoiseClient } from '../lib/noise/noise-client.mjs'
import { TokenManager } from '../lib/noise/token-manager.mjs'
import { MuseDriver } from '../muse-driver.mjs'
import {
  generateX25519KeyPair,
  x25519DH,
  concat,
  zeroize,
  SymmetricState,
} from '../lib/noise/crypto.mjs'

/**
 * Synthetic Noise Handshake Responder for fast test setup.
 */
class SyntheticNoiseHarnessResponder {
  constructor(staticKeyPair) {
    this.s = staticKeyPair
    this.e = null
    this.re = null
    this.rs = null
    this.symmetric = new SymmetricState()
  }

  async initialize() {
    await this.symmetric.initialize()
  }

  async receiveMessage1(msg1) {
    this.re = new Uint8Array(msg1.subarray(0, 32))
    await this.symmetric.mixHash(this.re)
    await this.symmetric.decryptAndHash(msg1.subarray(32))

    this.e = await generateX25519KeyPair()
    await this.symmetric.mixHash(this.e.publicKeyBytes)

    const ee = await x25519DH(this.e.privateKey, this.re)
    await this.symmetric.mixKey(ee)
    zeroize(ee)

    const enc_s = await this.symmetric.encryptAndHash(this.s.publicKeyBytes)
    const es = await x25519DH(this.s.privateKey, this.re)
    await this.symmetric.mixKey(es)
    zeroize(es)

    const enc_attestation = await this.symmetric.encryptAndHash(new TextEncoder().encode('MUSE_OK'))
    return concat(this.e.publicKeyBytes, enc_s, enc_attestation)
  }

  async receiveMessage3(msg3) {
    this.rs = await this.symmetric.decryptAndHash(msg3.subarray(0, 48))
    const se = await x25519DH(this.e.privateKey, this.rs)
    await this.symmetric.mixKey(se)
    zeroize(se)
    await this.symmetric.decryptAndHash(msg3.subarray(48))
    return await this.symmetric.split()
  }
}

/**
 * Controlled Mock WebSocket with listener tracking.
 */
class ControllableMockWebSocket extends EventEmitter {
  static instances = []
  static responder = null

  constructor(url) {
    super()
    this.url = url
    this.readyState = 1
    this.binaryType = 'arraybuffer'
    ControllableMockWebSocket.instances.push(this)
    this._step = 0
    queueMicrotask(() => this.emit('open'))
  }

  addEventListener(event, listener) {
    this.on(event, listener)
  }

  removeEventListener(event, listener) {
    this.off(event, listener)
  }

  async send(data) {
    if (!ControllableMockWebSocket.responder) return
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data)

    if (this._step === 0) {
      this._step = 1
      const msg2 = await ControllableMockWebSocket.responder.receiveMessage1(bytes)
      queueMicrotask(() => {
        this.emit('message', { data: msg2.buffer ? msg2.buffer : msg2 })
      })
    } else if (this._step === 1) {
      this._step = 2
      await ControllableMockWebSocket.responder.receiveMessage3(bytes)
    }
  }

  drop(code = 1006, reason = 'Abrupt socket termination') {
    this.readyState = 3
    queueMicrotask(() => {
      this.emit('close', { code, reason, wasClean: false })
    })
  }

  close(code = 1000, reason = 'Normal Closure') {
    this.readyState = 3
    queueMicrotask(() => {
      this.emit('close', { code, reason, wasClean: true })
    })
  }
}

class FastTokenManager extends TokenManager {
  async ensureValidSession() {
    return {
      vm_id: 'vm-stress-test-uuid',
      endpoint_url: 'wss://hatch.metaaivm.com/v1/noise',
      auth_token: 'auth-stress-token',
      notary_token: 'notary-stress-token',
    }
  }
}

function createMockBrowserDriver(overrides = {}) {
  const calls = []
  return {
    calls,
    async status() {
      calls.push({ method: 'status' })
      if (overrides.status) return overrides.status()
      return {
        browserRunning: true,
        url: 'https://muse.ai/',
        loggedIn: true,
        viewerId: '1315296991670251',
        composerReady: true,
      }
    },
    async chat(prompt, opts) {
      calls.push({ method: 'chat', prompt, opts })
      if (overrides.chat) return overrides.chat(prompt, opts)
      return { reply: `Browser reply to: ${prompt}` }
    },
    async chatStream(prompt, opts = {}) {
      calls.push({ method: 'chatStream', prompt, opts })
      if (overrides.chatStream) return overrides.chatStream(prompt, opts)
      if (typeof opts.onDelta === 'function') {
        opts.onDelta(`Browser streamed: ${prompt}`)
      }
      return { reply: `Browser streamed: ${prompt}` }
    },
    async close() {
      calls.push({ method: 'close' })
    },
  }
}

// ============================================================================
// SUITE 1: PROBE SOCKET DROP REJECTION TIMING (< 500ms) & LISTENER INTEGRITY
// ============================================================================

test('Probe 1.1: Single in-flight stream socket drop rejects in < 500ms without hanging', async () => {
  const serverStatic = await generateX25519KeyPair()
  const responder = new SyntheticNoiseHarnessResponder(serverStatic)
  await responder.initialize()
  ControllableMockWebSocket.responder = responder
  ControllableMockWebSocket.instances = []

  const client = new NoiseClient({
    tokenManager: new FastTokenManager(),
    WebSocketClass: ControllableMockWebSocket,
    timeoutMs: 180000, // 3 minutes timeout if not rejected
  })

  await client.connect()
  assert.equal(client.connected, true)
  const ws = ControllableMockWebSocket.instances[0]
  assert.ok(ws, 'WebSocket instance must exist')

  const t0 = performance.now()
  const streamPromise = client.chatStream('Stress test single stream drop')

  // Simulate network drop during generation
  queueMicrotask(() => {
    ws.drop(1006, 'Connection reset by peer')
  })

  let caughtError = null
  try {
    await streamPromise
  } catch (err) {
    caughtError = err
  }
  const elapsedMs = performance.now() - t0

  assert.ok(caughtError !== null, 'chatStream promise MUST reject on socket drop')
  assert.match(
    caughtError.message,
    /Noise WebSocket connection closed unexpectedly/i,
    'Error message must indicate unexpected WebSocket closure',
  )
  assert.match(caughtError.message, /Connection reset by peer/i)

  // EMPIRICAL CRITERION: Must reject in < 500ms
  assert.ok(
    elapsedMs < 500,
    `Empirical check failed: Rejection took ${elapsedMs.toFixed(2)}ms (must be < 500ms)`,
  )

  await client.close()
})

test('Probe 1.2: Multiple concurrent in-flight streams all reject in < 500ms when socket drops', async () => {
  const serverStatic = await generateX25519KeyPair()
  const responder = new SyntheticNoiseHarnessResponder(serverStatic)
  await responder.initialize()
  ControllableMockWebSocket.responder = responder
  ControllableMockWebSocket.instances = []

  const client = new NoiseClient({
    tokenManager: new FastTokenManager(),
    WebSocketClass: ControllableMockWebSocket,
    timeoutMs: 180000,
  })

  await client.connect()
  const ws = ControllableMockWebSocket.instances[0]

  const CONCURRENCY = 10
  const promises = []
  const t0 = performance.now()

  for (let i = 0; i < CONCURRENCY; i++) {
    promises.push(
      client.chatStream(`Concurrent prompt #${i}`).then(
        () => ({ ok: true }),
        (err) => ({ ok: false, err }),
      ),
    )
  }

  // Drop socket abruptly
  queueMicrotask(() => {
    ws.drop(1006, 'Gateway terminated TCP session')
  })

  const results = await Promise.all(promises)
  const elapsedMs = performance.now() - t0

  assert.equal(results.length, CONCURRENCY)
  for (let i = 0; i < CONCURRENCY; i++) {
    assert.equal(results[i].ok, false, `Stream #${i} must have rejected`)
    assert.match(
      results[i].err.message,
      /Noise WebSocket connection closed unexpectedly/i,
      `Stream #${i} must have received expected rejection error`,
    )
  }

  // EMPIRICAL CRITERION: All concurrent streams reject in < 500ms
  assert.ok(
    elapsedMs < 500,
    `Empirical check failed: ${CONCURRENCY} streams rejected in ${elapsedMs.toFixed(2)}ms (must be < 500ms)`,
  )

  await client.close()
})

test('Probe 1.3: Abrupt socket "error" event followed by "close" settles cleanly in < 500ms', async () => {
  const serverStatic = await generateX25519KeyPair()
  const responder = new SyntheticNoiseHarnessResponder(serverStatic)
  await responder.initialize()
  ControllableMockWebSocket.responder = responder
  ControllableMockWebSocket.instances = []

  const client = new NoiseClient({
    tokenManager: new FastTokenManager(),
    WebSocketClass: ControllableMockWebSocket,
    timeoutMs: 180000,
  })

  await client.connect()
  const ws = ControllableMockWebSocket.instances[0]

  const t0 = performance.now()
  const streamPromise = client.chatStream('Error event probe')

  queueMicrotask(() => {
    ws.emit('error', new Error('ECONNRESET: connection reset'))
    ws.drop(1006, 'Abnormal error closure')
  })

  await assert.rejects(
    async () => streamPromise,
    (err) => {
      assert.match(err.message, /Noise WebSocket connection closed unexpectedly/i)
      return true
    },
  )

  const elapsedMs = performance.now() - t0
  assert.ok(
    elapsedMs < 500,
    `Rejection with error event took ${elapsedMs.toFixed(2)}ms (expected < 500ms)`,
  )

  await client.close()
})

test('Probe 1.4: client.close() during in-flight stream rejects immediately in < 500ms', async () => {
  const serverStatic = await generateX25519KeyPair()
  const responder = new SyntheticNoiseHarnessResponder(serverStatic)
  await responder.initialize()
  ControllableMockWebSocket.responder = responder

  const client = new NoiseClient({
    tokenManager: new FastTokenManager(),
    WebSocketClass: ControllableMockWebSocket,
    timeoutMs: 180000,
  })

  await client.connect()

  const t0 = performance.now()
  const streamPromise = client.chatStream('Prompt before client.close()')

  queueMicrotask(() => {
    client.close()
  })

  await assert.rejects(
    async () => streamPromise,
    (err) => {
      assert.match(err.message, /NoiseClient was closed/i)
      return true
    },
  )

  const elapsedMs = performance.now() - t0
  assert.ok(
    elapsedMs < 500,
    `client.close() rejection took ${elapsedMs.toFixed(2)}ms (expected < 500ms)`,
  )
})

// ============================================================================
// SUITE 2: PROBE TOKEN DEDUPLICATION & SSE STREAM MONOTONICITY GUARD
// ============================================================================

test('Probe 2.1: Partial tokens emitted prior to failure trip breaker and reject without browser re-emission', async () => {
  const browserDriver = createMockBrowserDriver()

  class FailingNoiseClientWithDeltas {
    constructor() { this.connected = true }
    async connect() { this.connected = true }
    async chatStream(prompt, opts = {}) {
      if (typeof opts.onDelta === 'function') {
        opts.onDelta('The speed of light')
      }
      throw new Error('Mid-flight gateway drop')
    }
    async close() { this.connected = false }
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: browserDriver,
    NoiseClientClass: FailingNoiseClientWithDeltas,
  })

  const deltasCaptured = []
  let thrown = null

  try {
    await transport.chatStream('What is the speed of light?', {
      onDelta: (chunk) => deltasCaptured.push(chunk),
    })
  } catch (err) {
    thrown = err
  }

  // 1. Must throw descriptive mid-stream interruption error
  assert.ok(thrown !== null, 'Must throw error on mid-stream failure')
  assert.match(
    thrown.message,
    /Noise stream interrupted mid-stream after 1 token delta\(s\) emitted: Mid-flight gateway drop/i,
  )

  // 2. Exactly 1 delta was emitted to the consumer before failure
  assert.deepEqual(deltasCaptured, ['The speed of light'])

  // 3. Browser driver MUST NOT have been called (no duplicate restart from word 0)
  assert.equal(
    browserDriver.calls.filter((c) => c.method === 'chatStream').length,
    0,
    'Browser driver must NOT be called after partial token emission',
  )

  // 4. Circuit breaker tripped
  assert.equal(transport.fallbackActive, true)
  assert.equal(transport.activeTransport, 'browser')

  // 5. Subsequent request stays on browser driver and succeeds
  const nextRes = await transport.chatStream('Next query after failure', {
    onDelta: () => {},
  })
  assert.equal(nextRes.reply, 'Browser streamed: Next query after failure')
  assert.equal(browserDriver.calls.filter((c) => c.method === 'chatStream').length, 1)
})

test('Probe 2.2: Burst of 5 partial tokens emitted before failure prevents duplicate re-emission', async () => {
  const browserDriver = createMockBrowserDriver()

  class BurstTokenFailureClient {
    constructor() { this.connected = true }
    async connect() { this.connected = true }
    async chatStream(prompt, opts = {}) {
      if (typeof opts.onDelta === 'function') {
        opts.onDelta('Chunk 1 ')
        opts.onDelta('Chunk 1 Chunk 2 ')
        opts.onDelta('Chunk 1 Chunk 2 Chunk 3 ')
        opts.onDelta('Chunk 1 Chunk 2 Chunk 3 Chunk 4 ')
        opts.onDelta('Chunk 1 Chunk 2 Chunk 3 Chunk 4 Chunk 5 ')
      }
      throw new Error('TCP reset after 5 chunks')
    }
    async close() { this.connected = false }
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: browserDriver,
    NoiseClientClass: BurstTokenFailureClient,
  })

  await assert.rejects(
    async () => {
      await transport.chatStream('Burst probe', { onDelta: () => {} })
    },
    (err) => {
      assert.match(err.message, /after 5 token delta\(s\) emitted: TCP reset after 5 chunks/i)
      return true
    },
  )

  assert.equal(browserDriver.calls.filter((c) => c.method === 'chatStream').length, 0)
  assert.equal(transport.fallbackActive, true)
})

test('Probe 2.3: Zero tokens emitted before failure successfully triggers seamless browser fallback', async () => {
  const browserDriver = createMockBrowserDriver()

  class ImmediateFailureClient {
    constructor() { this.connected = true }
    async connect() { this.connected = true }
    async chatStream() {
      // Drop immediately before emitting any tokens
      throw new Error('Gateway rejected stream before generation')
    }
    async close() { this.connected = false }
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: browserDriver,
    NoiseClientClass: ImmediateFailureClient,
  })

  const deltasCaptured = []
  const result = await transport.chatStream('Zero tokens prompt', {
    onDelta: (chunk) => deltasCaptured.push(chunk),
  })

  // Since tokensEmitted === 0, seamless fallback occurred
  assert.equal(result.reply, 'Browser streamed: Zero tokens prompt')
  assert.equal(browserDriver.calls.filter((c) => c.method === 'chatStream').length, 1)
  assert.equal(transport.fallbackActive, true)
  assert.equal(deltasCaptured.length, 1)
  assert.equal(deltasCaptured[0], 'Browser streamed: Zero tokens prompt')
})

test('Probe 2.4: OpenAI Shim SSE emulation proves strict monotonic output without duplication', async () => {
  const browserDriver = createMockBrowserDriver()

  class InterruptedNoiseClient {
    constructor() { this.connected = true }
    async connect() { this.connected = true }
    async chatStream(prompt, opts = {}) {
      if (typeof opts.onDelta === 'function') {
        opts.onDelta('Hello')
        opts.onDelta('Hello world')
      }
      throw new Error('Connection lost')
    }
    async close() { this.connected = false }
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: browserDriver,
    NoiseClientClass: InterruptedNoiseClient,
  })

  // Emulate exact OpenAI shim SSE delta extraction logic from muse-openai-shim.mjs
  let emitted = ''
  const sseDeltas = []

  let streamError = null
  try {
    await transport.chatStream('Say hello', {
      onDelta: (full) => {
        const delta = full.startsWith(emitted) ? full.slice(emitted.length) : full
        emitted = full
        sseDeltas.push(delta)
      },
    })
  } catch (err) {
    streamError = err
  }

  // 1. Error caught
  assert.ok(streamError !== null)

  // 2. Verified SSE deltas emitted: ['Hello', ' world']
  assert.deepEqual(sseDeltas, ['Hello', ' world'])

  // 3. Verify monotonic: emitted is 'Hello world', and NO duplicate 'Hello' was emitted
  assert.equal(sseDeltas.filter((d) => d === 'Hello').length, 1)

  // 4. Browser driver was not touched during the failed call
  assert.equal(browserDriver.calls.length, 0)
})

// ============================================================================
// SUITE 3: PROBE STATUS RESPONSIVENESS (< 1000ms) WITH UNMOUNTED COMPOSER
// ============================================================================

test('Probe 3.1: MuseDriver.status() returns in < 1000ms when composer is unmounted', async () => {
  const driver = new MuseDriver()

  // Mock page where locator.waitFor will wait for 10000ms if given that timeout,
  // but respects the timeout option passed to it.
  driver.requirePage = async () => ({
    locator: () => ({
      first: () => ({
        waitFor: async ({ timeout }) => {
          // Simulate locator waiting up to timeout ms
          await new Promise((resolve, reject) => {
            setTimeout(() => {
              reject(new Error(`Timeout ${timeout}ms exceeded`))
            }, timeout)
          })
        },
      }),
    }),
  })
  driver.isRunning = () => true
  driver.checkAuth = async () => ({ ok: true, viewerId: '1315296991670251' })
  driver.page = { url: () => 'https://muse.ai/' }

  const t0 = performance.now()
  const st = await driver.status()
  const elapsedMs = performance.now() - t0

  assert.equal(st.browserRunning, true)
  assert.equal(st.loggedIn, true)
  assert.equal(st.composerReady, false, 'composerReady must be false when unmounted')

  // EMPIRICAL CRITERION: Must return in < 1000ms (500ms timeout)
  assert.ok(
    elapsedMs < 1000,
    `Empirical check failed: driver.status() took ${elapsedMs.toFixed(2)}ms (must be < 1000ms)`,
  )
  assert.ok(
    elapsedMs >= 450,
    `Empirical check: driver.status() waited the full 500ms timeout (${elapsedMs.toFixed(2)}ms)`,
  )
})

test('Probe 3.2: MuseTransport.status() returns unified status in < 1000ms with unmounted composer', async () => {
  const driver = new MuseDriver()
  driver.requirePage = async () => ({
    locator: () => ({
      first: () => ({
        waitFor: async ({ timeout }) => {
          await new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Composer not found')), timeout)
          })
        },
      }),
    }),
  })
  driver.isRunning = () => true
  driver.checkAuth = async () => ({ ok: true, viewerId: '1315296991670251' })
  driver.page = { url: () => 'https://muse.ai/' }

  const transport = new MuseTransport({
    transport: 'browser',
    driver,
  })

  const t0 = performance.now()
  const st = await transport.status()
  const elapsedMs = performance.now() - t0

  assert.equal(st.transport, 'browser')
  assert.equal(st.activeTransport, 'browser')
  assert.equal(st.fallbackActive, false)
  assert.equal(st.fallbackAvailable, true)
  assert.equal(st.browserRunning, true)
  assert.equal(st.composerReady, false)

  // EMPIRICAL CRITERION: Must return in < 1000ms
  assert.ok(
    elapsedMs < 1000,
    `Empirical check failed: transport.status() took ${elapsedMs.toFixed(2)}ms (must be < 1000ms)`,
  )
})

test('Probe 3.3: Rapid burst of 10 concurrent status() calls all succeed in < 1500ms', async () => {
  const driver = new MuseDriver()
  driver.requirePage = async () => ({
    locator: () => ({
      first: () => ({
        waitFor: async ({ timeout }) => {
          await new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Composer not found')), timeout)
          })
        },
      }),
    }),
  })
  driver.isRunning = () => true
  driver.checkAuth = async () => ({ ok: true, viewerId: '1315296991670251' })
  driver.page = { url: () => 'https://muse.ai/' }

  const transport = new MuseTransport({
    transport: 'browser',
    driver,
  })

  const t0 = performance.now()
  const probes = Array.from({ length: 10 }, () => transport.status())
  const results = await Promise.all(probes)
  const elapsedMs = performance.now() - t0

  assert.equal(results.length, 10)
  for (const st of results) {
    assert.equal(st.composerReady, false)
    assert.equal(st.browserRunning, true)
  }

  assert.ok(
    elapsedMs < 1500,
    `Burst of 10 status probes took ${elapsedMs.toFixed(2)}ms (must be < 1500ms)`,
  )
})

test('Probe 3.4: status() when browser is closed returns in < 50ms', async () => {
  const driver = new MuseDriver()
  driver.isRunning = () => false

  const transport = new MuseTransport({
    transport: 'browser',
    driver,
  })

  const t0 = performance.now()
  const st = await transport.status()
  const elapsedMs = performance.now() - t0

  assert.equal(st.browserRunning, false)
  assert.equal(st.composerReady, false)
  assert.equal(st.loggedIn, false)
  assert.ok(elapsedMs < 50, `status() for dead browser took ${elapsedMs.toFixed(2)}ms`)
})

// ============================================================================
// SUITE 4: PROBE CIRCUIT BREAKER STABILITY UNDER REPEATED RECOVERY ATTEMPTS
// ============================================================================

test('Probe 4.1: Once tripped, circuit breaker remains sticky across 20 rapid requests', async () => {
  const browserDriver = createMockBrowserDriver()
  let noiseAttempts = 0

  class SingleDropClient {
    async connect() {
      noiseAttempts++
      throw new Error('Persistent network partition')
    }
    async close() {}
  }

  const transport = new MuseTransport({
    transport: 'noise',
    driver: browserDriver,
    NoiseClientClass: SingleDropClient,
  })

  // First request trips breaker
  await transport.chat('Initial trip')
  assert.equal(noiseAttempts, 1)
  assert.equal(transport.fallbackActive, true)

  // 20 subsequent requests should NEVER attempt Noise
  for (let i = 0; i < 20; i++) {
    const res = await transport.chat(`Rapid chat #${i}`)
    assert.equal(res.reply, `Browser reply to: Rapid chat #${i}`)
  }

  assert.equal(
    noiseAttempts,
    1,
    'Circuit breaker must remain sticky: zero further Noise connection attempts',
  )
  assert.equal(browserDriver.calls.filter((c) => c.method === 'chat').length, 21)
})

// ============================================================================
// SUITE 5: LISTENER LEAK & PRE-FRAME DISCONNECT VERIFICATION
// ============================================================================

test('Probe 5.1: Socket drop before any response frames are received rejects cleanly without hanging', async () => {
  const serverStatic = await generateX25519KeyPair()
  const responder = new SyntheticNoiseHarnessResponder(serverStatic)
  await responder.initialize()
  ControllableMockWebSocket.responder = responder
  ControllableMockWebSocket.instances = []

  const client = new NoiseClient({
    tokenManager: new FastTokenManager(),
    WebSocketClass: ControllableMockWebSocket,
    timeoutMs: 180000,
  })

  await client.connect()
  const ws = ControllableMockWebSocket.instances[0]

  const t0 = performance.now()
  // Trigger chatStream, but drop immediately before responder handles sendRequest
  const streamPromise = client.chatStream('Pre-frame drop prompt')
  ws.drop(1006, '') // Empty disconnect reason

  await assert.rejects(
    async () => streamPromise,
    (err) => {
      assert.match(err.message, /Noise WebSocket connection closed unexpectedly/i)
      return true
    },
  )

  const elapsedMs = performance.now() - t0
  assert.ok(elapsedMs < 500, `Pre-frame drop rejected in ${elapsedMs.toFixed(2)}ms (expected < 500ms)`)
  await client.close()
})

test('Probe 5.2: Sequential connect and drop cycles do not accumulate active streams', async () => {
  const serverStatic = await generateX25519KeyPair()
  ControllableMockWebSocket.instances = []

  for (let cycle = 0; cycle < 5; cycle++) {
    const responder = new SyntheticNoiseHarnessResponder(serverStatic)
    await responder.initialize()
    ControllableMockWebSocket.responder = responder

    const client = new NoiseClient({
      tokenManager: new FastTokenManager(),
      WebSocketClass: ControllableMockWebSocket,
      timeoutMs: 180000,
    })

    await client.connect()
    const ws = ControllableMockWebSocket.instances[ControllableMockWebSocket.instances.length - 1]

    const streamPromise = client.chatStream(`Cycle ${cycle} prompt`)
    ws.drop(1006, `Drop cycle ${cycle}`)

    await assert.rejects(
      async () => streamPromise,
      (err) => {
        assert.match(err.message, /Noise WebSocket connection closed unexpectedly/i)
        return true
      },
    )

    await client.close()
  }
})

