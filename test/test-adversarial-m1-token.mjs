/**
 * test/test-adversarial-m1-token.mjs
 * ------------------------------------------------------------------
 * Adversarial Stress Test Suite for Milestone 1:
 * Live Browser Session Bootstrapping & Token Resolution.
 *
 * Authored by: challenger_m1_1 (Empirical Challenger)
 * Probing:
 *   1. Extreme Concurrency: 20 concurrent ensureValidSession() calls, deduplication,
 *      concurrency during failures, and post-failure self-healing recovery.
 *   2. Session Expiration & Invalidation: Time advancement past expiration buffer,
 *      cache bypass, manual invalidation, and edge-case lifetimes (< 300s).
 *   3. Malformed Responses & Non-200 HTTP codes: 401/403 typed errors vs 500/502
 *      untyped errors, missing fields, corrupted JSON, driver crashes, and non-fatal
 *      cookie synchronization failures.
 * ------------------------------------------------------------------
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  TokenManager,
  AuthSessionExpiredError,
} from '../lib/noise/token-manager.mjs'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

test('Milestone 1 Adversarial Suite: TokenManager Browser-Backed Session Resolution', async (t) => {

  // ================================================================
  // 1. CONCURRENCY STRESS PROBES
  // ================================================================
  await t.test('Concurrency Probe 1: 20 concurrent ensureValidSession() calls execute exactly 1 browser resolution', async () => {
    let evaluateCalls = 0
    let requirePageCalls = 0
    let gotoAppCalls = 0

    const mockDriver = {
      async requirePage() {
        requirePageCalls++
        return {
          async evaluate(fn) {
            evaluateCalls++
            // Simulate realistic in-browser network latency (50ms)
            await new Promise((resolve) => setTimeout(resolve, 50))
            return {
              vm_id: 'stress-vm-concurrent-20',
              endpoint_url: 'wss://stress-vm-concurrent-20.metaaivm.com/',
              auth_token: 'auth-jwt-stress-token-9999',
              notary_token: 'notary-token-stress-8888',
              expires_in: 86400,
            }
          },
        }
      },
      async gotoApp() {
        gotoAppCalls++
      },
    }

    const tm = new TokenManager({ driver: mockDriver })

    // Dispatch 20 concurrent calls
    const promises = Array.from({ length: 20 }, (_, i) => tm.ensureValidSession())
    const results = await Promise.all(promises)

    assert.equal(results.length, 20, 'All 20 calls must resolve')
    assert.equal(evaluateCalls, 1, 'Exactly 1 evaluate call must occur across 20 concurrent callers')
    assert.equal(requirePageCalls, 1, 'Exactly 1 requirePage call must occur')
    assert.equal(gotoAppCalls, 1, 'Exactly 1 gotoApp call must occur')

    // Verify all 20 returned promises yield the exact same session object reference
    const first = results[0]
    for (let i = 1; i < results.length; i++) {
      assert.strictEqual(
        results[i],
        first,
        `Result at index ${i} must be identical reference to result at index 0`
      )
    }

    assert.equal(first.vm_id, 'stress-vm-concurrent-20')
    assert.equal(first.auth_token, 'auth-jwt-stress-token-9999')
    assert.ok(first.expiresAt > Date.now(), 'Token must have a valid future expiration timestamp')
  })

  await t.test('Concurrency Probe 2: 20 concurrent calls during failure reject uniformly and self-heal cleanly', async () => {
    let evaluateAttempts = 0
    let shouldFail = true

    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            evaluateAttempts++
            await new Promise((resolve) => setTimeout(resolve, 30))
            if (shouldFail) {
              throw new Error('Simulated transient network drop during in-page evaluate')
            }
            return {
              vm_id: 'recovered-vm',
              endpoint_url: 'wss://recovered-vm.metaaivm.com/',
              auth_token: 'recovered-auth-token',
              notary_token: 'recovered-notary',
              expires_in: 3600,
            }
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })

    // Step A: 20 concurrent callers during failure
    const failingPromises = Array.from({ length: 20 }, () => tm.ensureValidSession())
    const settled = await Promise.allSettled(failingPromises)

    assert.equal(settled.length, 20)
    for (let i = 0; i < settled.length; i++) {
      assert.equal(settled[i].status, 'rejected', `Call ${i} must reject`)
      assert.match(settled[i].reason.message, /Simulated transient network drop/)
    }
    assert.equal(evaluateAttempts, 1, 'Only 1 attempt executed for the failed deduplicated batch')
    assert.equal(tm.getCachedSession(), null, 'Cached session must remain null after failure')

    // Step B: Self-healing recovery — subsequent call must NOT return stale rejected promise
    shouldFail = false
    const recovered = await tm.ensureValidSession()
    assert.equal(evaluateAttempts, 2, 'Next call must initiate a fresh evaluation')
    assert.equal(recovered.vm_id, 'recovered-vm')
    assert.equal(recovered.auth_token, 'recovered-auth-token')
  })

  // ================================================================
  // 2. SESSION EXPIRATION & INVALIDATION PROBES
  // ================================================================
  await t.test('Expiration Probe 1: Time advance past expiration triggers fresh acquisition', async () => {
    let evaluateCount = 0
    let tokenSeq = 1

    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            evaluateCount++
            return {
              vm_id: `vm-seq-${tokenSeq}`,
              endpoint_url: `wss://vm-seq-${tokenSeq}.metaaivm.com/`,
              auth_token: `token-seq-${tokenSeq++}`,
              notary_token: 'notary-test',
              expires_in: 310, // 310 seconds -> buffer is 300s -> lifetime is 10s
            }
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })

    // Initial session acquisition
    const origNow = Date.now
    let mockTime = 1_000_000_000_000
    Date.now = () => mockTime

    try {
      const s1 = await tm.ensureValidSession()
      assert.equal(evaluateCount, 1)
      assert.equal(s1.auth_token, 'token-seq-1')
      assert.equal(s1.expiresAt, mockTime + (310 - 300) * 1000) // mockTime + 10_000ms
      assert.equal(tm.isSessionValid(), true)

      // Time advances 5 seconds (still within lifetime)
      mockTime += 5_000
      assert.equal(tm.isSessionValid(), true)
      const s1Cached = await tm.ensureValidSession()
      assert.strictEqual(s1Cached, s1, 'Must return cached session when not expired')
      assert.equal(evaluateCount, 1, 'No evaluate should run on cache hit')

      // Time advances past expiration (advance 6 more seconds, total 11s > 10s)
      mockTime += 6_000
      assert.equal(tm.isSessionValid(), false, 'Session must report invalid after expiration')

      // Next call must trigger a fresh resolution
      const s2 = await tm.ensureValidSession()
      assert.equal(evaluateCount, 2, 'Fresh evaluate must execute after expiration')
      assert.equal(s2.auth_token, 'token-seq-2')
      assert.notStrictEqual(s2, s1)
      assert.equal(tm.isSessionValid(), true)
    } finally {
      Date.now = origNow
    }
  })

  await t.test('Expiration Probe 2: invalidateToken() wipes cache immediately', async () => {
    let evaluateCount = 0

    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            evaluateCount++
            return {
              vm_id: 'vm-invalidate-test',
              endpoint_url: 'wss://vm-invalidate-test.metaaivm.com/',
              auth_token: `auth-token-eval-${evaluateCount}`,
              notary_token: 'notary-test',
              expires_in: 86400,
            }
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })
    const s1 = await tm.ensureValidSession()
    assert.equal(evaluateCount, 1)
    assert.ok(tm.isSessionValid())
    assert.ok(tm.getCachedSession() !== null)

    // Invalidate
    tm.invalidateToken()
    assert.equal(tm.getCachedSession(), null)
    assert.equal(tm.isSessionValid(), false)

    // Re-acquire
    const s2 = await tm.ensureValidSession()
    assert.equal(evaluateCount, 2)
    assert.equal(s2.auth_token, 'auth-token-eval-2')
  })

  await t.test('Expiration Probe 3: Short lifetime (< 300s safety buffer) clamps cleanly without negative timestamp or NaN', async () => {
    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            return {
              vm_id: 'vm-short-lived',
              endpoint_url: 'wss://vm-short-lived',
              auth_token: 'short-auth-token',
              notary_token: 'notary',
              expires_in: 60, // 60s < 300s buffer
            }
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })
    const before = Date.now()
    const session = await tm.ensureValidSession()
    const after = Date.now()

    // Math.max(0, 60*1000 - 300000) === 0, so expiresAt = Date.now()
    assert.ok(!Number.isNaN(session.expiresAt), 'expiresAt must not be NaN')
    assert.ok(session.expiresAt >= before && session.expiresAt <= after)
  })

  // ================================================================
  // 3. MALFORMED RESPONSES & NON-200 HTTP CODES
  // ================================================================
  await t.test('Malformed Response Probe 1: In-page 401 Unauthorized converts to AuthSessionExpiredError with status 401', async () => {
    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            throw new Error('GET /api/session failed with HTTP 401: {"error":"Unauthorized","message":"Login required"}')
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })

    await assert.rejects(
      async () => tm.ensureValidSession(),
      (err) => {
        assert.ok(err instanceof AuthSessionExpiredError, 'Must be instance of AuthSessionExpiredError')
        assert.equal(err.name, 'AuthSessionExpiredError')
        assert.equal(err.status, 401, 'Status code must be 401')
        assert.match(err.message, /Browser session resolution failed/)
        return true
      }
    )
  })

  await t.test('Malformed Response Probe 2: In-page 403 Forbidden converts to AuthSessionExpiredError with status 403', async () => {
    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            throw new Error('POST /api/hatch/vm/wake failed with HTTP 403: {"error":"Forbidden","message":"Session token expired"}')
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })

    await assert.rejects(
      async () => tm.ensureValidSession(),
      (err) => {
        assert.ok(err instanceof AuthSessionExpiredError, 'Must be instance of AuthSessionExpiredError')
        assert.equal(err.name, 'AuthSessionExpiredError')
        assert.equal(err.status, 403, 'Status code must be 403')
        assert.match(err.message, /Browser session resolution failed/)
        return true
      }
    )
  })

  await t.test('Malformed Response Probe 3: In-page 500 Internal Server Error rejects with standard Error (NOT AuthSessionExpiredError)', async () => {
    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            throw new Error('GET /api/session failed with HTTP 500: {"error":"InternalServerError"}')
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })

    await assert.rejects(
      async () => tm.ensureValidSession(),
      (err) => {
        assert.ok(!(err instanceof AuthSessionExpiredError), '500 must NOT be typed as AuthSessionExpiredError')
        assert.equal(err.name, 'Error')
        assert.match(err.message, /HTTP 500/)
        return true
      }
    )
  })

  await t.test('Malformed Response Probe 4: In-page 502/503 Gateway Error rejects with standard Error', async () => {
    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            throw new Error('POST /api/hatch/token failed with HTTP 503: Service Unavailable')
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })

    await assert.rejects(
      async () => tm.ensureValidSession(),
      (err) => {
        assert.ok(!(err instanceof AuthSessionExpiredError))
        assert.match(err.message, /HTTP 503/)
        return true
      }
    )
  })

  await t.test('Malformed Response Probe 5: Malformed JSON / SyntaxError during in-page evaluation throws standard Error', async () => {
    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            throw new SyntaxError('Unexpected token < in JSON at position 0')
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })

    await assert.rejects(
      async () => tm.ensureValidSession(),
      (err) => {
        assert.ok(!(err instanceof AuthSessionExpiredError))
        assert.equal(err.name, 'SyntaxError')
        assert.match(err.message, /Unexpected token < in JSON/)
        return true
      }
    )
  })

  await t.test('Malformed Response Probe 6: Missing vm_id from session response is rejected', async () => {
    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            // Evaluator code logic checks vm_id or vms[0].id
            throw new Error('Invalid session response: missing vm_id. Response: {"status":"empty"}')
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })

    await assert.rejects(
      async () => tm.ensureValidSession(),
      (err) => {
        assert.ok(!(err instanceof AuthSessionExpiredError))
        assert.match(err.message, /missing vm_id/)
        return true
      }
    )
  })

  await t.test('Malformed Response Probe 7: Missing auth_token from token response is rejected', async () => {
    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            throw new Error('Invalid token response: missing auth_token. Response: {"ok":true,"notary_token":"n1"}')
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })

    await assert.rejects(
      async () => tm.ensureValidSession(),
      (err) => {
        assert.ok(!(err instanceof AuthSessionExpiredError))
        assert.match(err.message, /missing auth_token/)
        return true
      }
    )
  })

  await t.test('Malformed Response Probe 8: requirePage() throws driver crash error', async () => {
    const mockDriver = {
      async requirePage() {
        throw new Error('Target page destroyed / browser disconnected')
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })

    await assert.rejects(
      async () => tm.ensureValidSession(),
      (err) => {
        assert.ok(!(err instanceof AuthSessionExpiredError))
        assert.match(err.message, /Target page destroyed/)
        return true
      }
    )
  })

  await t.test('Malformed Response Probe 9: gotoApp() throws navigation timeout', async () => {
    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            return { vm_id: 'vm1' }
          },
        }
      },
      async gotoApp() {
        throw new Error('page.goto: Timeout 30000ms exceeded')
      },
    }

    const tm = new TokenManager({ driver: mockDriver })

    await assert.rejects(
      async () => tm.ensureValidSession(),
      (err) => {
        assert.ok(!(err instanceof AuthSessionExpiredError))
        assert.match(err.message, /Timeout 30000ms exceeded/)
        return true
      }
    )
  })

  await t.test('Malformed Response Probe 10: In-page Execution context destroyed is caught and thrown cleanly', async () => {
    const mockDriver = {
      async requirePage() {
        return {
          async evaluate() {
            throw new Error('Execution context was destroyed, most likely because of a navigation.')
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })

    await assert.rejects(
      async () => tm.ensureValidSession(),
      (err) => {
        assert.match(err.message, /Execution context was destroyed/)
        return true
      }
    )
  })

  // ================================================================
  // 4. COOKIE SYNCHRONIZATION ADVERSARIAL TOLERANCE
  // ================================================================
  await t.test('Cookie Sync Probe 1: Failure during driver.ctx.cookies() is non-fatal', async () => {
    const tempDir = path.join(__dirname, '.temp-cookie-fail-' + Date.now())
    fs.mkdirSync(tempDir, { recursive: true })

    try {
      const mockDriver = {
        ctx: {
          async cookies() {
            throw new Error('Target closed while reading cookies')
          },
        },
        async requirePage() {
          return {
            async evaluate() {
              return {
                vm_id: 'vm-resilient',
                endpoint_url: 'wss://vm-resilient',
                auth_token: 'token-resilient',
                notary_token: 'notary-resilient',
                expires_in: 3600,
              }
            },
          }
        },
        async gotoApp() {},
      }

      const tm = new TokenManager({
        driver: mockDriver,
        profileDir: tempDir,
        storageDir: tempDir,
      })

      // Must NOT throw even though cookie reading threw
      const session = await tm.ensureValidSession()
      assert.equal(session.vm_id, 'vm-resilient')
      assert.equal(session.auth_token, 'token-resilient')
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true })
    }
  })

  await t.test('Cookie Sync Probe 2: driver.ctx missing or null does not throw', async () => {
    const mockDriver = {
      ctx: null, // No ctx
      async requirePage() {
        return {
          async evaluate() {
            return {
              vm_id: 'vm-no-ctx',
              endpoint_url: 'wss://vm-no-ctx',
              auth_token: 'token-no-ctx',
              notary_token: 'notary-no-ctx',
              expires_in: 3600,
            }
          },
        }
      },
      async gotoApp() {},
    }

    const tm = new TokenManager({ driver: mockDriver })
    const session = await tm.ensureValidSession()
    assert.equal(session.vm_id, 'vm-no-ctx')
  })
})
