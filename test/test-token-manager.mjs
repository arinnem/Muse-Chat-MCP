/**
 * test/test-token-manager.mjs
 * ------------------------------------------------------------------
 * Unit test suite for lib/noise/token-manager.mjs (Milestone 4).
 * Verifies:
 *   1. Cookie parsing, normalization, and Cookie header formatting.
 *   2. Mandatory browser security headers presence on all requests.
 *   3. Expiration calculation with 5-minute safety buffer.
 *   4. Cache hit / miss behavior and concurrent request deduplication.
 *   5. Invalidation behavior (invalidateToken).
 *   6. Error handling: AuthSessionExpiredError on missing cookies, 401, and 403.
 *   7. Standard Error on 500 / network failures.
 *   8. File loading from cookies.json and storage_state.json.
 * ------------------------------------------------------------------
 */

import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  TokenManager,
  AuthSessionExpiredError,
  parseCookieString,
  normalizeCookies,
  formatCookieHeader,
  REQUIRED_COOKIES,
  DEFAULT_USER_AGENT,
} from '../lib/noise/token-manager.mjs'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

async function runTests() {
  console.log('============================================================')
  console.log('Testing lib/noise/token-manager.mjs (Milestone 4)')
  console.log('============================================================\n')

  let passed = 0
  let failed = 0

  const test = async (name, fn) => {
    try {
      await fn()
      console.log(`[PASS] ${name}`)
      passed++
    } catch (err) {
      console.error(`[FAIL] ${name}`)
      console.error(err)
      failed++
    }
  }

  // ----------------------------------------------------------------
  // Test 1: Cookie parsing and normalization
  // ----------------------------------------------------------------
  await test('Cookie string parsing and normalization', () => {
    const raw = 'c_user=1000123; xs=abc%3Adef; datr=token_xyz; hatch_sess=sess_123'
    const parsed = parseCookieString(raw)
    assert.equal(parsed.c_user, '1000123')
    assert.equal(parsed.xs, 'abc%3Adef')
    assert.equal(parsed.datr, 'token_xyz')
    assert.equal(parsed.hatch_sess, 'sess_123')

    // Array format
    const arr = [
      { name: 'c_user', value: '1000123' },
      { name: 'hatch_gw', value: 'gw_999' },
    ]
    const normalizedArr = normalizeCookies(arr)
    assert.equal(normalizedArr.c_user, '1000123')
    assert.equal(normalizedArr.hatch_gw, 'gw_999')

    // storageState format
    const storageState = {
      cookies: [
        { name: 'hatch_sess', value: 'sess_storage' },
        { name: 'datr', value: 'datr_storage' },
      ],
      origins: [],
    }
    const normalizedStorage = normalizeCookies(storageState)
    assert.equal(normalizedStorage.hatch_sess, 'sess_storage')
    assert.equal(normalizedStorage.datr, 'datr_storage')

    // Header formatting
    const header = formatCookieHeader({
      c_user: '1000123',
      hatch_sess: 'sess_123',
    })
    assert.equal(header, 'c_user=1000123; hatch_sess=sess_123')
  })

  // ----------------------------------------------------------------
  // Test 2: Mandatory browser headers on fetch requests
  // ----------------------------------------------------------------
  await test('Mandatory browser headers presence on fetch requests', async () => {
    const capturedRequests = []

    // Simulated external HTTP network transport (prevents hitting live Meta servers offline)
    const networkFetch = async (url, init) => {
      capturedRequests.push({ url, init })
      return new Response(JSON.stringify({ ok: true, status: 'running' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    const tm = new TokenManager({
      cookies: { hatch_sess: 'test_sess', datr: 'test_datr' },
      fetch: networkFetch,
    })

    await tm.wakeVm()

    assert.equal(capturedRequests.length, 1)
    const req = capturedRequests[0]
    assert.equal(req.url, 'https://muse.ai/api/hatch/vm/wake')
    assert.equal(req.init.method, 'POST')

    const headers = req.init.headers
    assert.equal(headers.origin, 'https://muse.ai')
    assert.equal(headers.referer, 'https://muse.ai/')
    assert.equal(headers['user-agent'], DEFAULT_USER_AGENT)
    assert.equal(headers['sec-fetch-site'], 'same-origin')
    assert.equal(headers['sec-fetch-mode'], 'cors')
    assert.equal(headers['content-type'], 'application/json')
    assert.match(headers.cookie, /hatch_sess=test_sess/)
    assert.match(headers.cookie, /datr=test_datr/)
  })

  // ----------------------------------------------------------------
  // Test 3: HTTP lifecycle calls sequence and expiration calculation
  // ----------------------------------------------------------------
  await test('HTTP lifecycle calls sequence and 5-minute safety buffer', async () => {
    const calls = []

    const networkFetch = async (url, init) => {
      const u = new URL(url)
      calls.push({ pathname: u.pathname, method: init.method, body: init.body })

      if (u.pathname === '/api/hatch/vm/wake') {
        return new Response(JSON.stringify({ ok: true, status: 'running' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }

      if (u.pathname === '/api/session') {
        return new Response(
          JSON.stringify({
            status: 'assigned',
            vm_id: 'test-vm-uuid-1234',
            endpoint_url: 'wss://test-vm-uuid-1234.metaaivm.com/',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      }

      if (u.pathname === '/api/hatch/token') {
        const bodyObj = JSON.parse(init.body)
        assert.equal(bodyObj.vm_id, 'test-vm-uuid-1234')
        return new Response(
          JSON.stringify({
            ok: true,
            auth_token: 's0:mock_jwt_token',
            notary_token: 'endorsement.v1.mock_notary',
            expires_in: 86400, // 24 hours
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      }

      throw new Error(`Unexpected endpoint: ${u.pathname}`)
    }

    const tm = new TokenManager({
      cookies: 'hatch_sess=val_sess',
      fetch: networkFetch,
    })

    const before = Date.now()
    const session = await tm.ensureValidSession()
    const after = Date.now()

    // Verify lifecycle execution order
    assert.equal(calls.length, 3)
    assert.equal(calls[0].pathname, '/api/hatch/vm/wake')
    assert.equal(calls[0].method, 'POST')
    assert.equal(calls[1].pathname, '/api/session')
    assert.equal(calls[1].method, 'GET')
    assert.equal(calls[2].pathname, '/api/hatch/token')
    assert.equal(calls[2].method, 'POST')

    // Verify returned session object
    assert.equal(session.vm_id, 'test-vm-uuid-1234')
    assert.equal(session.endpoint_url, 'wss://test-vm-uuid-1234.metaaivm.com/')
    assert.equal(session.auth_token, 's0:mock_jwt_token')
    assert.equal(session.notary_token, 'endorsement.v1.mock_notary')

    // Verify 5-minute safety buffer: expiresAt = now + (86400 - 300) * 1000
    const expectedBufferMs = (86400 - 300) * 1000
    assert.ok(session.expiresAt >= before + expectedBufferMs)
    assert.ok(session.expiresAt <= after + expectedBufferMs)
  })

  // ----------------------------------------------------------------
  // Test 4: Cache hit vs cache miss behavior
  // ----------------------------------------------------------------
  await test('Cache hit avoids roundtrips; forceRefresh re-fetches', async () => {
    let fetchCount = 0

    const networkFetch = async (url) => {
      fetchCount++
      const u = new URL(url)
      if (u.pathname === '/api/hatch/vm/wake') {
        return new Response(JSON.stringify({ ok: true }), { status: 200 })
      }
      if (u.pathname === '/api/session') {
        return new Response(JSON.stringify({ vm_id: 'vm-cache-1', endpoint_url: 'wss://vm1' }), {
          status: 200,
        })
      }
      if (u.pathname === '/api/hatch/token') {
        return new Response(
          JSON.stringify({ auth_token: 'auth-cache-1', notary_token: 'notary-1', expires_in: 3600 }),
          { status: 200 }
        )
      }
      throw new Error(`Unexpected: ${url}`)
    }

    const tm = new TokenManager({
      cookies: { hatch_sess: 'cache_sess' },
      fetch: networkFetch,
    })

    // 1st call -> fetches 3 endpoints
    const s1 = await tm.ensureValidSession()
    assert.equal(fetchCount, 3)
    assert.equal(s1.vm_id, 'vm-cache-1')
    assert.ok(tm.isSessionValid())

    // 2nd call -> cache hit (zero additional fetches)
    const s2 = await tm.ensureValidSession()
    assert.equal(fetchCount, 3)
    assert.equal(s2, s1) // identical reference

    // 3rd call with forceRefresh=true -> re-fetches all 3 endpoints
    const s3 = await tm.ensureValidSession(true)
    assert.equal(fetchCount, 6)
    assert.equal(s3.vm_id, 'vm-cache-1')
  })

  // ----------------------------------------------------------------
  // Test 5: Concurrent request deduplication
  // ----------------------------------------------------------------
  await test('Concurrent ensureValidSession() calls deduplicate to 1 fetch cycle', async () => {
    let fetchCount = 0

    const networkFetch = async (url) => {
      fetchCount++
      await new Promise((r) => setTimeout(r, 20))
      const u = new URL(url)
      if (u.pathname === '/api/hatch/vm/wake') {
        return new Response(JSON.stringify({ ok: true }), { status: 200 })
      }
      if (u.pathname === '/api/session') {
        return new Response(JSON.stringify({ vm_id: 'vm-concurrent', endpoint_url: 'wss://vm' }), {
          status: 200,
        })
      }
      if (u.pathname === '/api/hatch/token') {
        return new Response(
          JSON.stringify({ auth_token: 'auth-concurrent', notary_token: 'notary', expires_in: 3600 }),
          { status: 200 }
        )
      }
      throw new Error(url)
    }

    const tm = new TokenManager({
      cookies: { hatch_sess: 'concurrent_sess' },
      fetch: networkFetch,
    })

    // Launch 5 concurrent calls
    const results = await Promise.all([
      tm.ensureValidSession(),
      tm.ensureValidSession(),
      tm.ensureValidSession(),
      tm.ensureValidSession(),
      tm.ensureValidSession(),
    ])

    // Exactly 3 HTTP calls were made (1 cycle)
    assert.equal(fetchCount, 3)
    for (const r of results) {
      assert.equal(r.vm_id, 'vm-concurrent')
      assert.equal(r.auth_token, 'auth-concurrent')
    }
  })

  // ----------------------------------------------------------------
  // Test 6: Invalidation behavior (invalidateToken)
  // ----------------------------------------------------------------
  await test('invalidateToken() clears cache and forces fresh fetch', async () => {
    let fetchCount = 0

    const networkFetch = async (url) => {
      fetchCount++
      const u = new URL(url)
      if (u.pathname === '/api/hatch/vm/wake') return new Response('{}', { status: 200 })
      if (u.pathname === '/api/session') {
        return new Response(JSON.stringify({ vm_id: 'vm-inval', endpoint_url: 'wss://vm' }), {
          status: 200,
        })
      }
      if (u.pathname === '/api/hatch/token') {
        return new Response(
          JSON.stringify({ auth_token: 'tok-inval', notary_token: '', expires_in: 3600 }),
          { status: 200 }
        )
      }
      throw new Error(url)
    }

    const tm = new TokenManager({
      cookies: { hatch_sess: 'inval_sess' },
      fetch: networkFetch,
    })

    await tm.ensureValidSession()
    assert.equal(fetchCount, 3)
    assert.ok(tm.isSessionValid())

    // Invalidate
    tm.invalidateToken()
    assert.equal(tm.getCachedSession(), null)
    assert.equal(tm.isSessionValid(), false)

    // Next call must re-fetch
    await tm.ensureValidSession()
    assert.equal(fetchCount, 6)
  })

  // ----------------------------------------------------------------
  // Test 7: Error handling on missing cookies
  // ----------------------------------------------------------------
  await test('Missing cookies throws AuthSessionExpiredError', async () => {
    // Provide a dummy profile directory that has no cookies
    const tempDir = path.join(__dirname, '.temp-no-cookies-' + Date.now())
    fs.mkdirSync(tempDir, { recursive: true })

    try {
      const tm = new TokenManager({
        profileDir: tempDir,
        storageDir: tempDir,
      })

      await assert.rejects(
        async () => {
          await tm.ensureValidSession()
        },
        (err) => {
          assert.ok(err instanceof AuthSessionExpiredError)
          assert.match(err.message, /No valid session cookies found/)
          return true
        }
      )
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true })
    }
  })

  // ----------------------------------------------------------------
  // Test 8: Error handling on HTTP 401 & 403 Forbidden
  // ----------------------------------------------------------------
  await test('HTTP 401 and 403 endpoints throw AuthSessionExpiredError', async () => {
    // Test 401
    const fetch401 = async () =>
      new Response(JSON.stringify({ error: 'Unauthorized', code: 401 }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      })

    const tm401 = new TokenManager({
      cookies: { hatch_sess: 'expired' },
      fetch: fetch401,
    })

    await assert.rejects(
      async () => {
        await tm401.wakeVm()
      },
      (err) => {
        assert.ok(err instanceof AuthSessionExpiredError)
        assert.equal(err.status, 401)
        assert.match(err.message, /expired or forbidden/)
        return true
      }
    )

    // Test 403
    const fetch403 = async () =>
      new Response(JSON.stringify({ error: 'Forbidden', message: 'CSRF token missing' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      })

    const tm403 = new TokenManager({
      cookies: { hatch_sess: 'forbidden' },
      fetch: fetch403,
    })

    await assert.rejects(
      async () => {
        await tm403.getSession()
      },
      (err) => {
        assert.ok(err instanceof AuthSessionExpiredError)
        assert.equal(err.status, 403)
        assert.match(err.message, /expired or forbidden/)
        return true
      }
    )
  })

  // ----------------------------------------------------------------
  // Test 9: HTTP 500 throws standard Error
  // ----------------------------------------------------------------
  await test('HTTP 500 throws standard Error with status and details', async () => {
    const fetch500 = async () =>
      new Response('Internal Server Error in cloud VM provisioner', {
        status: 500,
        statusText: 'Internal Server Error',
      })

    const tm500 = new TokenManager({
      cookies: { hatch_sess: 'valid_sess' },
      fetch: fetch500,
    })

    await assert.rejects(
      async () => {
        await tm500.wakeVm()
      },
      (err) => {
        assert.ok(!(err instanceof AuthSessionExpiredError))
        assert.match(err.message, /failed with HTTP 500/)
        return true
      }
    )
  })

  // ----------------------------------------------------------------
  // Test 10: File loading from cookies.json and saveCookies
  // ----------------------------------------------------------------
  await test('File discovery from cookies.json and saveCookies helper', async () => {
    const tempDir = path.join(__dirname, '.temp-cookies-test-' + Date.now())
    fs.mkdirSync(tempDir, { recursive: true })

    try {
      const cookiesFile = path.join(tempDir, 'cookies.json')
      fs.writeFileSync(
        cookiesFile,
        JSON.stringify({
          c_user: '1000987',
          xs: 'xs_secret_token',
          datr: 'datr_token_value',
          hatch_sess: 'hatch_sess_value',
        }),
        'utf-8'
      )

      const tm = new TokenManager({
        profileDir: tempDir,
        storageDir: tempDir,
      })

      const cookies = await tm.loadCookies()
      assert.equal(cookies.c_user, '1000987')
      assert.equal(cookies.xs, 'xs_secret_token')
      assert.equal(cookies.datr, 'datr_token_value')
      assert.equal(cookies.hatch_sess, 'hatch_sess_value')

      const header = await tm.getCookieHeader()
      assert.match(header, /c_user=1000987/)
      assert.match(header, /hatch_sess=hatch_sess_value/)

      // Test saveCookies
      await tm.saveCookies({ hatch_gw: 'gw_updated' }, path.join(tempDir, 'saved.json'))
      const savedContent = JSON.parse(
        fs.readFileSync(path.join(tempDir, 'saved.json'), 'utf-8')
      )
      assert.equal(savedContent.hatch_gw, 'gw_updated')
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true })
    }
  })

  // ----------------------------------------------------------------
  // Summary
  // ----------------------------------------------------------------
  console.log('\n============================================================')
  console.log(`Test Results: ${passed} passed, ${failed} failed`)
  console.log('============================================================')

  if (failed > 0) {
    process.exit(1)
  }
}

runTests().catch((err) => {
  console.error('Fatal test runner error:', err)
  process.exit(1)
})
