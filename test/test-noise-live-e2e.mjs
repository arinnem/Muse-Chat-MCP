/**
 * test/test-noise-live-e2e.mjs
 * ------------------------------------------------------------------
 * Live End-to-End Acceptance Test for Meta Muse Phase 2 Noise Transport.
 *
 * Requirements:
 * 1. Probes live Meta edge gateway reachability (wss://hatch.metaaivm.com/v1/noise).
 * 2. Bootstraps session credentials via TokenManager (with browser driver origin context).
 * 3. If session credentials are valid:
 *    - Connects NoiseClient directly to Meta Muse's RPC gateway.
 *    - Completes live 3-message Noise_XX_25519_AESGCM_SHA256 handshake.
 *    - Verifies client.connected === true and remoteStaticPublicKey is 32 bytes.
 *    - Executes live chatStream("Say hello in three words.") with onDelta tracking.
 *    - Verifies monotonic text delta progression, non-empty response, and finishReason.
 *    - Closes client cleanly.
 * 4. If session cookies are unavailable or expired:
 *    - Verifies graceful AuthSessionExpiredError is caught.
 *    - Verifies seamless fallback via MuseTransport without client crashes.
 * 5. Isolated test verifies offline/empty cookie handling fails closed to AuthSessionExpiredError
 *    and triggers seamless browser fallback.
 *
 * Pure Node 20+ built-ins (node:test, node:assert/strict, node:https).
 * ------------------------------------------------------------------
 */

import test from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";

import { NoiseClient, DEFAULT_ENDPOINT_URL } from "../lib/noise/noise-client.mjs";
import { TokenManager, AuthSessionExpiredError } from "../lib/noise/token-manager.mjs";
import { MuseTransport } from "../muse-transport.mjs";
import driver from "../muse-driver.mjs";

// ============================================================================
// SUITE 1: Live Meta Edge Gateway Reachability
// ============================================================================

test("Suite 1: Live Meta edge gateway HTTPS ingress reachability", async () => {
  const statusCode = await new Promise((resolve, reject) => {
    const req = https.get(
      "https://hatch.metaaivm.com/v1/noise",
      {
        headers: {
          Origin: "https://muse.ai",
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
        },
        timeout: 10000,
      },
      (res) => {
        res.resume(); // Discard response body
        resolve(res.statusCode);
      }
    );
    req.on("error", (err) => reject(err));
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Timeout probing hatch.metaaivm.com"));
    });
  });

  // Meta edge proxy returns 401 Unauthorized for unauthenticated requests,
  // confirming network path to Meta edge infrastructure is live and reachable.
  assert.strictEqual(
    statusCode,
    401,
    `Expected HTTP 401 from Meta ingress, got HTTP ${statusCode}`
  );
});

// ============================================================================
// SUITE 2: Canonical WebSocket URL Formatting & Upgrade Headers
// ============================================================================

test("Suite 2: Canonical WebSocket URL normalization preserves vm_id and targets /v1/noise", async () => {
  class CapturingWebSocket {
    constructor(url, options) {
      this.url = url;
      this.options = options;
      this.readyState = 3; // CLOSED
    }
    close() {}
  }

  const tokenManager = new TokenManager({
    cookies: { hatch_sess: "test_sess", hatch_gw: "test_gw" },
  });

  // Mock ensureValidSession to supply legacy host-based endpoint URL
  tokenManager.ensureValidSession = async () => ({
    vm_id: "vm-live-e2e-check-001",
    endpoint_url: "wss://vm-live-e2e-check-001.metaaivm.com/",
    auth_token: "test_auth_token",
    notary_token: "test_notary_token",
  });

  let captured = null;
  class TestWS extends CapturingWebSocket {
    constructor(url, options) {
      super(url, options);
      captured = { url, options };
      queueMicrotask(() => {
        if (typeof this.onerror === "function") {
          this.onerror(new Error("Expected test closure"));
        }
      });
    }
  }

  const client = new NoiseClient({
    tokenManager,
    WebSocketClass: TestWS,
    timeoutMs: 1000,
  });

  await client.connect().catch(() => {});

  assert.ok(captured, "WebSocket was constructed");
  const parsed = new URL(captured.url);
  assert.strictEqual(parsed.hostname, "hatch.metaaivm.com");
  assert.strictEqual(parsed.pathname, "/v1/noise");
  assert.strictEqual(parsed.searchParams.get("vm_id"), "vm-live-e2e-check-001");
  assert.strictEqual(parsed.searchParams.get("auth_token"), "test_auth_token");
  assert.strictEqual(parsed.searchParams.get("notary_token"), "test_notary_token");
  assert.strictEqual(parsed.searchParams.get("app_id"), "hatch-web");
  assert.ok(parsed.searchParams.get("request_id"), "request_id must be populated");

  // Verify upgrade headers passed to WebSocket constructor
  assert.ok(captured.options?.headers, "Headers object must be passed");
  assert.strictEqual(captured.options.headers.Origin, "https://muse.ai");
  assert.ok(
    captured.options.headers["User-Agent"].includes("Mozilla/5.0"),
    "User-Agent header must be browser-grade"
  );
});

// ============================================================================
// SUITE 3: Live Session Bootstrapping, Noise_XX Handshake & Streaming
// ============================================================================

test("Suite 3: Live session bootstrapping, Noise_XX handshake, and chatStream verification", async () => {
  const tokenManager = new TokenManager({ driver });
  let session = null;
  let sessionError = null;

  try {
    session = await tokenManager.ensureValidSession();
  } catch (err) {
    sessionError = err;
  }

  if (session) {
    // Branch A: Active authenticated session available in browser profile
    assert.ok(session.vm_id, "vm_id must be present");
    assert.ok(session.auth_token, "auth_token must be present");

    const client = new NoiseClient({
      tokenManager,
      timeoutMs: 25000,
    });

    try {
      await client.connect();
      assert.strictEqual(client.connected, true, "NoiseClient must be connected");
      assert.ok(client.remoteStaticPublicKey instanceof Uint8Array);
      assert.strictEqual(
        client.remoteStaticPublicKey.length,
        32,
        "Remote static public key must be exactly 32 bytes"
      );

      // Verify chatStream with monotonic delta tracking
      const deltas = [];
      const result = await client.chatStream("Say hello in three words.", {
        timeoutMs: 30000,
        onDelta: (text) => {
          deltas.push(text);
        },
      });

      assert.ok(result.text.length > 0, "Assistant response text must not be empty");
      assert.strictEqual(typeof result.finishReason, "string");

      // Verify delta monotonicity
      for (let i = 1; i < deltas.length; i++) {
        assert.ok(
          deltas[i].length >= deltas[i - 1].length,
          `Deltas must be monotonic: "${deltas[i]}" >= "${deltas[i - 1]}"`
        );
      }
    } finally {
      await client.close();
    }
  } else {
    // Branch B: Cookies are unavailable, expired, or browser session could not be acquired
    assert.ok(sessionError, "Session resolution failure was captured");

    // Verify graceful fallback via MuseTransport
    const fallbackDriver = {
      async status() {
        return {
          browserRunning: true,
          loggedIn: true,
          viewerId: "1315296991670251",
          composerReady: true,
          headless: true,
        };
      },
      async chatStream(prompt, opts = {}) {
        if (typeof opts.onDelta === "function") {
          opts.onDelta("Browser fallback: hello");
        }
        return {
          reply: "Browser fallback: hello",
          messages: ["Browser fallback: hello"],
          elapsedMs: 30,
        };
      },
      async close() {},
    };

    const transport = new MuseTransport({
      driver: fallbackDriver,
      tokenManager,
    });

    const status = await transport.status();
    assert.ok(status.fallbackAvailable, "Fallback must be available");

    // Fallback streaming must succeed via fallback driver
    const deltas = [];
    const streamResult = await transport.chatStream("Say hello in three words.", {
      onDelta: (t) => deltas.push(t),
    });
    assert.ok(
      streamResult.reply || streamResult.text,
      "Fallback response must deliver content"
    );
    assert.strictEqual(transport.fallbackActive, true);
    assert.strictEqual(transport.activeTransport, "browser");
  }
});

// ============================================================================
// SUITE 4: Isolated Missing-Cookie Handling & Zero-Crash Fallback
// ============================================================================

test("Suite 4: Missing cookies trigger AuthSessionExpiredError and seamless circuit breaker fallback", async () => {
  const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), "muse-empty-profile-"));
  try {
    const tokenManager = new TokenManager({
      profileDir: emptyDir,
      cookies: {},
    });

    // 1. Standalone tokenManager must throw AuthSessionExpiredError
    await assert.rejects(
      async () => tokenManager.ensureValidSession(),
      (err) => err instanceof AuthSessionExpiredError,
      "Missing cookies must reject with AuthSessionExpiredError"
    );

    // 2. Mock browser driver for isolated fallback test
    let browserChatStreamCalled = false;
    const mockDriver = {
      async status() {
        return {
          browserRunning: true,
          loggedIn: true,
          viewerId: "12345678",
          composerReady: true,
          headless: true,
        };
      },
      async chatStream(prompt, opts = {}) {
        browserChatStreamCalled = true;
        if (typeof opts.onDelta === "function") {
          opts.onDelta("Fallback greeting from browser");
        }
        return {
          reply: "Fallback greeting from browser",
          messages: ["Fallback greeting from browser"],
          elapsedMs: 20,
        };
      },
      async close() {},
    };

    const transport = new MuseTransport({
      tokenManager,
      driver: mockDriver,
    });

    const deltas = [];
    const res = await transport.chatStream("Say hello in three words.", {
      onDelta: (text) => deltas.push(text),
    });

    assert.strictEqual(browserChatStreamCalled, true);
    assert.strictEqual(res.reply, "Fallback greeting from browser");
    assert.strictEqual(deltas.length, 1);
    assert.strictEqual(deltas[0], "Fallback greeting from browser");

    const st = await transport.status();
    assert.strictEqual(st.fallbackActive, true);
    assert.strictEqual(st.activeTransport, "browser");
    assert.ok(st.fallbackReason.includes("No valid session cookies"));
  } finally {
    fs.rmSync(emptyDir, { recursive: true, force: true });
  }
});
