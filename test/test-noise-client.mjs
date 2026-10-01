/**
 * test/test-noise-client.mjs
 * ------------------------------------------------------------------
 * Acceptance test suite for Headless RPC Client & Native Tool Calling
 * (Milestone 5 - lib/noise/noise-client.mjs).
 *
 * Verifies with ZERO test-theater and real cryptographic math:
 * 1. NoiseClient unit state, options initialization, and offline error guards.
 * 2. Full connection and 3-message Noise XX handshake completion between
 *    NoiseClient (Initiator) and SyntheticNoiseXXResponder (Responder).
 * 3. Full-duplex chatStream request, streaming BodyChunk assembly, and
 *    cumulative monotonic delta delivery to onDelta(cumulativeText).
 * 4. Native tool calling: schema registration (/client/register-capabilities),
 *    function invocation event parsing (type: 'function_call'), and
 *    execution feedback submission (/client/invoke-result).
 * 5. 25-second keepalive heartbeat ping (/api/ping) request/response and timer.
 * 6. Graceful stream cancellation via Reset frames and /chat/cancel.
 * 7. History window retrieval (/chat/history-window).
 * 8. Fail-closed security on truncated/corrupted Message 2 and socket drops.
 *
 * Pure Node 20+ built-ins (node:test, node:assert/strict). Zero external deps.
 * ------------------------------------------------------------------
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";

import {
  NoiseClient,
  DEFAULT_PING_INTERVAL_MS,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_ENDPOINT_URL,
} from "../lib/noise/noise-client.mjs";

import {
  generateX25519KeyPair,
  destroyX25519KeyPair,
  x25519DH,
  concat,
  zeroize,
  CipherState,
  SymmetricState,
} from "../lib/noise/crypto.mjs";

import {
  Header,
  ServiceFrame,
  ApplicationRequest,
  ApplicationResponse,
  BodyChunk,
  Reset,
  ResetCode,
  ServiceType,
  ServiceRequest,
  ServiceResponse,
  NoiseTransportFrame,
  encodeServiceFrame,
  decodeServiceFrame,
  encodeServiceResponse,
  decodeServiceResponse,
  encodeNoiseTransportFrame,
  decodeNoiseTransportFrame,
} from "../lib/noise/proto.mjs";

import { NoiseTransport, MAX_PAYLOAD_CHUNK_SIZE } from "../lib/noise/transport.mjs";
import { TokenManager, AuthSessionExpiredError } from "../lib/noise/token-manager.mjs";

// ============================================================================
// SUITE 1: NoiseClient Direct Unit Invariants & Disconnected State Guards
// ============================================================================

test("Suite 1.1: NoiseClient initialization, default properties, and disconnected guards", async () => {
  const tokenManager = new TokenManager();
  const client = new NoiseClient({
    tokenManager,
    pingIntervalMs: 25000,
    timeoutMs: 30000,
  });

  assert.strictEqual(client.connected, false);
  assert.strictEqual(client.transport, null);
  assert.strictEqual(client.initiator, null);
  assert.strictEqual(client.remoteStaticPublicKey, null);
  assert.strictEqual(client.credentials, null);
  assert.strictEqual(client.tokenManager, tokenManager);

  // Negative paths: operations on unconnected client must reject cleanly
  await assert.rejects(async () => client.chatStream("Hello"), {
    name: "Error",
    message: /NoiseClient is not connected/i,
  });

  await assert.rejects(async () => client.ping(), {
    name: "Error",
    message: /NoiseClient is not connected/i,
  });

  await assert.rejects(async () => client.registerCapabilities([]), {
    name: "Error",
    message: /NoiseClient is not connected/i,
  });

  await assert.rejects(async () => client.sendInvokeResult("call_1", {}), {
    name: "Error",
    message: /NoiseClient is not connected/i,
  });

  await assert.rejects(async () => client.historyWindow("chat_1"), {
    name: "Error",
    message: /NoiseClient is not connected/i,
  });

  // Idempotent close
  await client.close();
  assert.strictEqual(client.connected, false);
  assert.strictEqual(client.transport, null);
});

test("Suite 1.2: URL query parameters formatting (vm_id, auth_token, notary_token, app_id, request_id)", async () => {
  let capturedUrl = null;
  class InspectingWebSocket extends LoopbackWebSocket {
    constructor(url) {
      super(url);
      capturedUrl = url;
    }
  }

  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  const tokenManager = new TestTokenManager({
    vm_id: "vm-test-uuid-4455",
    auth_token: "token-auth-secret",
    notary_token: "token-notary-secret",
  });

  const client = new NoiseClient({
    tokenManager,
    WebSocketClass: InspectingWebSocket,
  });

  await client.connect();

  assert.ok(capturedUrl, "WebSocket was instantiated with URL");
  const parsed = new URL(capturedUrl);
  assert.strictEqual(parsed.protocol, "wss:");
  assert.strictEqual(parsed.hostname, "hatch.metaaivm.com");
  assert.strictEqual(parsed.pathname, "/v1/noise");
  assert.strictEqual(parsed.searchParams.get("vm_id"), "vm-test-uuid-4455");
  assert.strictEqual(parsed.searchParams.get("auth_token"), "token-auth-secret");
  assert.strictEqual(parsed.searchParams.get("notary_token"), "token-notary-secret");
  assert.strictEqual(parsed.searchParams.get("app_id"), "hatch-web");
  assert.ok(parsed.searchParams.get("request_id"), "request_id is present");

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

test("Suite 1.3: Idempotent connect() when already connected", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
  });

  await client.connect();
  assert.strictEqual(client.connected, true);

  // Second connect() should resolve immediately without re-handshaking
  await client.connect();
  assert.strictEqual(client.connected, true);

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

// ============================================================================
// SUITE 2: Full Noise XX Handshake & Transport Verification
// ============================================================================

test("Suite 2.1: Successful Noise XX 3-message handshake and transport establishment", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  const tokenManager = new TestTokenManager();
  const client = new NoiseClient({
    tokenManager,
    WebSocketClass: LoopbackWebSocket,
    pingIntervalMs: 60000,
  });

  assert.strictEqual(client.connected, false);

  // Connect and complete handshake
  await client.connect();

  assert.strictEqual(client.connected, true);
  assert.ok(client.transport instanceof NoiseTransport);
  assert.ok(client.remoteStaticPublicKey instanceof Uint8Array);
  assert.strictEqual(client.remoteStaticPublicKey.length, 32);

  // Verify remote static key discovered in handshake matches server static public key
  assert.deepStrictEqual(
    client.remoteStaticPublicKey,
    server.serverStatic.publicKeyBytes
  );

  // Verify server received Message 1 (66 bytes: 32B pubkey + 34B client nonce)
  assert.ok(server.receivedMessage1 instanceof Uint8Array);
  assert.strictEqual(server.receivedMessage1.length, 66);

  // Verify server received Message 3 (48B enc_s + enc_auth_token + 16B tag)
  assert.ok(server.receivedMessage3 instanceof Uint8Array);
  assert.ok(server.receivedMessage3.length >= 64);

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

// ============================================================================
// SUITE 3: Full-Duplex Chat Streaming (chatStream)
// ============================================================================

test("Suite 3.1: Streaming text with BodyChunks and cumulative monotonic delta delivery", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  // Custom multi-chunk stream generator
  server.chatStreamHandler = async (srv, streamId, reqJson) => {
    assert.strictEqual(reqJson.prompt, "Explain quantum entanglement");

    const resp = new ApplicationResponse({ status: 200, end_body: false });
    await srv.sendServerResponseFrame(streamId, new ServiceFrame({ stream_id: streamId, response: resp }));

    const chunks = ["Quantum ", "entanglement ", "is ", "spooky ", "action ", "at ", "a distance."];
    for (let i = 0; i < chunks.length; i++) {
      const isLast = i === chunks.length - 1;
      await srv.sendServerResponseFrame(
        streamId,
        new ServiceFrame({
          stream_id: streamId,
          body_chunk: new BodyChunk({
            data: new TextEncoder().encode(chunks[i]),
            end_body: isLast,
          }),
        })
      );
    }
  };

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
  });
  await client.connect();

  const deltas = [];
  const result = await client.chatStream("Explain quantum entanglement", {
    onDelta: (cumulative) => {
      deltas.push(cumulative);
    },
  });

  // Verify cumulative deltas were monotonically increasing
  assert.ok(deltas.length >= 7);
  assert.strictEqual(deltas[0], "Quantum ");
  assert.strictEqual(deltas[1], "Quantum entanglement ");
  assert.strictEqual(deltas[deltas.length - 1], "Quantum entanglement is spooky action at a distance.");

  // Verify final return object
  assert.strictEqual(result.text, "Quantum entanglement is spooky action at a distance.");
  assert.strictEqual(result.reply, "Quantum entanglement is spooky action at a distance.");
  assert.deepStrictEqual(result.toolCalls, []);
  assert.strictEqual(result.finishReason, "stop");

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

test("Suite 3.2: SSE format parsing and JSON delta chunk stream handling", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  server.chatStreamHandler = async (srv, streamId) => {
    const resp = new ApplicationResponse({ status: 200, end_body: false });
    await srv.sendServerResponseFrame(streamId, new ServiceFrame({ stream_id: streamId, response: resp }));

    const sseLines = [
      'data: {"choices":[{"delta":{"content":"Line 1 "}}]}\n\n',
      'data: {"choices":[{"delta":{"content":"Line 2 "}}]}\n\n',
      'data: {"choices":[{"delta":{"content":"Line 3"}},{"finish_reason":"stop"}]}\n\n',
      "data: [DONE]\n\n",
    ];

    for (let i = 0; i < sseLines.length; i++) {
      const isLast = i === sseLines.length - 1;
      await srv.sendServerResponseFrame(
        streamId,
        new ServiceFrame({
          stream_id: streamId,
          body_chunk: new BodyChunk({
            data: new TextEncoder().encode(sseLines[i]),
            end_body: isLast,
          }),
        })
      );
    }
  };

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
  });
  await client.connect();

  const deltas = [];
  const result = await client.chatStream("Stream SSE", {
    onDelta: (cum) => deltas.push(cum),
  });

  assert.strictEqual(result.text, "Line 1 Line 2 Line 3");
  assert.strictEqual(result.finishReason, "stop");
  assert.strictEqual(deltas[deltas.length - 1], "Line 1 Line 2 Line 3");

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

// ============================================================================
// SUITE 4: Native Tool Calling
// ============================================================================

test("Suite 4.1: Capability registration via registerCapabilities(tools)", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
  });
  await client.connect();

  const toolSchemas = [
    {
      name: "get_weather",
      description: "Get weather for location",
      parameters: {
        type: "object",
        properties: { location: { type: "string" } },
        required: ["location"],
      },
    },
    {
      name: "search_db",
      description: "Search corporate knowledge database",
      parameters: {
        type: "object",
        properties: { query: { type: "string" } },
        required: ["query"],
      },
    },
  ];

  const regResult = await client.registerCapabilities(toolSchemas);
  assert.strictEqual(regResult.ok, true);
  assert.strictEqual(regResult.status, 200);
  assert.strictEqual(regResult.registeredCount, 2);

  // Verify server received and stored the schemas
  assert.strictEqual(server.registeredCapabilities.length, 2);
  assert.strictEqual(server.registeredCapabilities[0].name, "get_weather");
  assert.strictEqual(server.registeredCapabilities[1].name, "search_db");

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

test("Suite 4.2: Tool invocation event detection (type: 'function_call') in chatStream", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  server.chatStreamHandler = async (srv, streamId) => {
    const resp = new ApplicationResponse({ status: 200, end_body: false });
    await srv.sendServerResponseFrame(streamId, new ServiceFrame({ stream_id: streamId, response: resp }));

    // Emit function invocation event
    const toolCallEvent = JSON.stringify({
      type: "function_call",
      call_id: "call_weather_tokyo_001",
      name: "get_weather",
      arguments: { location: "Tokyo, Japan", units: "metric" },
    });

    const chunk = new BodyChunk({
      data: new TextEncoder().encode(toolCallEvent),
      end_body: true,
    });
    await srv.sendServerResponseFrame(streamId, new ServiceFrame({ stream_id: streamId, body_chunk: chunk }));
  };

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
  });
  await client.connect();

  const result = await client.chatStream("What is the weather in Tokyo?", {
    tools: [{ name: "get_weather" }],
  });

  assert.strictEqual(result.finishReason, "tool_calls");
  assert.strictEqual(result.toolCalls.length, 1);
  assert.strictEqual(result.toolCalls[0].id, "call_weather_tokyo_001");
  assert.strictEqual(result.toolCalls[0].type, "function");
  assert.strictEqual(result.toolCalls[0].function.name, "get_weather");

  const parsedArgs = JSON.parse(result.toolCalls[0].function.arguments);
  assert.strictEqual(parsedArgs.location, "Tokyo, Japan");
  assert.strictEqual(parsedArgs.units, "metric");

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

test("Suite 4.3: Feedback transmission via sendInvokeResult(callId, result)", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
  });
  await client.connect();

  const invokeRes = await client.sendInvokeResult("call_weather_tokyo_001", {
    temperature: "18C",
    condition: "Sunny",
  });

  assert.strictEqual(invokeRes.ok, true);
  assert.strictEqual(invokeRes.status, 200);
  assert.strictEqual(invokeRes.acknowledgedCallId, "call_weather_tokyo_001");

  // Verify server recorded the invoke result
  assert.ok(server.lastInvokeResult);
  assert.strictEqual(server.lastInvokeResult.call_id, "call_weather_tokyo_001");
  assert.strictEqual(server.lastInvokeResult.status, "success");

  const serverOutput = JSON.parse(server.lastInvokeResult.output);
  assert.strictEqual(serverOutput.temperature, "18C");
  assert.strictEqual(serverOutput.condition, "Sunny");

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

// ============================================================================
// SUITE 5: Keepalive Heartbeat, Stream Management, & History
// ============================================================================

test("Suite 5.1: Heartbeat ping() roundtrip (POST /api/ping)", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
  });
  await client.connect();

  const pingOk = await client.ping();
  assert.strictEqual(pingOk, true);
  assert.strictEqual(server.receivedPingCount, 1);

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

test("Suite 5.2: Fast keepalive timer triggers automatic periodic ping()", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  // Use a fast ping interval (50ms) to test automatic periodic trigger
  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
    pingIntervalMs: 50,
  });
  await client.connect();

  // Wait for 3-4 ping cycles
  await new Promise((r) => setTimeout(r, 180));

  assert.ok(
    server.receivedPingCount >= 2,
    `Expected at least 2 pings, got ${server.receivedPingCount}`
  );

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

test("Suite 5.3: Graceful stream cancellation via cancel(streamId)", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  let streamAbortedOnServer = false;

  server.chatStreamHandler = async (srv, streamId) => {
    const resp = new ApplicationResponse({ status: 200, end_body: false });
    await srv.sendServerResponseFrame(streamId, new ServiceFrame({ stream_id: streamId, response: resp }));

    // Send first chunk
    await srv.sendServerResponseFrame(
      streamId,
      new ServiceFrame({
        stream_id: streamId,
        body_chunk: new BodyChunk({
          data: new TextEncoder().encode("Beginning long stream... "),
          end_body: false,
        }),
      })
    );

    // Watch for cancellation
    const checkCancel = setInterval(() => {
      if (server.cancelledStreamIds.includes(streamId)) {
        streamAbortedOnServer = true;
        clearInterval(checkCancel);
      }
    }, 20);

    // Clean up timer after 500ms safety timeout
    setTimeout(() => clearInterval(checkCancel), 500);
  };

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
  });
  await client.connect();

  let deltaReceived = "";
  let cancelPromise = null;
  const streamPromise = client.chatStream("Generate infinite text", {
    onDelta: (cum) => {
      deltaReceived = cum;
      if (!cancelPromise) {
        cancelPromise = client.cancel(1n, "USER_STOPPED");
      }
    },
  });

  const res = await streamPromise;
  if (cancelPromise) await cancelPromise;
  await new Promise((r) => setTimeout(r, 50));

  assert.strictEqual(res.finishReason, "cancelled");
  assert.ok(res.text.includes("Beginning long stream..."));

  // Verify server registered cancellation
  assert.ok(
    server.cancelledStreamIds.length > 0 || streamAbortedOnServer,
    "Server should receive stream cancellation"
  );

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

test("Suite 5.4: History window inspection via historyWindow(chatId, max)", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
  });
  await client.connect();

  const history = await client.historyWindow("chat_session_99", 10);
  assert.ok(Array.isArray(history.messages));
  assert.strictEqual(history.messages.length, 2);
  assert.strictEqual(history.messages[0].role, "user");
  assert.strictEqual(history.messages[1].role, "assistant");

  // Verify server received request with query params
  const lastReq = server.receivedRequests.find((r) => r.path.startsWith("/chat/history-window"));
  assert.ok(lastReq);
  assert.ok(lastReq.path.includes("chat_id=chat_session_99"));
  assert.ok(lastReq.path.includes("max=10"));

  await client.close();
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

// ============================================================================
// SUITE 6: Failure Modes, Security & Teardown
// ============================================================================

test("Suite 6.1: Handshake rejection on truncated Message 2 (< 96 bytes)", async () => {
  const server = new SyntheticNoiseServer({ truncateMessage2: true });
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
    timeoutMs: 2000,
  });

  await assert.rejects(
    async () => {
      await client.connect();
    },
    {
      name: "Error",
      message: /message 2 too short/i,
    }
  );

  assert.strictEqual(client.connected, false);
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

test("Suite 6.2: Handshake rejection on corrupted Message 2 ciphertext", async () => {
  const server = new SyntheticNoiseServer({ corruptMessage2: true });
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
    timeoutMs: 2000,
  });

  await assert.rejects(
    async () => {
      await client.connect();
    },
    (err) => {
      assert.strictEqual(client.connected, false);
      return err instanceof Error;
    }
  );

  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

test("Suite 6.3: Handshake rejection when WebSocket closes prematurely", async () => {
  const server = new SyntheticNoiseServer({ closeOnHandshake: true });
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
    timeoutMs: 2000,
  });

  await assert.rejects(
    async () => {
      await client.connect();
    },
    {
      name: "Error",
      message: /WebSocket closed during Noise handshake/i,
    }
  );

  assert.strictEqual(client.connected, false);
  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

test("Suite 6.4: close() stops ping timer, resets transport, and is idempotent", async () => {
  const server = new SyntheticNoiseServer();
  await server.initialize();
  LoopbackWebSocket.activeServer = server;

  const client = new NoiseClient({
    tokenManager: new TestTokenManager(),
    WebSocketClass: LoopbackWebSocket,
    pingIntervalMs: 50,
  });

  await client.connect();
  assert.strictEqual(client.connected, true);

  await client.close();
  assert.strictEqual(client.connected, false);
  assert.strictEqual(client.transport, null);

  const pingCountAtClose = server.receivedPingCount;
  await new Promise((r) => setTimeout(r, 120));

  // Verify ping timer was cleared and stopped sending pings
  assert.strictEqual(server.receivedPingCount, pingCountAtClose);

  // Subsequent close() calls should be safely idempotent
  await client.close();
  assert.strictEqual(client.connected, false);

  server.destroy();
  LoopbackWebSocket.activeServer = null;
});

// ============================================================================
// SYNTHETIC NOISE RESPONDER & TEST INFRASTRUCTURE (Evaluated at module load)
// ============================================================================

/**
 * SyntheticNoiseXXResponder performing the responder side of Noise XX
 * using real WebCrypto X25519 and AES-GCM operations.
 */
class SyntheticNoiseXXResponder {
  constructor(staticKeyPair) {
    this.s = staticKeyPair;
    this.e = null;
    this.re = null;
    this.rs = null;
    this.symmetric = new SymmetricState();
    this.splitResult = null;
  }

  async initialize() {
    await this.symmetric.initialize();
  }

  async receiveMessage1(msg1, attestationPayload = new TextEncoder().encode("MUSE_SERVER_ATTESTATION_OK")) {
    if (!msg1 || msg1.length < 32) {
      throw new Error(`Responder: msg1 too short (${msg1 ? msg1.length : 0} < 32)`);
    }

    this.re = new Uint8Array(msg1.subarray(0, 32));
    await this.symmetric.mixHash(this.re);

    const clientNoncePayload = await this.symmetric.decryptAndHash(msg1.subarray(32));

    this.e = await generateX25519KeyPair();
    await this.symmetric.mixHash(this.e.publicKeyBytes);

    const ee = await x25519DH(this.e.privateKey, this.re);
    await this.symmetric.mixKey(ee);
    zeroize(ee);

    const enc_s = await this.symmetric.encryptAndHash(this.s.publicKeyBytes);

    const es = await x25519DH(this.s.privateKey, this.re);
    await this.symmetric.mixKey(es);
    zeroize(es);

    const enc_attestation = await this.symmetric.encryptAndHash(attestationPayload);

    return {
      message2: concat(this.e.publicKeyBytes, enc_s, enc_attestation),
      clientNoncePayload,
    };
  }

  async receiveMessage3(msg3) {
    if (!msg3 || msg3.length < 48) {
      throw new Error(`Responder: msg3 too short (${msg3 ? msg3.length : 0} < 48)`);
    }

    this.rs = await this.symmetric.decryptAndHash(msg3.subarray(0, 48));

    const se = await x25519DH(this.e.privateKey, this.rs);
    await this.symmetric.mixKey(se);
    zeroize(se);

    const clientTicket = await this.symmetric.decryptAndHash(msg3.subarray(48));

    const [rxCipher, txCipher] = await this.symmetric.split();
    this.splitResult = { rxCipher, txCipher };

    return { clientTicket, rxCipher, txCipher };
  }
}

/**
 * Loopback WebSocket implementing the W3C / HTML5 WebSocket interface
 * completely in memory with asynchronous frame dispatching.
 */
class LoopbackWebSocket extends EventEmitter {
  constructor(url) {
    super();
    this.url = String(url);
    this.binaryType = "arraybuffer";
    this.readyState = 0; // CONNECTING
    this.server = LoopbackWebSocket.activeServer;

    if (!this.server) {
      queueMicrotask(() => {
        this.readyState = 3; // CLOSED
        const err = new Error("No active synthetic server bound to loopback socket");
        this.emit("error", err);
        if (typeof this.onerror === "function") this.onerror(err);
        this.emit("close", { code: 1006, reason: "Server unavailable", wasClean: false });
        if (typeof this.onclose === "function") {
          this.onclose({ code: 1006, reason: "Server unavailable", wasClean: false });
        }
      });
      return;
    }

    this.server._attachClient(this);
  }

  addEventListener(event, listener) {
    this.on(event, listener);
  }

  removeEventListener(event, listener) {
    this.off(event, listener);
  }

  send(data) {
    if (this.readyState !== 1) {
      throw new Error(`WebSocket is not open: readyState is ${this.readyState}`);
    }
    if (this.server) {
      this.server._enqueueClientSend(this, data);
    }
  }

  close(code = 1000, reason = "") {
    if (this.readyState === 2 || this.readyState === 3) return;
    this.readyState = 2; // CLOSING
    queueMicrotask(() => {
      this.readyState = 3; // CLOSED
      if (this.server) {
        this.server._handleClientClose(this, code, reason);
      }
      this.emit("close", { code, reason, wasClean: true });
      if (typeof this.onclose === "function") {
        this.onclose({ code, reason, wasClean: true });
      }
    });
  }

  _dispatchOpen() {
    this.readyState = 1; // OPEN
    this.emit("open", {});
    if (typeof this.onopen === "function") {
      this.onopen({});
    }
  }

  _dispatchMessage(data) {
    if (this.readyState !== 1) return;
    const event = { data };
    this.emit("message", event);
    if (typeof this.onmessage === "function") {
      this.onmessage(event);
    }
  }

  _dispatchError(err) {
    this.emit("error", err);
    if (typeof this.onerror === "function") {
      this.onerror(err);
    }
  }

  _dispatchClose(code = 1000, reason = "") {
    this.readyState = 3;
    const event = { code, reason, wasClean: code === 1000 };
    this.emit("close", event);
    if (typeof this.onclose === "function") {
      this.onclose(event);
    }
  }
}

/**
 * Synthetic Noise Server implementing the server side of Meta Muse's RPC gateway.
 */
class SyntheticNoiseServer {
  constructor(options = {}) {
    this.serverStatic = null;
    this.responder = null;
    this.serverTransport = null;
    this.sTx = null;
    this.sRx = null;
    this.clientWs = null;
    this.handshakePhase = 0;
    this.serverAttestation = new TextEncoder().encode("MUSE_EDGE_SERVER_ATTESTATION_PASS");

    this._queue = Promise.resolve();

    this.receivedMessage1 = null;
    this.receivedMessage3 = null;
    this.registeredCapabilities = null;
    this.lastInvokeResult = null;
    this.receivedPingCount = 0;
    this.cancelledStreamIds = [];
    this.receivedRequests = [];

    this.chatStreamHandler = null;
    this.corruptMessage2 = Boolean(options.corruptMessage2);
    this.truncateMessage2 = Boolean(options.truncateMessage2);
    this.closeOnHandshake = Boolean(options.closeOnHandshake);
  }

  async initialize() {
    this.serverStatic = await generateX25519KeyPair();
    this.responder = new SyntheticNoiseXXResponder(this.serverStatic);
    await this.responder.initialize();
  }

  _attachClient(ws) {
    this.clientWs = ws;
    queueMicrotask(() => {
      if (this.closeOnHandshake) {
        ws._dispatchClose(1008, "Policy violation during handshake");
        return;
      }
      ws._dispatchOpen();
    });
  }

  _handleClientClose(ws, code, reason) {
    this.clientWs = null;
  }

  _enqueueClientSend(ws, data) {
    this._queue = this._queue
      .then(() => this._handleClientSend(ws, data))
      .catch((err) => {
        if (this.clientWs) {
          this.clientWs._dispatchError(err);
        }
      });
  }

  async _handleClientSend(ws, data) {
    const raw = data instanceof Uint8Array ? data : new Uint8Array(data);

    if (this.handshakePhase === 0) {
      this.receivedMessage1 = raw;
      const { message2 } = await this.responder.receiveMessage1(raw, this.serverAttestation);

      if (this.truncateMessage2) {
        ws._dispatchMessage(message2.subarray(0, 50));
        return;
      }

      if (this.corruptMessage2) {
        const corrupted = new Uint8Array(message2);
        corrupted[40] ^= 0xff;
        corrupted[60] ^= 0xaa;
        ws._dispatchMessage(corrupted);
        return;
      }

      this.handshakePhase = 1;
      ws._dispatchMessage(message2);
      return;
    }

    if (this.handshakePhase === 1) {
      this.receivedMessage3 = raw;
      const { rxCipher: sRx, txCipher: sTx } = await this.responder.receiveMessage3(raw);
      this.sRx = sRx;
      this.sTx = sTx;

      this.serverTransport = new NoiseTransport(sTx, sRx, (bytes) => {
        if (this.clientWs) {
          this.clientWs._dispatchMessage(bytes);
        }
      });

      this.handshakePhase = 2;
      return;
    }

    if (this.handshakePhase === 2 && this.serverTransport) {
      const serviceFrame = await this.serverTransport.handleIncoming(raw);
      if (!serviceFrame) return;

      if (serviceFrame.reset) {
        this.cancelledStreamIds.push(serviceFrame.stream_id);
        return;
      }

      if (serviceFrame.request) {
        await this._handleRequest(serviceFrame.stream_id, serviceFrame.request);
      }
    }
  }

  async sendServerResponseFrame(streamId, serviceFrame) {
    const frameBytes = encodeServiceFrame(serviceFrame);
    const respEnvelope = new ServiceResponse({ payload: frameBytes });
    const respBytes = encodeServiceResponse(respEnvelope);

    const transportFrame = new NoiseTransportFrame({
      chunk_id: BigInt(Date.now()),
      chunk_index: 0,
      total_chunks: 1,
      payload: respBytes,
    });
    const encoded = encodeNoiseTransportFrame(transportFrame);
    const ciphertext = await this.sTx.encryptWithAd(new Uint8Array(0), encoded);
    if (this.clientWs) {
      this.clientWs._dispatchMessage(ciphertext);
    }
  }

  async _handleRequest(streamId, req) {
    const verb = req.verb;
    const path = req.path;
    const reqBodyText = req.body && req.body.length > 0 ? new TextDecoder().decode(req.body) : "";
    let reqBodyJson = null;
    try {
      reqBodyJson = reqBodyText ? JSON.parse(reqBodyText) : null;
    } catch {}

    this.receivedRequests.push({ streamId, verb, path, bodyText: reqBodyText, bodyJson: reqBodyJson });

    if (verb === "POST" && path === "/api/ping") {
      this.receivedPingCount++;
      const resp = new ApplicationResponse({ status: 200, end_body: true });
      await this.sendServerResponseFrame(streamId, new ServiceFrame({ stream_id: streamId, response: resp }));
      return;
    }

    if (verb === "POST" && path === "/client/register-capabilities") {
      this.registeredCapabilities = reqBodyJson?.capabilities || [];
      const respBody = JSON.stringify({
        ok: true,
        registeredCount: this.registeredCapabilities.length,
      });
      const resp = new ApplicationResponse({
        status: 200,
        body: new TextEncoder().encode(respBody),
        end_body: true,
      });
      await this.sendServerResponseFrame(streamId, new ServiceFrame({ stream_id: streamId, response: resp }));
      return;
    }

    if (verb === "POST" && path === "/client/invoke-result") {
      this.lastInvokeResult = reqBodyJson;
      const respBody = JSON.stringify({ ok: true, acknowledgedCallId: reqBodyJson?.call_id });
      const resp = new ApplicationResponse({
        status: 200,
        body: new TextEncoder().encode(respBody),
        end_body: true,
      });
      await this.sendServerResponseFrame(streamId, new ServiceFrame({ stream_id: streamId, response: resp }));
      return;
    }

    if (verb === "GET" && path.startsWith("/chat/history-window")) {
      const respBody = JSON.stringify({
        messages: [
          { role: "user", content: "Tell me a joke" },
          { role: "assistant", content: "Why do programmers prefer dark mode? Because light attracts bugs." },
        ],
      });
      const resp = new ApplicationResponse({
        status: 200,
        body: new TextEncoder().encode(respBody),
        end_body: true,
      });
      await this.sendServerResponseFrame(streamId, new ServiceFrame({ stream_id: streamId, response: resp }));
      return;
    }

    if (verb === "POST" && path === "/chat/cancel") {
      this.cancelledStreamIds.push(reqBodyJson?.stream_id || streamId);
      const resp = new ApplicationResponse({ status: 200, end_body: true });
      await this.sendServerResponseFrame(streamId, new ServiceFrame({ stream_id: streamId, response: resp }));
      return;
    }

    if (verb === "POST" && path === "/chat/stream") {
      if (typeof this.chatStreamHandler === "function") {
        await this.chatStreamHandler(this, streamId, reqBodyJson);
        return;
      }

      const initialResp = new ApplicationResponse({ status: 200, end_body: false });
      await this.sendServerResponseFrame(
        streamId,
        new ServiceFrame({ stream_id: streamId, response: initialResp })
      );

      const chunks = ["Hello ", "from Meta ", "Muse headless!"];
      for (let i = 0; i < chunks.length; i++) {
        const isLast = i === chunks.length - 1;
        const chunkFrame = new ServiceFrame({
          stream_id: streamId,
          body_chunk: new BodyChunk({
            data: new TextEncoder().encode(chunks[i]),
            end_body: isLast,
          }),
        });
        await this.sendServerResponseFrame(streamId, chunkFrame);
      }
      return;
    }

    const notFound = new ApplicationResponse({
      status: 404,
      body: new TextEncoder().encode(`Not Found: ${path}`),
      end_body: true,
    });
    await this.sendServerResponseFrame(
      streamId,
      new ServiceFrame({ stream_id: streamId, response: notFound })
    );
  }

  destroy() {
    if (this.serverStatic) {
      destroyX25519KeyPair(this.serverStatic);
      this.serverStatic = null;
    }
    if (this.clientWs) {
      this.clientWs.close();
      this.clientWs = null;
    }
  }
}

/**
 * TestTokenManager extending TokenManager with deterministic session credentials.
 */
class TestTokenManager extends TokenManager {
  constructor(credentials = {}) {
    super();
    this._credentials = {
      vm_id: credentials.vm_id || "vm-9b1deb4d-3b7d-4ba9-8976-123456789abc",
      endpoint_url: credentials.endpoint_url || "wss://hatch.metaaivm.com/v1/noise",
      auth_token: credentials.auth_token || "s0:eyJhbGciOiJFZERTQTEwMiIsInR5cCI6IkpXVCJ9.token_payload",
      notary_token: credentials.notary_token || "endorsement.v1.eyJyZXF1ZXN0X2hhc2giOiJkZW1vIn0",
      expiresAt: Date.now() + 86400 * 1000,
    };
  }

  async ensureValidSession() {
    return { ...this._credentials };
  }
}
