/**
 * lib/noise/noise-client.mjs
 * ------------------------------------------------------------------
 * Headless RPC Client & Native Tool Calling for Meta Muse (Phase 2).
 *
 * Implements Milestone 5 (R5):
 * - Connects to Meta Muse's RPC gateway over encrypted WebSockets
 *   (wss://hatch.metaaivm.com/v1/noise) using query parameters:
 *   vm_id, auth_token, notary_token, app_id=hatch-web, request_id.
 * - Orchestrates the full Noise_XX_25519_AESGCM_SHA256 handshake
 *   via NoiseXXInitiator:
 *     1. Sends Message 1 (initiator.writeMessage1(), 66 bytes).
 *     2. Receives Message 2 (>= 96 bytes) and processes via initiator.readMessage2().
 *     3. Sends Message 3 (initiator.writeMessage3()).
 *     4. Splits initiator into [txCipher, rxCipher].
 *     5. Binds txCipher/rxCipher to NoiseTransport over the WebSocket connection.
 * - Starts a 25-second periodic keep-alive heartbeat calling ping() (POST /api/ping).
 * - Full-duplex chat streaming via chatStream():
 *     - Serializes user prompt, system prompt, attachments, and tool definitions.
 *     - Dispatches POST /chat/stream ServiceFrame.
 *     - Assembles streaming BodyChunk frames.
 *     - Emits cumulative full text to onDelta(cumulativeText) matching muse-driver.mjs contract.
 *     - Detects native tool call function invocation events (type: 'function_call').
 *     - Returns normalized { text, toolCalls, finishReason }.
 * - Native tool calling lifecycle:
 *     - registerCapabilities(tools): POST /client/register-capabilities
 *     - sendInvokeResult(callId, result): POST /client/invoke-result
 * - Stream and session management:
 *     - ping(): POST /api/ping
 *     - cancel(streamId): POST /chat/cancel and Reset frame
 *     - historyWindow(chatId, max): GET /chat/history-window
 *     - close(): stops timers, resets transport, closes WebSocket cleanly.
 *
 * Pure Node 20+ built-ins only (node:crypto, node:events). ZERO external dependencies.
 * ------------------------------------------------------------------
 */

import crypto from "node:crypto";
import { NoiseXXInitiator, concat } from "./crypto.mjs";
import {
  Header,
  ServiceFrame,
  ApplicationRequest,
  ApplicationResponse,
  BodyChunk,
  Reset,
  ResetCode,
  ServiceType,
} from "./proto.mjs";
import { NoiseTransport, NoiseFrameDecoder } from "./transport.mjs";
import { TokenManager, AuthSessionExpiredError } from "./token-manager.mjs";

export const DEFAULT_PING_INTERVAL_MS = 25000;
export const DEFAULT_TIMEOUT_MS = 30000;
export const DEFAULT_ENDPOINT_URL = "wss://hatch.metaaivm.com/v1/noise";

/**
 * Normalizes any binary representation (Uint8Array, ArrayBuffer, Buffer) to a Uint8Array.
 * @param {Uint8Array|ArrayBuffer|ArrayBufferView} data
 * @returns {Uint8Array}
 */
function toUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data);
}

/**
 * Headless RPC client communicating directly with Meta Muse over an encrypted
 * Noise_XX WebSocket channel.
 */
export class NoiseClient {
  #tokenManager;
  #wsUrl;
  #autoReconnect;
  #pingIntervalMs;
  #timeoutMs;
  #WebSocketClass;

  #ws = null;
  #transport = null;
  #initiator = null;
  #remoteStaticPublicKey = null;
  #pingTimer = null;
  #connected = false;
  #closed = false;
  #credentials = null;
  #activeStreams = new Map();

  /**
   * @param {object} [options={}]
   * @param {TokenManager} [options.tokenManager] Session token manager instance
   * @param {string} [options.wsUrl] Optional explicit WebSocket URL override
   * @param {boolean} [options.autoReconnect=false] Whether to auto-reconnect on unexpected drop
   * @param {number} [options.pingIntervalMs=25000] Heartbeat ping interval in ms
   * @param {number} [options.timeoutMs=30000] Request / handshake timeout in ms
   * @param {Function} [options.WebSocketClass=globalThis.WebSocket] WebSocket constructor
   */
  constructor(options = {}) {
    this.#tokenManager =
      options.tokenManager instanceof TokenManager
        ? options.tokenManager
        : new TokenManager(options);

    this.#wsUrl = typeof options.wsUrl === "string" ? options.wsUrl : null;
    this.#autoReconnect = Boolean(options.autoReconnect);
    this.#pingIntervalMs =
      typeof options.pingIntervalMs === "number" && options.pingIntervalMs > 0
        ? options.pingIntervalMs
        : DEFAULT_PING_INTERVAL_MS;
    this.#timeoutMs =
      typeof options.timeoutMs === "number" && options.timeoutMs > 0
        ? options.timeoutMs
        : DEFAULT_TIMEOUT_MS;
    this.#WebSocketClass =
      options.WebSocketClass ||
      (typeof WebSocket !== "undefined" ? WebSocket : globalThis.WebSocket);
  }

  /** Whether the Noise client is actively connected and encrypted tunnel is ready. */
  get connected() {
    return Boolean(
      this.#connected &&
        this.#transport &&
        this.#ws &&
        (this.#ws.readyState === 1 || this.#ws.readyState === undefined)
    );
  }

  /** Active TokenManager instance. */
  get tokenManager() {
    return this.#tokenManager;
  }

  /** Underlying NoiseTransport multiplexer instance (null if disconnected). */
  get transport() {
    return this.#transport;
  }

  /** Active NoiseXXInitiator instance from handshake (null if disconnected). */
  get initiator() {
    return this.#initiator;
  }

  /** Remote static public key discovered during Message 2 of handshake. */
  get remoteStaticPublicKey() {
    return this.#remoteStaticPublicKey
      ? new Uint8Array(this.#remoteStaticPublicKey)
      : null;
  }

  /** Cached session credentials from last connect. */
  get credentials() {
    return this.#credentials ? { ...this.#credentials } : null;
  }

  /**
   * Establishes an encrypted Noise WebSocket connection to Meta Muse.
   *
   * Sequence:
   * 1. Obtains session credentials via tokenManager.ensureValidSession()
   * 2. Builds gateway URL with vm_id, auth_token, notary_token, app_id, request_id
   * 3. Opens WebSocket with binaryType 'arraybuffer'
   * 4. Executes Noise XX initiator handshake:
   *    - Sends Message 1 (66 bytes: 32B pubkey + 34B client nonce)
   *    - Awaits Message 2 (>= 96 bytes) and processes via readMessage2()
   *    - Sends Message 3 with client auth token
   *    - Splits into [txCipher, rxCipher]
   * 5. Instantiates NoiseTransport and starts 25s keepalive ping timer
   *
   * @returns {Promise<void>}
   */
  async connect() {
    if (this.connected) {
      return;
    }

    if (!this.#WebSocketClass) {
      throw new Error(
        "WebSocket constructor is not available in current environment. " +
          "Provide options.WebSocketClass or ensure Node 20+ globalThis.WebSocket is available."
      );
    }

    this.#closed = false;

    // 1. Obtain session credentials
    const credentials = await this.#tokenManager.ensureValidSession();
    this.#credentials = credentials;
    const { vm_id, endpoint_url, auth_token, notary_token } = credentials;

    // 2. Build WebSocket URL
    let base = this.#wsUrl || endpoint_url || DEFAULT_ENDPOINT_URL;
    if (!this.#wsUrl && typeof base === "string") {
      let u = null;
      try {
        u = new URL(base);
      } catch {
        u = null;
      }
      if (u && !u.pathname.includes("/v1/noise")) {
        let extractedVmId = vm_id;
        if (!extractedVmId && u.hostname.endsWith(".metaaivm.com") && u.hostname !== "hatch.metaaivm.com") {
          extractedVmId = u.hostname.replace(".metaaivm.com", "");
        }
        if (u.hostname.endsWith(".metaaivm.com")) {
          u.hostname = "hatch.metaaivm.com";
        }
        u.pathname = "/v1/noise";
        if (extractedVmId && !u.searchParams.has("vm_id")) {
          u.searchParams.set("vm_id", extractedVmId);
        }
        base = u.toString();
      }
    }
    const url = new URL(base);
    if (vm_id) url.searchParams.set("vm_id", vm_id);
    if (auth_token) url.searchParams.set("auth_token", auth_token);
    if (notary_token) url.searchParams.set("notary_token", notary_token);
    url.searchParams.set("app_id", "hatch-web");
    url.searchParams.set("request_id", crypto.randomUUID());

    // 3. Initiate connection and Noise XX handshake
    await new Promise((resolve, reject) => {
      let settled = false;
      let handshakeTimer = null;
      let ws = null;
      const initiator = new NoiseXXInitiator();

      const cleanup = () => {
        if (handshakeTimer) {
          clearTimeout(handshakeTimer);
          handshakeTimer = null;
        }
      };

      if (this.#timeoutMs > 0) {
        handshakeTimer = setTimeout(() => {
          if (settled) return;
          settled = true;
          cleanup();
          initiator.destroy();
          try {
            if (ws) ws.close();
          } catch {}
          reject(
            new Error(`Noise handshake timed out after ${this.#timeoutMs}ms`)
          );
        }, this.#timeoutMs);
        if (handshakeTimer.unref) handshakeTimer.unref();
      }

      const wsOptions = {
        headers: {
          Origin: "https://muse.ai",
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
        },
      };

      try {
        ws = new this.#WebSocketClass(url.toString(), wsOptions);
      } catch (wsErr) {
        try {
          ws = new this.#WebSocketClass(url.toString());
        } catch (fallbackErr) {
          cleanup();
          initiator.destroy();
          return reject(
            new Error(`Failed to instantiate WebSocket: ${fallbackErr.message || wsErr.message}`, {
              cause: fallbackErr || wsErr,
            })
          );
        }
      }

      ws.binaryType = "arraybuffer";

      let handshakeStep = 0;

      const handleOpen = async () => {
        try {
          // Message 1: 32 bytes ephemeral public key + 34 bytes client nonce payload = 66 bytes
          const clientNonce = new Uint8Array(34);
          clientNonce[0] = 0x0a; // Protobuf tag 1, wireType 2 (length-delimited)
          clientNonce[1] = 0x20; // 32 bytes length
          crypto.getRandomValues(clientNonce.subarray(2));

          const msg1 = await initiator.writeMessage1(clientNonce);
          handshakeStep = 1;
          ws.send(msg1);
        } catch (err) {
          if (settled) return;
          settled = true;
          cleanup();
          initiator.destroy();
          try {
            ws.close();
          } catch {}
          reject(err);
        }
      };

      const handleMessage = async (event) => {
        const raw = toUint8Array(event.data);

        // Handshake phase: expecting Message 2
        if (handshakeStep === 1) {
          try {
            if (raw.length < 96) {
              throw new Error(
                `NoiseXX: message 2 too short (${raw.length} < 96)`
              );
            }

            // Read Message 2: e, ee, s, es, payload
            await initiator.readMessage2(raw);
            const remoteStatic = initiator.remoteStaticPublicKey();
            this.#remoteStaticPublicKey = remoteStatic
              ? new Uint8Array(remoteStatic)
              : null;
            handshakeStep = 2;

            // Message 3: enc_s || enc_payload
            // For standard VMs, credentials are in URL query parameters, so payload is empty.
            const clientTicket = new Uint8Array(0);
            const msg3 = await initiator.writeMessage3(clientTicket);
            ws.send(msg3);

            // Split into [txCipher, rxCipher]
            const [txCipher, rxCipher] = await initiator.split();

            // Instantiate transport multiplexer
            const transport = new NoiseTransport(
              txCipher,
              rxCipher,
              (bytes) => {
                if (ws && (ws.readyState === 1 || ws.readyState === undefined)) {
                  ws.send(bytes);
                }
              }
            );

            this.#ws = ws;
            this.#transport = transport;
            this.#initiator = initiator;
            this.#connected = true;

            // Switch to transport message handling
            handshakeStep = 3;
            cleanup();
            settled = true;

            // Start 25s keepalive ping timer
            this.#startPingTimer();

            resolve();
          } catch (err) {
            if (settled) return;
            settled = true;
            cleanup();
            initiator.destroy();
            try {
              ws.close();
            } catch {}
            reject(err);
          }
          return;
        }

        // Post-handshake: route encrypted binary frames to transport multiplexer
        if (handshakeStep === 3 && this.#transport) {
          try {
            await this.#transport.handleIncoming(raw);
          } catch (err) {
            // Unhandled incoming frame decryption or protocol error
          }
        }
      };

      const handleError = (err) => {
        if (!settled) {
          settled = true;
          cleanup();
          initiator.destroy();
          const reason =
            err && err.message
              ? err.message
              : typeof err === "object"
              ? JSON.stringify(err)
              : String(err);
          reject(new Error(`WebSocket connection error during handshake: ${reason}`));
        }
      };

      const handleClose = (event) => {
        const wasConnected = this.#connected;
        this.#connected = false;
        if (this.#pingTimer) {
          clearInterval(this.#pingTimer);
          this.#pingTimer = null;
        }

        if (!settled) {
          settled = true;
          cleanup();
          initiator.destroy();
          const reason =
            event && event.reason
              ? event.reason
              : `Code ${event?.code || "unknown"}`;
          reject(new Error(`WebSocket closed during Noise handshake: ${reason}`));
          return;
        }

        // Post-handshake: immediately reject all active in-flight streams to avoid hanging
        const disconnectReason = event && event.reason ? `: ${event.reason}` : "";
        const disconnectError = new Error(
          `Noise WebSocket connection closed unexpectedly${disconnectReason}`
        );
        const activeHandlers = Array.from(this.#activeStreams.values());
        this.#activeStreams.clear();
        for (const handler of activeHandlers) {
          try {
            if (typeof handler?.reject === "function") {
              handler.reject(disconnectError);
            } else if (typeof handler === "function") {
              handler(disconnectError);
            }
          } catch {}
        }

        // Handle post-handshake unexpected disconnection
        if (wasConnected && this.#autoReconnect && !this.#closed) {
          this.#reconnect().catch(() => {});
        }
      };

      // Register standard listeners (supporting EventTarget, W3C, and Node WebSocket)
      if (typeof ws.addEventListener === "function") {
        ws.addEventListener("open", handleOpen);
        ws.addEventListener("message", handleMessage);
        ws.addEventListener("error", handleError);
        ws.addEventListener("close", handleClose);
      } else {
        ws.onopen = handleOpen;
        ws.onmessage = handleMessage;
        ws.onerror = handleError;
        ws.onclose = handleClose;
      }
    });
  }

  /**
   * Internal automatic reconnection logic.
   */
  async #reconnect() {
    if (this.#closed) return;
    try {
      await this.close();
      await this.connect();
    } catch (err) {
      // If session expired, invalidate token cache
      if (err instanceof AuthSessionExpiredError) {
        this.#tokenManager.invalidateToken();
      }
    }
  }

  /**
   * Starts the 25-second keepalive timer calling ping().
   */
  #startPingTimer() {
    if (this.#pingTimer) {
      clearInterval(this.#pingTimer);
    }
    if (this.#pingIntervalMs > 0) {
      this.#pingTimer = setInterval(async () => {
        if (!this.connected) return;
        try {
          await this.ping();
        } catch (err) {
          // If ping fails, connection may be stale
          if (this.#autoReconnect && !this.#closed) {
            this.#reconnect().catch(() => {});
          }
        }
      }, this.#pingIntervalMs);

      if (this.#pingTimer.unref) {
        this.#pingTimer.unref();
      }
    }
  }

  /**
   * Internal helper for executing unary RPC request/response exchanges.
   *
   * @param {string} verb HTTP verb (POST, GET)
   * @param {string} path Target RPC route path
   * @param {object} [options={}]
   * @param {Array<Header>} [options.headers=[]]
   * @param {Uint8Array|string|object} [options.body=null]
   * @param {number} [options.timeoutMs]
   * @returns {Promise<{ status: number, headers: Header[], body: Uint8Array }>}
   */
  async #request(verb, path, options = {}) {
    if (!this.connected || !this.#transport) {
      throw new Error("NoiseClient is not connected");
    }

    const timeout =
      typeof options.timeoutMs === "number" && options.timeoutMs > 0
        ? options.timeoutMs
        : this.#timeoutMs;

    let bodyBytes = new Uint8Array(0);
    if (options.body) {
      if (options.body instanceof Uint8Array) {
        bodyBytes = options.body;
      } else if (typeof options.body === "string") {
        bodyBytes = new TextEncoder().encode(options.body);
      } else {
        bodyBytes = new TextEncoder().encode(JSON.stringify(options.body));
      }
    }

    const reqHeaders = Array.isArray(options.headers) ? [...options.headers] : [];
    if (
      options.body &&
      !reqHeaders.some(
        (h) => (h.key || h.name || "").toLowerCase() === "content-type"
      )
    ) {
      reqHeaders.push(
        new Header({ key: "content-type", value: "application/json" })
      );
    }
    if (
      !reqHeaders.some(
        (h) => (h.key || h.name || "").toLowerCase() === "x-request-id"
      )
    ) {
      reqHeaders.push(
        new Header({ key: "x-request-id", value: crypto.randomUUID() })
      );
    }
    if (
      !reqHeaders.some(
        (h) => (h.key || h.name || "").toLowerCase() === "x-app-id"
      )
    ) {
      reqHeaders.push(new Header({ key: "x-app-id", value: "hatch-web" }));
    }

    return new Promise((resolve, reject) => {
      let timer = null;
      let streamId = null;
      const responseChunks = [];
      let appResponse = null;
      let finished = false;

      const cleanup = () => {
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
        if (streamId !== null) {
          this.#activeStreams.delete(streamId);
          if (this.#transport) {
            this.#transport.streams.delete(streamId);
          }
        }
      };

      if (timeout > 0) {
        timer = setTimeout(() => {
          if (finished) return;
          finished = true;
          cleanup();
          reject(
            new Error(`RPC request ${verb} ${path} timed out after ${timeout}ms`)
          );
        }, timeout);
        if (timer.unref) timer.unref();
      }

      const onFrame = (frame) => {
        if (finished) return;

        if (frame.reset) {
          finished = true;
          cleanup();
          reject(
            new Error(
              `RPC request ${verb} ${path} reset: ${
                frame.reset.reason || frame.reset.code
              }`
            )
          );
          return;
        }

        if (frame.response) {
          appResponse = frame.response;
          if (appResponse.body && appResponse.body.length > 0) {
            responseChunks.push(appResponse.body);
          }
          if (appResponse.end_body) {
            finished = true;
            cleanup();
            const fullBody = concat(...responseChunks);
            resolve({
              status: appResponse.status,
              headers: appResponse.headers || [],
              body: fullBody,
            });
            return;
          }
        }

        if (frame.body_chunk) {
          if (frame.body_chunk.data && frame.body_chunk.data.length > 0) {
            responseChunks.push(frame.body_chunk.data);
          }
          if (frame.body_chunk.end_body) {
            finished = true;
            cleanup();
            const fullBody = concat(...responseChunks);
            const status = appResponse ? appResponse.status : 200;
            const respHeaders = appResponse ? appResponse.headers || [] : [];
            resolve({
              status,
              headers: respHeaders,
              body: fullBody,
            });
            return;
          }
        }
      };

      const expectedStreamId = this.#transport.nextStreamId;
      streamId = expectedStreamId;
      this.#activeStreams.set(streamId, {
        reject: (err) => {
          if (finished) return;
          finished = true;
          cleanup();
          reject(err);
        },
      });

      this.#transport
        .sendRequest(verb, path, reqHeaders, bodyBytes, true, onFrame)
        .then((res) => {
          streamId = res.streamId;
        })
        .catch((err) => {
          if (finished) return;
          finished = true;
          cleanup();
          reject(err);
        });
    });
  }

  /**
   * Sends a prompt and streams full-duplex generation deltas.
   *
   * Assembles streaming BodyChunk frames, emits cumulative full text
   * to onDelta(cumulativeText) (matching the muse-driver.mjs contract for
   * muse-openai-shim.mjs), detects native tool calling events, and returns
   * { text, reply, toolCalls, finishReason }.
   *
   * @param {string} prompt Prompt text to send
   * @param {object} [options={}]
   * @param {(cumulativeText: string) => void} [options.onDelta] Cumulative text delta callback
   * @param {Array<object>} [options.tools] Client tool/function definitions
   * @param {Array<object|string>} [options.files] File attachments
   * @param {string} [options.model] Model identifier
   * @param {string} [options.chat] Existing conversation thread ID
   * @param {string} [options.system] System instructions prompt
   * @param {number} [options.timeoutMs] Generation timeout
   * @returns {Promise<{ text: string, reply: string, toolCalls: Array<object>, finishReason: string }>}
   */
  async chatStream(prompt, options = {}) {
    if (!this.connected || !this.#transport) {
      throw new Error("NoiseClient is not connected");
    }

    const {
      onDelta,
      tools,
      files,
      model,
      chat,
      system,
      timeoutMs = this.#timeoutMs,
    } = options;

    const payloadObj = {
      prompt,
      ...(system ? { system } : {}),
      ...(model ? { model } : {}),
      ...(chat ? { chat_id: chat } : {}),
      ...(Array.isArray(tools) && tools.length > 0 ? { tools } : {}),
      ...(Array.isArray(files) && files.length > 0 ? { files } : {}),
    };

    const reqHeaders = [
      new Header({ key: "content-type", value: "application/json" }),
      new Header({ key: "x-request-id", value: crypto.randomUUID() }),
      new Header({ key: "x-app-id", value: "hatch-web" }),
    ];

    return new Promise((resolve, reject) => {
      let timer = null;
      let streamId = null;
      let cumulativeText = "";
      const toolCalls = [];
      let finishReason = "stop";
      let isFinished = false;
      let textBuffer = "";

      const cleanup = () => {
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
        if (streamId !== null) {
          this.#activeStreams.delete(streamId);
          if (this.#transport) {
            this.#transport.streams.delete(streamId);
          }
        }
      };

      if (timeoutMs > 0) {
        timer = setTimeout(() => {
          if (isFinished) return;
          isFinished = true;
          cleanup();
          reject(new Error(`chatStream timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        if (timer.unref) timer.unref();
      }

      const emitDelta = () => {
        if (typeof onDelta === "function") {
          try {
            onDelta(cumulativeText);
          } catch {}
        }
      };

      const handleObject = (obj) => {
        if (!obj || typeof obj !== "object") return;

        // 1. Native tool calling: type: 'function_call'
        if (obj.type === "function_call" || obj.function_call) {
          const fc = obj.function_call || obj;
          const callId =
            fc.call_id ||
            fc.id ||
            `call_${Date.now().toString(36)}_${toolCalls.length}`;
          const name = fc.name;
          const args = fc.arguments ?? fc.args ?? {};
          toolCalls.push({
            id: callId,
            type: "function",
            function: {
              name,
              arguments:
                typeof args === "string" ? args : JSON.stringify(args),
            },
          });
          finishReason = "tool_calls";
          return;
        }

        // tool_calls array format
        if (Array.isArray(obj.tool_calls) || Array.isArray(obj.toolCalls)) {
          const calls = obj.tool_calls || obj.toolCalls;
          for (const c of calls) {
            const name = c.name || c?.function?.name;
            if (!name) continue;
            const callId =
              c.id ||
              c.call_id ||
              `call_${Date.now().toString(36)}_${toolCalls.length}`;
            const args = c.arguments ?? c?.function?.arguments ?? {};
            toolCalls.push({
              id: callId,
              type: "function",
              function: {
                name,
                arguments:
                  typeof args === "string" ? args : JSON.stringify(args),
              },
            });
          }
          if (toolCalls.length > 0) {
            finishReason = "tool_calls";
          }
          return;
        }

        // Choices delta format
        if (Array.isArray(obj.choices) && obj.choices[0]) {
          const choice = obj.choices[0];
          if (choice.delta) {
            if (choice.delta.content) {
              cumulativeText += choice.delta.content;
              emitDelta();
            }
            if (Array.isArray(choice.delta.tool_calls)) {
              for (const tc of choice.delta.tool_calls) {
                const name = tc?.function?.name || tc.name;
                if (name) {
                  toolCalls.push({
                    id:
                      tc.id ||
                      `call_${Date.now().toString(36)}_${toolCalls.length}`,
                    type: "function",
                    function: {
                      name,
                      arguments:
                        typeof tc?.function?.arguments === "string"
                          ? tc.function.arguments
                          : JSON.stringify(tc?.function?.arguments || {}),
                    },
                  });
                  finishReason = "tool_calls";
                }
              }
            }
          }
          if (choice.finish_reason) {
            finishReason = choice.finish_reason;
          }
          return;
        }

        // Direct content / delta fields
        const delta = obj.delta ?? obj.text ?? obj.content ?? obj.chunk;
        if (typeof delta === "string" && delta.length > 0) {
          cumulativeText += delta;
          emitDelta();
        }

        if (obj.finish_reason || obj.finishReason) {
          finishReason = obj.finish_reason || obj.finishReason;
        }
      };

      const parseEventPayload = (str) => {
        try {
          const obj = JSON.parse(str);
          handleObject(obj);
        } catch {
          // Plain text fallback
          cumulativeText += str;
          emitDelta();
        }
      };

      const processTextChunk = (rawText) => {
        textBuffer += rawText;

        // Check for SSE formatting
        if (textBuffer.includes("data:")) {
          const lines = textBuffer.split("\n");
          textBuffer = lines.pop() || "";

          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith(":")) continue;
            if (trimmed === "data: [DONE]") continue;
            if (trimmed.startsWith("data:")) {
              parseEventPayload(trimmed.slice(5).trim());
            }
          }
        } else {
          // Check for newline-delimited JSON objects
          const lines = textBuffer.split("\n");
          if (lines.length > 1) {
            textBuffer = lines.pop() || "";
            for (const line of lines) {
              const trimmed = line.trim();
              if (!trimmed) continue;
              parseEventPayload(trimmed);
            }
          } else {
            // Direct single JSON object
            if (textBuffer.startsWith("{") && textBuffer.endsWith("}")) {
              try {
                const obj = JSON.parse(textBuffer);
                textBuffer = "";
                handleObject(obj);
                return;
              } catch {}
            }
            // Incremental raw text if not JSON
            if (!textBuffer.startsWith("{")) {
              cumulativeText += textBuffer;
              textBuffer = "";
              emitDelta();
            }
          }
        }
      };

      const flushRemainder = () => {
        if (textBuffer.length > 0) {
          const trimmed = textBuffer.trim();
          if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
              handleObject(JSON.parse(trimmed));
            } catch {
              cumulativeText += textBuffer;
              emitDelta();
            }
          } else if (trimmed.startsWith("data:")) {
            parseEventPayload(trimmed.slice(5).trim());
          } else {
            cumulativeText += textBuffer;
            emitDelta();
          }
          textBuffer = "";
        }
      };

      const finalize = () => {
        if (isFinished) return;
        isFinished = true;
        cleanup();
        flushRemainder();

        if (toolCalls.length > 0 && finishReason === "stop") {
          finishReason = "tool_calls";
        }

        resolve({
          text: cumulativeText,
          reply: cumulativeText,
          toolCalls,
          finishReason,
        });
      };

      const onFrame = (frame) => {
        if (frame.reset) {
          if (isFinished) return;
          isFinished = true;
          cleanup();
          flushRemainder();

          if (frame.reset.code === ResetCode.CANCELLED) {
            resolve({
              text: cumulativeText,
              reply: cumulativeText,
              toolCalls,
              finishReason: "cancelled",
            });
          } else {
            reject(
              new Error(
                `Stream reset: ${frame.reset.reason || frame.reset.code}`
              )
            );
          }
          return;
        }

        if (frame.response) {
          if (frame.response.status >= 400) {
            if (isFinished) return;
            isFinished = true;
            cleanup();
            let errDetail = "";
            if (frame.response.body && frame.response.body.length > 0) {
              errDetail = new TextDecoder().decode(frame.response.body);
            }
            reject(
              new Error(
                `chatStream failed with status ${frame.response.status}: ${errDetail}`
              )
            );
            return;
          }

          if (frame.response.body && frame.response.body.length > 0) {
            const chunkStr = new TextDecoder().decode(frame.response.body);
            processTextChunk(chunkStr);
          }

          if (frame.response.end_body) {
            finalize();
            return;
          }
        }

        if (frame.body_chunk) {
          if (frame.body_chunk.data && frame.body_chunk.data.length > 0) {
            const chunkStr = new TextDecoder().decode(frame.body_chunk.data);
            processTextChunk(chunkStr);
          }

          if (frame.body_chunk.end_body) {
            finalize();
            return;
          }
        }
      };

      const cancelHandler = (cancelReason) => {
        if (isFinished) return;
        isFinished = true;
        cleanup();
        flushRemainder();
        resolve({
          text: cumulativeText,
          reply: cumulativeText,
          toolCalls,
          finishReason: "cancelled",
        });
      };

      const rejectHandler = (err) => {
        if (isFinished) return;
        isFinished = true;
        cleanup();
        reject(err);
      };

      const streamEntry = Object.assign(cancelHandler, {
        cancel: cancelHandler,
        reject: rejectHandler,
      });

      const expectedStreamId = this.#transport.nextStreamId;
      streamId = expectedStreamId;
      this.#activeStreams.set(streamId, streamEntry);

      this.#transport
        .sendRequest(
          "POST",
          "/chat/stream",
          reqHeaders,
          JSON.stringify(payloadObj),
          true,
          onFrame
        )
        .then((res) => {
          streamId = res.streamId;
          this.#activeStreams.set(streamId, streamEntry);
        })
        .catch((err) => {
          if (isFinished) return;
          isFinished = true;
          cleanup();
          reject(err);
        });
    });
  }

  /**
   * Registers native client tool/function schemas with Meta's edge gateway.
   * POST /client/register-capabilities
   *
   * @param {Array<object>} tools Array of tool definitions with name, description, parameters
   * @returns {Promise<{ ok: boolean, status: number, [key: string]: any }>}
   */
  async registerCapabilities(tools) {
    if (!Array.isArray(tools)) {
      throw new TypeError("registerCapabilities: tools must be an array");
    }

    const payload = {
      capabilities: tools,
    };

    const res = await this.#request("POST", "/client/register-capabilities", {
      body: payload,
    });

    if (res.status >= 400) {
      throw new Error(
        `registerCapabilities failed with HTTP ${res.status}: ${
          res.body ? new TextDecoder().decode(res.body) : ""
        }`
      );
    }

    let parsed = {};
    if (res.body && res.body.length > 0) {
      try {
        parsed = JSON.parse(new TextDecoder().decode(res.body));
      } catch {}
    }

    return {
      ok: true,
      status: res.status,
      ...parsed,
    };
  }

  /**
   * Sends the output of an executed client tool back into the conversation.
   * POST /client/invoke-result
   *
   * @param {string} callId Correlating tool invocation call_id
   * @param {object|string} result Result object or string output
   * @returns {Promise<{ ok: boolean, status: number, [key: string]: any }>}
   */
  async sendInvokeResult(callId, result) {
    if (!callId || typeof callId !== "string") {
      throw new TypeError("sendInvokeResult: callId must be a non-empty string");
    }

    const status =
      typeof result === "object" && result !== null && result.status
        ? String(result.status)
        : "success";

    let output = "";
    if (typeof result === "object" && result !== null && "output" in result) {
      output =
        typeof result.output === "string"
          ? result.output
          : JSON.stringify(result.output);
    } else if (typeof result === "string") {
      output = result;
    } else {
      output = JSON.stringify(result ?? {});
    }

    const payload = {
      call_id: callId,
      status,
      output,
    };

    const res = await this.#request("POST", "/client/invoke-result", {
      body: payload,
    });

    if (res.status >= 400) {
      throw new Error(
        `sendInvokeResult failed with HTTP ${res.status}: ${
          res.body ? new TextDecoder().decode(res.body) : ""
        }`
      );
    }

    let parsed = {};
    if (res.body && res.body.length > 0) {
      try {
        parsed = JSON.parse(new TextDecoder().decode(res.body));
      } catch {}
    }

    return {
      ok: true,
      status: res.status,
      ...parsed,
    };
  }

  /**
   * Keepalive heartbeat ping to Meta's daemon.
   * POST /api/ping
   *
   * @returns {Promise<boolean>} True if server responds with status < 400
   */
  async ping() {
    const res = await this.#request("POST", "/api/ping", {
      timeoutMs: 10000,
    });
    return res.status >= 200 && res.status < 400;
  }

  /**
   * Gracefully cancels an in-flight stream generation.
   * Sends both a Reset frame and POST /chat/cancel.
   *
   * @param {bigint|number} streamId Target stream to cancel
   * @param {string} [reason="CANCELLED"] Human-readable cancellation reason
   * @returns {Promise<void>}
   */
  async cancel(streamId, reason = "CANCELLED") {
    if (streamId === undefined || streamId === null) {
      const activeIds = Array.from(this.#activeStreams.keys());
      for (const id of activeIds) {
        await this.cancel(id, reason);
      }
      return;
    }

    const sid = typeof streamId === "bigint" ? streamId : BigInt(streamId);

    // 1. Settle local in-flight stream immediately if active
    const localCanceller = this.#activeStreams.get(sid);
    if (typeof localCanceller === "function") {
      this.#activeStreams.delete(sid);
      localCanceller(reason);
    }

    // 2. Send Reset frame immediately to peer
    if (this.#transport) {
      try {
        await this.#transport.cancelStream(sid, reason);
      } catch {}
    }

    // 3. Transmit POST /chat/cancel RPC route frame
    if (this.connected && this.#transport) {
      try {
        await this.#request("POST", "/chat/cancel", {
          body: { stream_id: sid.toString(), reason },
          timeoutMs: 5000,
        });
      } catch {}
    }
  }

  /**
   * Retrieves message history window for a conversation thread.
   * GET /chat/history-window?chat_id=...&max=...
   *
   * @param {string} [chatId] Conversation thread ID
   * @param {number} [max=50] Maximum number of messages to fetch
   * @returns {Promise<{ messages: Array<object>, [key: string]: any }>}
   */
  async historyWindow(chatId = "", max = 50) {
    let path = "/chat/history-window";
    const query = [];
    if (chatId) query.push(`chat_id=${encodeURIComponent(chatId)}`);
    if (typeof max === "number" && max > 0) {
      query.push(`max=${encodeURIComponent(max)}`);
    }
    if (query.length > 0) {
      path += `?${query.join("&")}`;
    }

    const res = await this.#request("GET", path);
    if (res.status >= 400) {
      throw new Error(
        `historyWindow failed with HTTP ${res.status}: ${
          res.body ? new TextDecoder().decode(res.body) : ""
        }`
      );
    }

    if (res.body && res.body.length > 0) {
      try {
        return JSON.parse(new TextDecoder().decode(res.body));
      } catch {}
    }

    return { messages: [] };
  }

  /**
   * Cleanly closes the Noise client connection:
   * - Stops the keep-alive ping timer
   * - Resets transport decoder and wipes cipher states
   * - Destroys initiator state machine
   * - Closes the WebSocket connection
   *
   * @returns {Promise<void>}
   */
  async close() {
    this.#closed = true;
    this.#connected = false;
    this.#remoteStaticPublicKey = null;
    const closeError = new Error("NoiseClient was closed");
    const activeHandlers = Array.from(this.#activeStreams.values());
    this.#activeStreams.clear();
    for (const handler of activeHandlers) {
      try {
        if (typeof handler?.reject === "function") {
          handler.reject(closeError);
        } else if (typeof handler === "function") {
          handler(closeError);
        }
      } catch {}
    }

    if (this.#pingTimer) {
      clearInterval(this.#pingTimer);
      this.#pingTimer = null;
    }

    if (this.#transport) {
      try {
        this.#transport.decoder?.reset();
      } catch {}
      try {
        this.#transport.txCipher?.zeroize();
      } catch {}
      try {
        this.#transport.rxCipher?.zeroize();
      } catch {}
      this.#transport = null;
    }

    if (this.#initiator) {
      try {
        this.#initiator.destroy();
      } catch {}
      this.#initiator = null;
    }

    if (this.#ws) {
      try {
        if (
          this.#ws.readyState === 0 /* CONNECTING */ ||
          this.#ws.readyState === 1 /* OPEN */
        ) {
          this.#ws.close(1000, "Normal Closure");
        }
      } catch {}
      this.#ws = null;
    }
  }
}

export default NoiseClient;
