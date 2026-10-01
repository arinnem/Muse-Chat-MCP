/**
 * lib/noise/transport.mjs
 *
 * Framing, Reassembly, and Transport Multiplexer for Meta Muse Noise protocol.
 * Implements:
 * - NoiseFrameDecoder: chunk reassembly, single-chunk fast path, DoS protections,
 *   budget enforcement (65,489 B / chunk, 16 max concurrent assemblies, 16 MiB total budget, 60s expiration).
 * - NoiseTransport: multiplexes streams (monotonic BigInt stream_id), handles bidirectional
 *   encryption (txCipher) and decryption (rxCipher), ServiceRequest/ServiceResponse wrapping,
 *   and payload splitting.
 *
 * Pure Node 20+ built-ins. ZERO external dependencies.
 */

import crypto from "node:crypto";
import { concat } from "./crypto.mjs";
import {
  NoiseTransportFrame,
  ServiceRequest,
  ServiceResponse,
  ServiceFrame,
  ApplicationRequest,
  ApplicationResponse,
  BodyChunk,
  Reset,
  ServiceType,
  ResetCode,
  encodeNoiseTransportFrame,
  decodeNoiseTransportFrame,
  encodeServiceRequest,
  decodeServiceRequest,
  encodeServiceResponse,
  decodeServiceResponse,
  encodeServiceFrame,
  decodeServiceFrame,
} from "./proto.mjs";

/** Max payload size per transport frame chunk (65,489 bytes). */
export const MAX_PAYLOAD_CHUNK_SIZE = 65489;

/** Maximum allowed chunks in a multi-chunk frame assembly. */
export const MAX_TOTAL_CHUNKS = 256;

/** Maximum concurrent pending assemblies to prevent memory exhaustion DoS. */
export const MAX_CONCURRENT_ASSEMBLIES = 16;

/** Maximum cumulative bytes per frame assembly (16 MiB = 16,777,216 bytes). */
export const MAX_ASSEMBLY_BYTES = 16 * 1024 * 1024;

/** Default stale assembly expiration timeout in milliseconds (60 seconds). */
export const DEFAULT_ASSEMBLY_TIMEOUT_MS = 60000;

/** Empty associated data buffer for transport phase AEAD operations. */
const EMPTY_AD = new Uint8Array(0);

/**
 * NoiseFrameDecoder reassembles chunked transport frames and enforces memory safety budgets.
 */
export class NoiseFrameDecoder {
  #assemblies = new Map();
  #timeoutMs = DEFAULT_ASSEMBLY_TIMEOUT_MS;
  #maxAssemblyBytes = MAX_ASSEMBLY_BYTES;

  constructor(options = {}) {
    if (typeof options.timeoutMs === "number" && options.timeoutMs > 0) {
      this.#timeoutMs = options.timeoutMs;
    }
    if (typeof options.maxAssemblyBytes === "number" && options.maxAssemblyBytes > 0) {
      this.#maxAssemblyBytes = options.maxAssemblyBytes;
    }
  }

  get timeoutMs() {
    return this.#timeoutMs;
  }

  get maxAssemblyBytes() {
    return this.#maxAssemblyBytes;
  }

  get pendingCount() {
    return this.#assemblies.size;
  }

  hasAssembly(chunkId) {
    const id = typeof chunkId === "bigint" ? chunkId : BigInt(chunkId);
    return this.#assemblies.has(id);
  }

  reset() {
    this.#assemblies.clear();
  }

  /**
   * Purges uncompleted assemblies older than timeoutMs.
   * @param {number} [now=Date.now()]
   */
  purgeExpired(now = Date.now()) {
    for (const [id, entry] of this.#assemblies) {
      if (now - entry.createdAt > this.#timeoutMs) {
        this.#assemblies.delete(id);
      }
    }
  }

  #purgeExpired(now = Date.now()) {
    this.purgeExpired(now);
  }

  /**
   * Pushes a serialized or decoded NoiseTransportFrame into the reassembly pipeline.
   * @param {Uint8Array|NoiseTransportFrame|object} chunk
   * @returns {Uint8Array|null} Complete reassembled payload when ready, or null if pending.
   */
  push(chunk) {
    let frame;
    if (chunk instanceof Uint8Array) {
      frame = decodeNoiseTransportFrame(chunk);
    } else if (chunk && typeof chunk === "object") {
      frame = chunk;
    } else {
      throw new TypeError("NoiseFrameDecoder: chunk must be Uint8Array or NoiseTransportFrame object");
    }

    const rawId = frame.chunk_id !== undefined ? frame.chunk_id : frame.chunkId;
    const chunkId = rawId !== undefined ? (typeof rawId === "bigint" ? rawId : BigInt(rawId)) : 0n;

    const rawIndex = frame.chunk_index !== undefined ? frame.chunk_index : frame.chunkIndex;
    const chunkIndex = rawIndex !== undefined ? Number(rawIndex) : 0;

    const rawTotal = frame.total_chunks !== undefined ? frame.total_chunks : frame.totalChunks;
    const totalChunks = rawTotal !== undefined ? Number(rawTotal) : 1;

    let payload = frame.payload;
    if (!payload) {
      payload = new Uint8Array(0);
    } else if (!(payload instanceof Uint8Array)) {
      payload = new Uint8Array(payload);
    }

    // 1. Validate chunkId inside int64 bounds
    if (chunkId < -(1n << 63n) || chunkId > (1n << 63n) - 1n) {
      throw new RangeError(`chunkId outside int64 range: ${chunkId}`);
    }

    // 2. Validate totalChunks range [1, 256]
    if (totalChunks < 1 || totalChunks > MAX_TOTAL_CHUNKS) {
      throw new RangeError(`invalid totalChunks: ${totalChunks}`);
    }

    // 3. Validate chunkIndex range [0, totalChunks)
    if (chunkIndex < 0 || chunkIndex >= totalChunks) {
      throw new RangeError(`chunkIndex ${chunkIndex} out of range [0, ${totalChunks})`);
    }

    // 4. Validate max payload chunk size (65,489 bytes)
    if (payload.length > MAX_PAYLOAD_CHUNK_SIZE) {
      throw new Error(`payload too large for noise frame (${payload.length} bytes)`);
    }

    // 5. Purge expired assemblies
    this.#purgeExpired();

    // 6. Fast single-chunk bypass
    if (totalChunks === 1) {
      if (this.#assemblies.has(chunkId)) {
        const existing = this.#assemblies.get(chunkId);
        if (existing.total !== 1) {
          this.#assemblies.delete(chunkId);
          throw new Error(`inconsistent totalChunks for chunkId: expected ${existing.total}, got 1`);
        }
      }
      return payload;
    }

    // 7. Multi-chunk reassembly
    if (!this.#assemblies.has(chunkId)) {
      if (this.#assemblies.size >= MAX_CONCURRENT_ASSEMBLIES) {
        throw new Error("too many pending noise frame assemblies");
      }
      const now = Date.now();
      this.#assemblies.set(chunkId, {
        chunks: new Map(),
        total: totalChunks,
        totalBytes: 0,
        createdAt: now,
        lastUpdated: now,
      });
    }

    const assembly = this.#assemblies.get(chunkId);

    // Inconsistent total_chunks check
    if (assembly.total !== totalChunks) {
      this.#assemblies.delete(chunkId);
      throw new Error(`inconsistent totalChunks for chunkId: expected ${assembly.total}, got ${totalChunks}`);
    }

    // Duplicate chunk_index check
    if (assembly.chunks.has(chunkIndex)) {
      this.#assemblies.delete(chunkId);
      throw new Error(`duplicate chunkIndex ${chunkIndex}`);
    }

    // Update cumulative byte count and check budget
    assembly.lastUpdated = Date.now();
    assembly.totalBytes += payload.length;
    if (assembly.totalBytes > this.#maxAssemblyBytes) {
      this.#assemblies.delete(chunkId);
      throw new Error("assembly exceeded byte budget");
    }

    // Record chunk
    assembly.chunks.set(chunkIndex, payload);

    // If more chunks pending, return null
    if (assembly.chunks.size < assembly.total) {
      return null;
    }

    // Assembly complete! Purge from map and concatenate in index order
    this.#assemblies.delete(chunkId);
    const chunkList = [];
    for (let i = 0; i < assembly.total; i++) {
      const piece = assembly.chunks.get(i);
      if (!piece) {
        throw new Error(`missing chunk ${i}/${assembly.total}`);
      }
      chunkList.push(piece);
    }

    return concat(...chunkList);
  }

  /**
   * Alias for push() to match reference decoder interface.
   * @param {Uint8Array|NoiseTransportFrame|object} chunk
   * @returns {Uint8Array|null}
   */
  decode(chunk) {
    return this.push(chunk);
  }
}

/**
 * NoiseTransport handles bidirectional encrypted frame transmission and stream multiplexing.
 */
export class NoiseTransport {
  #txCipher;
  #rxCipher;
  #sendRaw;
  #decoder;
  #nextStreamId = 1n;
  #streams = new Map();

  /**
   * @param {import("./crypto.mjs").CipherState} txCipher CipherState for outgoing frames
   * @param {import("./crypto.mjs").CipherState} rxCipher CipherState for incoming frames
   * @param {((bytes: Uint8Array) => Promise<void>|void)|null} [sendRaw=null] Outgoing raw bytes transport callback
   * @param {object} [options={}]
   */
  constructor(txCipher, rxCipher, sendRaw = null, options = {}) {
    this.#txCipher = txCipher;
    this.#rxCipher = rxCipher;
    this.#sendRaw = typeof sendRaw === "function" ? sendRaw : null;
    this.#decoder = options.decoder instanceof NoiseFrameDecoder ? options.decoder : new NoiseFrameDecoder(options);
  }

  get txCipher() {
    return this.#txCipher;
  }

  get rxCipher() {
    return this.#rxCipher;
  }

  get sendRaw() {
    return this.#sendRaw;
  }

  set sendRaw(fn) {
    this.#sendRaw = typeof fn === "function" ? fn : null;
  }

  get decoder() {
    return this.#decoder;
  }

  get nextStreamId() {
    return this.#nextStreamId;
  }

  get streams() {
    return this.#streams;
  }

  /**
   * Registers callback handlers for an active stream ID.
   * @param {bigint|number} streamId
   * @param {(frame: ServiceFrame) => void} onFrame
   * @param {((err: Error) => void)|null} [onError=null]
   * @returns {bigint} streamId
   */
  registerStream(streamId, onFrame, onError = null) {
    const sid = typeof streamId === "bigint" ? streamId : BigInt(streamId);
    this.#streams.set(sid, { onFrame, onError });
    return sid;
  }

  /**
   * Cancels an active stream by sending a Reset frame and removing the stream entry.
   * @param {bigint|number} streamId
   * @param {string} [reason="CANCELLED"]
   * @returns {Promise<Uint8Array[]>}
   */
  async cancelStream(streamId, reason = "CANCELLED") {
    const sid = typeof streamId === "bigint" ? streamId : BigInt(streamId);
    this.#streams.delete(sid);
    const reset = new Reset({
      code: ResetCode.CANCELLED,
      reason: typeof reason === "string" ? reason : "CANCELLED",
    });
    const frame = new ServiceFrame({
      stream_id: sid,
      reset,
    });
    return this.sendFrame(sid, frame);
  }

  /**
   * Encapsulates, serializes, encrypts, and sends a ServiceFrame.
   * Splits into multiple NoiseTransportFrames if ciphertext exceeds 65,489 bytes.
   *
   * @param {bigint|number} streamId
   * @param {ServiceFrame|object} frame
   * @returns {Promise<Uint8Array[]>} Array of encoded raw frames dispatched
   */
  async sendFrame(streamId, frame) {
    const sid = typeof streamId === "bigint" ? streamId : BigInt(streamId);
    let sFrame;
    if (frame instanceof ServiceFrame) {
      sFrame = frame;
      sFrame.stream_id = sid;
    } else {
      sFrame = new ServiceFrame({ ...frame, stream_id: sid });
    }

    const frameBytes = encodeServiceFrame(sFrame);
    const req = new ServiceRequest({
      service: ServiceType.SERVICE_DAEMON,
      payload: frameBytes,
    });
    const reqBytes = encodeServiceRequest(req);

    const rawFrames = [];
    const totalChunks = Math.max(1, Math.ceil(reqBytes.length / MAX_PAYLOAD_CHUNK_SIZE));
    if (totalChunks > MAX_TOTAL_CHUNKS) {
      throw new Error(`payload too large for noise framing (${reqBytes.length} bytes, ${totalChunks} chunks > 256)`);
    }

    // Generate random signed 64-bit chunk_id
    const u32 = crypto.getRandomValues(new Uint32Array(2));
    const chunkId = BigInt.asIntN(64, BigInt(u32[0]) | (BigInt(u32[1]) << 32n));

    if (reqBytes.length === 0) {
      const transportFrame = new NoiseTransportFrame({
        chunk_id: chunkId,
        chunk_index: 0,
        total_chunks: 1,
        payload: new Uint8Array(0),
      });
      const encoded = encodeNoiseTransportFrame(transportFrame);
      const ciphertext = await this.#txCipher.encryptWithAd(EMPTY_AD, encoded);
      rawFrames.push(ciphertext);
      if (this.#sendRaw) {
        await this.#sendRaw(ciphertext);
      }
    } else {
      for (let i = 0; i < totalChunks; i++) {
        const start = i * MAX_PAYLOAD_CHUNK_SIZE;
        const end = Math.min(start + MAX_PAYLOAD_CHUNK_SIZE, reqBytes.length);
        const slice = reqBytes.subarray(start, end);
        const transportFrame = new NoiseTransportFrame({
          chunk_id: chunkId,
          chunk_index: i,
          total_chunks: totalChunks,
          payload: slice,
        });
        const encoded = encodeNoiseTransportFrame(transportFrame);
        const ciphertext = await this.#txCipher.encryptWithAd(EMPTY_AD, encoded);
        rawFrames.push(ciphertext);
        if (this.#sendRaw) {
          await this.#sendRaw(ciphertext);
        }
      }
    }

    return rawFrames;
  }

  /**
   * Helper to allocate a monotonic stream ID and send an ApplicationRequest.
   *
   * @param {string} verb HTTP verb (e.g. "POST", "GET")
   * @param {string} path Target RPC path (e.g. "/chat/stream")
   * @param {Array<import("./proto.mjs").Header|object>} [headers=[]]
   * @param {Uint8Array|string} [body=new Uint8Array(0)]
   * @param {boolean} [endBody=true]
   * @param {((frame: ServiceFrame) => void)|null} [onFrame=null]
   * @returns {Promise<{ streamId: bigint, frames: Uint8Array[] }>}
   */
  async sendRequest(verb, path, headers = [], body = new Uint8Array(0), endBody = true, onFrame = null) {
    const streamId = this.#nextStreamId++;
    if (typeof onFrame === "function") {
      this.registerStream(streamId, onFrame);
    }

    const bodyBytes = typeof body === "string" ? new TextEncoder().encode(body) : body;
    const appReq = new ApplicationRequest({
      verb,
      path,
      headers,
      body: bodyBytes,
      end_body: endBody,
    });
    const frame = new ServiceFrame({
      stream_id: streamId,
      request: appReq,
    });

    const frames = await this.sendFrame(streamId, frame);
    return { streamId, frames };
  }

  /**
   * Handles incoming binary frames from the network or loopback:
   * 1. Decrypts raw bytes with rxCipher
   * 2. Reassembles chunks via NoiseFrameDecoder
   * 3. Deserializes ServiceResponse and extracts ServiceFrame
   * 4. Dispatches to registered stream callback if any
   *
   * @param {Uint8Array} rawBytes
   * @returns {Promise<ServiceFrame|null>} Reconstructed ServiceFrame, or null if awaiting more chunks
   */
  async handleIncoming(rawBytes) {
    if (!rawBytes || rawBytes.length === 0) {
      return null;
    }

    // 1. Decrypt ciphertext FIRST with rxCipher
    const decrypted = await this.#rxCipher.decryptWithAd(EMPTY_AD, rawBytes);

    // 2. Reassemble chunks via NoiseFrameDecoder
    const assembled = this.#decoder.push(decrypted);
    if (assembled === null) {
      return null; // More chunks pending
    }

    // Empty ServiceResponse payload guard (tag 1 length 0)
    if (assembled.length === 2 && assembled[0] === 0x0a && assembled[1] === 0x00) {
      throw new Error("empty ServiceResponse payload");
    }

    // 3. Deserialization: check ServiceResponse envelope first, then ServiceRequest, then raw ServiceFrame
    let serviceFrame = null;

    if (assembled.length > 0 && assembled[0] === 0x0a) {
      try {
        const resp = decodeServiceResponse(assembled);
        if (resp && resp.payload && resp.payload.length > 0) {
          serviceFrame = decodeServiceFrame(resp.payload);
        } else if (resp && resp.payload && resp.payload.length === 0) {
          throw new Error("empty ServiceResponse payload");
        }
      } catch (err) {
        if (err.message === "empty ServiceResponse payload") throw err;
      }
    }

    if (!serviceFrame) {
      try {
        const req = decodeServiceRequest(assembled);
        if (req && req.payload && req.payload.length > 0) {
          serviceFrame = decodeServiceFrame(req.payload);
        }
      } catch {}
    }

    if (!serviceFrame) {
      serviceFrame = decodeServiceFrame(assembled);
    }

    // 4. Dispatch to registered stream handler
    const sid = serviceFrame.stream_id;
    const stream = this.#streams.get(sid);
    if (stream && typeof stream.onFrame === "function") {
      try {
        stream.onFrame(serviceFrame);
      } catch (err) {
        if (typeof stream.onError === "function") {
          stream.onError(err);
        }
      }
    }

    return serviceFrame;
  }

  /**
   * Alias for handleIncoming() for reference compatibility.
   * @param {Uint8Array} rawBytes
   * @returns {Promise<ServiceFrame|null>}
   */
  async decryptFrame(rawBytes) {
    return this.handleIncoming(rawBytes);
  }

  /**
   * Convenience helper to encrypt and send a body chunk on an active stream.
   * @param {{ streamId: bigint|number, data: Uint8Array|string, endBody?: boolean }} opts
   * @returns {Promise<Uint8Array[]>}
   */
  async encryptBodyChunk(opts) {
    const dataBytes = typeof opts.data === "string" ? new TextEncoder().encode(opts.data) : opts.data;
    const bodyChunk = new BodyChunk({
      data: dataBytes,
      end_body: Boolean(opts.endBody),
    });
    const frame = new ServiceFrame({
      stream_id: opts.streamId,
      body_chunk: bodyChunk,
    });
    return this.sendFrame(opts.streamId, frame);
  }

  /**
   * Convenience helper to encrypt and send a reset frame on an active stream.
   * @param {{ streamId: bigint|number, reason?: string, code?: number }} opts
   * @returns {Promise<Uint8Array[]>}
   */
  async encryptReset(opts) {
    const reset = new Reset({
      code: opts.code ?? ResetCode.CANCELLED,
      reason: opts.reason ?? "",
    });
    const frame = new ServiceFrame({
      stream_id: opts.streamId,
      reset,
    });
    return this.sendFrame(opts.streamId, frame);
  }
}
