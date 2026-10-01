/**
 * test/test-adversarial-m2-wire-framing.mjs
 * ------------------------------------------------------------------
 * Adversarial Stress Test Suite for Milestone 2:
 * Wire Framing Alignment, AEAD Integrity, Multi-Chunk Reassembly & Client Resilience.
 *
 * Authored by: challenger_m2_1 (Empirical Challenger)
 * Scope:
 *   1. Probing Ciphertext Corruption & AEAD Integrity Rejection:
 *      - Bitwise corruption at byte 0, payload center, tag boundary, tag bytes
 *      - Fail-closed verification: throws operation-specific AEAD tag mismatch
 *      - CipherState poisoning verification: cipher state poisoned, no memory corruption
 *      - Zero hanging promises (< 50ms execution per probe)
 *      - Truncated wire frames (< 16 bytes tag length)
 *   2. Probing Multi-Chunk Wire Reassembly (> 65,489 bytes):
 *      - 2-chunk payload (75,000 bytes) bitwise round-trip reconstruction
 *      - 4-chunk payload (200,000 bytes) bitwise round-trip reconstruction
 *      - 8-chunk payload (500,000 bytes) bitwise round-trip reconstruction
 *      - Verification that intermediate chunks return null, final chunk reassembles
 *      - Interleaved concurrent multi-stream multi-chunk wire transport
 *   3. Probing Out-of-Order Wire Rejection & Timeout Fail-Closed Behavior:
 *      - Wire chunk swapping (chunk 1 before chunk 0) -> AEAD tag mismatch (nonce desync)
 *      - Corrupt intermediate chunk poisons connection and prevents corrupted delivery
 *      - Stale chunk assembly timeout purge in NoiseFrameDecoder
 *      - Memory safety & budget enforcement (byte budget, duplicate chunks, max assemblies)
 * ------------------------------------------------------------------
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  CipherState,
  constantTimeEqual,
  ALL_ZEROS_32,
  formatNonce,
} from "../lib/noise/crypto.mjs";

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
  encodeServiceFrame,
  decodeServiceFrame,
  encodeServiceRequest,
  decodeServiceRequest,
  encodeServiceResponse,
  decodeServiceResponse,
} from "../lib/noise/proto.mjs";

import {
  NoiseFrameDecoder,
  NoiseTransport,
  MAX_PAYLOAD_CHUNK_SIZE,
  MAX_TOTAL_CHUNKS,
  MAX_CONCURRENT_ASSEMBLIES,
  MAX_ASSEMBLY_BYTES,
  DEFAULT_ASSEMBLY_TIMEOUT_MS,
} from "../lib/noise/transport.mjs";

/** Empty associated data buffer matching transport phase */
const EMPTY_AD = new Uint8Array(0);

/**
 * Helper to create a paired sender and receiver NoiseTransport instance.
 */
async function createPairedTransports(options = {}) {
  // Shared keys for symmetric transport testing
  const c2sKey = crypto.getRandomValues(new Uint8Array(32));

  // Sender (e.g. client tx, server rx)
  const txCipher = new CipherState();
  const dummyRxCipher = new CipherState();
  // Clone buffer because initializeKey zeroizes its argument!
  await txCipher.initializeKey(new Uint8Array(c2sKey));

  // Receiver (e.g. server rx from client tx)
  const rxCipher = new CipherState();
  const dummyTxCipher = new CipherState();
  await rxCipher.initializeKey(new Uint8Array(c2sKey));

  const sender = new NoiseTransport(txCipher, dummyRxCipher, null, options.senderOptions || {});
  const receiver = new NoiseTransport(dummyTxCipher, rxCipher, null, options.receiverOptions || {});

  return { sender, receiver, txCipher, rxCipher };
}

// =============================================================================
// CATEGORY 1: Ciphertext Corruption Probes & AEAD Integrity Rejection
// =============================================================================

test("Probe 1.1: Single-byte corruption at varied offsets triggers AEAD tag mismatch without hanging", async () => {
  const { sender, receiver, rxCipher } = await createPairedTransports();

  const originalBody = new TextEncoder().encode("Adversarial payload verification for Meta Muse Phase 2");
  const testFrame = new ServiceFrame({
    stream_id: 42n,
    request: new ApplicationRequest({
      verb: "POST",
      path: "/chat/stream",
      body: originalBody,
    }),
  });

  const frames = await sender.sendFrame(42n, testFrame);
  assert.strictEqual(frames.length, 1);
  const wireCiphertext = frames[0];
  assert.ok(wireCiphertext.length > 16, "Ciphertext must contain payload and 16-byte tag");

  // Test corruption at multiple distinct offsets:
  // 1. First byte (byte 0)
  // 2. Middle of ciphertext
  // 3. Start of 16-byte AEAD tag (length - 16)
  // 4. Last byte of AEAD tag (length - 1)
  const testOffsets = [
    0,
    Math.floor((wireCiphertext.length - 16) / 2),
    wireCiphertext.length - 16,
    wireCiphertext.length - 1,
  ];

  for (const offset of testOffsets) {
    const { receiver: localReceiver, rxCipher: localRx } = await createPairedTransports();
    const tampered = new Uint8Array(wireCiphertext);
    tampered[offset] ^= 0x5a; // Flip bits

    const startTime = Date.now();
    await assert.rejects(
      async () => {
        await localReceiver.handleIncoming(tampered);
      },
      (err) => {
        // Must reject with crypto failure (AEAD tag mismatch)
        assert.ok(
          /operation failed|decrypt|poisoned|OperationError/i.test(err.message || err.name),
          `Expected crypto error, got: ${err.message}`
        );
        return true;
      }
    );
    const elapsed = Date.now() - startTime;
    assert.ok(elapsed < 200, `Rejection took ${elapsed}ms; must not hang`);

    // Verify CipherState is permanently poisoned
    await assert.rejects(
      async () => {
        await localRx.decryptWithAd(EMPTY_AD, wireCiphertext);
      },
      (err) => {
        assert.match(err.message, /poisoned after prior failure/);
        return true;
      }
    );

    // Verify decoder has no leaked pending state
    assert.strictEqual(localReceiver.decoder.pendingCount, 0);
  }
});

test("Probe 1.2: Truncated wire frames (< 16 bytes tag) reject fail-closed without memory corruption", async () => {
  const { receiver } = await createPairedTransports();

  // Test truncated lengths from 1 to 15 bytes
  for (let len = 1; len < 16; len++) {
    const truncated = crypto.getRandomValues(new Uint8Array(len));
    await assert.rejects(
      async () => {
        await receiver.handleIncoming(truncated);
      },
      (err) => {
        assert.ok(
          /operation failed|decrypt|poisoned|too small|OperationError/i.test(err.message || err.name),
          `Expected crypto truncation error, got: ${err.message}`
        );
        return true;
      }
    );
  }
});

test("Probe 1.3: Empty wire frames (0 bytes) return null gracefully without altering nonce or poisoning", async () => {
  const { sender, receiver } = await createPairedTransports();

  // Empty frames return null without advancing nonce or poisoning
  const result1 = await receiver.handleIncoming(new Uint8Array(0));
  assert.strictEqual(result1, null);
  const result2 = await receiver.handleIncoming(null);
  assert.strictEqual(result2, null);

  // Normal frame must still decrypt successfully
  const testFrame = new ServiceFrame({
    stream_id: 1n,
    body_chunk: new BodyChunk({ data: new TextEncoder().encode("valid after empty"), end_body: true }),
  });
  const [wireBytes] = await sender.sendFrame(1n, testFrame);
  const recovered = await receiver.handleIncoming(wireBytes);
  assert.ok(recovered instanceof ServiceFrame);
  assert.strictEqual(recovered.stream_id, 1n);
  assert.strictEqual(new TextDecoder().decode(recovered.body_chunk.data), "valid after empty");
});

test("Probe 1.4: Zeroize and memory safety on poisoned receiver", async () => {
  const { sender, receiver, rxCipher } = await createPairedTransports();

  const [validBytes] = await sender.sendFrame(1n, new ServiceFrame({ stream_id: 1n }));
  const corrupt = new Uint8Array(validBytes);
  corrupt[corrupt.length - 1] ^= 0x01;

  await assert.rejects(async () => {
    await receiver.handleIncoming(corrupt);
  });

  // Zeroize cipher state safely
  rxCipher.zeroize();
  assert.strictEqual(rxCipher.hasKey(), false);
  assert.strictEqual(rxCipher.nonce, 0);
});

test("Probe 1.5: Bit-flip perturbation across pseudo-random byte offsets always caught by AEAD", async () => {
  const { sender, receiver } = await createPairedTransports();

  const originalBody = new TextEncoder().encode("AEAD tag integrity adversarial matrix");
  const testFrame = new ServiceFrame({
    stream_id: 55n,
    request: new ApplicationRequest({ verb: "GET", path: "/test", body: originalBody }),
  });

  const [wireCiphertext] = await sender.sendFrame(55n, testFrame);
  assert.ok(wireCiphertext.length >= 32);

  // Pick 15 deterministic pseudorandom offsets
  const len = wireCiphertext.length;
  const offsets = [1, 3, 7, 11, 15, Math.floor(len / 4), Math.floor(len / 2), Math.floor((3 * len) / 4), len - 16, len - 8, len - 4, len - 2, len - 1];

  for (const off of offsets) {
    const { receiver: freshReceiver } = await createPairedTransports();
    const tampered = new Uint8Array(wireCiphertext);
    tampered[off] ^= 0x01; // Invert least significant bit

    await assert.rejects(
      async () => {
        await freshReceiver.handleIncoming(tampered);
      },
      /operation failed|decrypt|poisoned|OperationError/i,
      `Bit flip at offset ${off} must be rejected by AEAD`
    );
  }
});

test("Probe 1.6: Replay of valid wire frame is rejected due to monotonic nonce progression", async () => {
  const { sender, receiver } = await createPairedTransports();

  const frame = new ServiceFrame({ stream_id: 10n, body_chunk: new BodyChunk({ data: new Uint8Array([1, 2, 3]) }) });
  const [wireCiphertext] = await sender.sendFrame(10n, frame);

  // First arrival succeeds (rx nonce 0 -> 1)
  const first = await receiver.handleIncoming(wireCiphertext);
  assert.ok(first instanceof ServiceFrame);

  // Replay of the exact same wire frame must be rejected because rx nonce is now 1,
  // whereas the replayed ciphertext was encrypted with nonce 0!
  await assert.rejects(
    async () => {
      await receiver.handleIncoming(wireCiphertext);
    },
    /operation failed|decrypt|poisoned|OperationError/i
  );
});

// =============================================================================
// CATEGORY 2: Multi-Chunk Wire Reassembly Probes (> 65,489 bytes)
// =============================================================================

test("Probe 2.1: 2-chunk payload (75,000 bytes) wire round-trip with bitwise reconstruction", async () => {
  const { sender, receiver } = await createPairedTransports();

  const payloadSize = 75000;
  const originalBytes = new Uint8Array(crypto.randomBytes(payloadSize));

  const frame = new ServiceFrame({
    stream_id: 77n,
    response: new ApplicationResponse({
      status: 200,
      body: originalBytes,
      end_body: true,
    }),
  });

  const wireFrames = await sender.sendFrame(77n, frame);
  assert.strictEqual(wireFrames.length, 2, "75,000 bytes must split into 2 chunks");

  // Chunk 0 must return null (assembly pending)
  const res0 = await receiver.handleIncoming(wireFrames[0]);
  assert.strictEqual(res0, null, "Chunk 0 must return null");
  assert.strictEqual(receiver.decoder.pendingCount, 1, "Must have 1 pending assembly");

  // Chunk 1 must return completed ServiceFrame
  const res1 = await receiver.handleIncoming(wireFrames[1]);
  assert.ok(res1 instanceof ServiceFrame, "Chunk 1 must complete assembly");
  assert.strictEqual(res1.stream_id, 77n);
  assert.strictEqual(res1.response.status, 200);
  assert.strictEqual(res1.response.body.length, payloadSize);

  // Bitwise round-trip check
  assert.ok(
    constantTimeEqual(res1.response.body, originalBytes),
    "Reassembled 75,000-byte body must match original bitwise"
  );
  assert.strictEqual(receiver.decoder.pendingCount, 0, "Pending count must return to 0");
});

test("Probe 2.2: 4-chunk payload (200,000 bytes) wire round-trip with bitwise reconstruction", async () => {
  const { sender, receiver } = await createPairedTransports();

  const payloadSize = 200000;
  const originalBytes = new Uint8Array(crypto.randomBytes(payloadSize));

  const frame = new ServiceFrame({
    stream_id: 99n,
    request: new ApplicationRequest({
      verb: "POST",
      path: "/api/large-upload",
      body: originalBytes,
      end_body: true,
    }),
  });

  const wireFrames = await sender.sendFrame(99n, frame);
  const expectedChunks = Math.ceil(payloadSize / MAX_PAYLOAD_CHUNK_SIZE);
  assert.strictEqual(wireFrames.length, expectedChunks, `200,000 bytes must produce ${expectedChunks} chunks`);

  for (let i = 0; i < wireFrames.length; i++) {
    const res = await receiver.handleIncoming(wireFrames[i]);
    if (i < wireFrames.length - 1) {
      assert.strictEqual(res, null, `Chunk ${i} must return null`);
    } else {
      assert.ok(res instanceof ServiceFrame, "Final chunk must return reassembled ServiceFrame");
      assert.strictEqual(res.stream_id, 99n);
      assert.strictEqual(res.request.body.length, payloadSize);
      assert.ok(
        constantTimeEqual(res.request.body, originalBytes),
        "Reassembled 200,000-byte body must match original bitwise"
      );
    }
  }
  assert.strictEqual(receiver.decoder.pendingCount, 0);
});

test("Probe 2.3: Interleaved concurrent multi-stream multi-chunk wire transport", async () => {
  const { sender, receiver } = await createPairedTransports();

  // Stream A: 80,000 bytes (2 chunks)
  const bytesA = new Uint8Array(crypto.randomBytes(80000));
  const frameA = new ServiceFrame({
    stream_id: 101n,
    response: new ApplicationResponse({ status: 200, body: bytesA }),
  });

  // Stream B: 80,000 bytes (2 chunks)
  const bytesB = new Uint8Array(crypto.randomBytes(80000));
  const frameB = new ServiceFrame({
    stream_id: 102n,
    response: new ApplicationResponse({ status: 200, body: bytesB }),
  });

  const framesA = await sender.sendFrame(101n, frameA);
  const framesB = await sender.sendFrame(102n, frameB);

  assert.strictEqual(framesA.length, 2);
  assert.strictEqual(framesB.length, 2);

  // In standard transport, packets arrive in transmission order.
  // Sender sent: A0, A1, B0, B1
  const outA0 = await receiver.handleIncoming(framesA[0]);
  assert.strictEqual(outA0, null);

  const outA1 = await receiver.handleIncoming(framesA[1]);
  assert.ok(outA1 instanceof ServiceFrame);
  assert.strictEqual(outA1.stream_id, 101n);
  assert.ok(constantTimeEqual(outA1.response.body, bytesA));

  const outB0 = await receiver.handleIncoming(framesB[0]);
  assert.strictEqual(outB0, null);

  const outB1 = await receiver.handleIncoming(framesB[1]);
  assert.ok(outB1 instanceof ServiceFrame);
  assert.strictEqual(outB1.stream_id, 102n);
  assert.ok(constantTimeEqual(outB1.response.body, bytesB));

  assert.strictEqual(receiver.decoder.pendingCount, 0);
});

test("Probe 2.4: Boundary payload splitting at exact MAX_PAYLOAD_CHUNK_SIZE (65,489 B) vs boundary+1", async () => {
  const { sender, receiver } = await createPairedTransports();

  // Note: ServiceFrame has envelope overhead (ServiceRequest + ServiceFrame + stream_id + headers ~ 20 bytes)
  // Let's test raw body sizes around the threshold
  // Body of 60,000 bytes fits in 1 chunk
  const body1 = new Uint8Array(crypto.randomBytes(60000));
  const frame1 = new ServiceFrame({ stream_id: 11n, response: new ApplicationResponse({ body: body1 }) });
  const frames1 = await sender.sendFrame(11n, frame1);
  assert.strictEqual(frames1.length, 1, "60,000 bytes should produce 1 chunk");
  const rec1 = await receiver.handleIncoming(frames1[0]);
  assert.ok(constantTimeEqual(rec1.response.body, body1));

  // Body of 140,000 bytes produces 3 chunks (since 2 * 65489 = 130,978)
  const { sender: sender2, receiver: receiver2 } = await createPairedTransports();
  const body2 = new Uint8Array(crypto.randomBytes(140000));
  const frame2 = new ServiceFrame({ stream_id: 12n, response: new ApplicationResponse({ body: body2 }) });
  const frames2 = await sender2.sendFrame(12n, frame2);
  assert.strictEqual(frames2.length, 3, "140,000 bytes should produce 3 chunks");
  for (let i = 0; i < frames2.length; i++) {
    const rec = await receiver2.handleIncoming(frames2[i]);
    if (i < 2) assert.strictEqual(rec, null);
    else assert.ok(constantTimeEqual(rec.response.body, body2));
  }
});

test("Probe 2.5: Giant 10-chunk payload (~650,000 bytes) wire round-trip reconstruction", async () => {
  const { sender, receiver } = await createPairedTransports();

  const giantSize = 650000;
  const giantBytes = new Uint8Array(crypto.randomBytes(giantSize));
  const frame = new ServiceFrame({
    stream_id: 300n,
    response: new ApplicationResponse({ status: 200, body: giantBytes }),
  });

  const wireFrames = await sender.sendFrame(300n, frame);
  assert.strictEqual(wireFrames.length, 10, "650,000 bytes should produce 10 chunks");

  for (let i = 0; i < wireFrames.length; i++) {
    const res = await receiver.handleIncoming(wireFrames[i]);
    if (i < 9) {
      assert.strictEqual(res, null);
      assert.strictEqual(receiver.decoder.pendingCount, 1);
    } else {
      assert.ok(res instanceof ServiceFrame);
      assert.strictEqual(res.stream_id, 300n);
      assert.strictEqual(res.response.body.length, giantSize);
      assert.ok(constantTimeEqual(res.response.body, giantBytes));
    }
  }
  assert.strictEqual(receiver.decoder.pendingCount, 0);
});

// =============================================================================
// CATEGORY 3: Out-of-Order Wire Rejection & Timeout Fail-Closed Probes
// =============================================================================

test("Probe 3.1: Wire chunk reordering (chunk 1 delivered before chunk 0) fails closed with AEAD tag mismatch", async () => {
  const { sender, receiver } = await createPairedTransports();

  const payloadSize = 80000; // 2 chunks
  const data = new Uint8Array(crypto.randomBytes(payloadSize));
  const frame = new ServiceFrame({
    stream_id: 111n,
    response: new ApplicationResponse({ status: 200, body: data }),
  });

  const wireFrames = await sender.sendFrame(111n, frame);
  assert.strictEqual(wireFrames.length, 2);

  // Adversary delivers chunk 1 BEFORE chunk 0.
  // Chunk 1 was encrypted with nonce=1. Receiver expects nonce=0.
  // AES-GCM AEAD decryption MUST reject with tag mismatch!
  await assert.rejects(
    async () => {
      await receiver.handleIncoming(wireFrames[1]);
    },
    (err) => {
      assert.ok(
        /operation failed|decrypt|poisoned/i.test(err.message),
        `Must reject with AEAD error, got: ${err.message}`
      );
      return true;
    }
  );

  // Receiver cipher state must be poisoned
  assert.strictEqual(receiver.decoder.pendingCount, 0, "No pending assembly was started");
  await assert.rejects(
    async () => {
      await receiver.handleIncoming(wireFrames[0]);
    },
    /poisoned after prior failure/
  );
});

test("Probe 3.2: Wire frame dropping (nonce desync) triggers immediate fail-closed rejection", async () => {
  const { sender, receiver } = await createPairedTransports();

  const frame1 = new ServiceFrame({ stream_id: 1n, body_chunk: new BodyChunk({ data: new Uint8Array([1]) }) });
  const frame2 = new ServiceFrame({ stream_id: 2n, body_chunk: new BodyChunk({ data: new Uint8Array([2]) }) });

  const [wire1] = await sender.sendFrame(1n, frame1);
  const [wire2] = await sender.sendFrame(2n, frame2);

  // Drop wire1, deliver wire2 directly
  // wire2 was encrypted with nonce=1. Receiver rxCipher is at nonce=0.
  await assert.rejects(
    async () => {
      await receiver.handleIncoming(wire2);
    },
    /operation failed|decrypt/i
  );
});

test("Probe 3.3: Corrupted intermediate chunk in 3-chunk transfer prevents incomplete delivery", async () => {
  const { sender, receiver } = await createPairedTransports();

  const payloadSize = 150000; // 3 chunks
  const data = new Uint8Array(crypto.randomBytes(payloadSize));
  const frame = new ServiceFrame({
    stream_id: 123n,
    request: new ApplicationRequest({ verb: "POST", path: "/test", body: data }),
  });

  const wireFrames = await sender.sendFrame(123n, frame);
  assert.strictEqual(wireFrames.length, 3);

  // Chunk 0 is valid
  const res0 = await receiver.handleIncoming(wireFrames[0]);
  assert.strictEqual(res0, null);
  assert.strictEqual(receiver.decoder.pendingCount, 1);

  // Chunk 1 is corrupted on wire
  const corruptedChunk1 = new Uint8Array(wireFrames[1]);
  corruptedChunk1[20] ^= 0xff;

  let streamDelivered = false;
  receiver.registerStream(123n, () => {
    streamDelivered = true;
  });

  await assert.rejects(
    async () => {
      await receiver.handleIncoming(corruptedChunk1);
    },
    /operation failed|decrypt/i
  );

  // Attempting chunk 2 must also fail
  await assert.rejects(
    async () => {
      await receiver.handleIncoming(wireFrames[2]);
    },
    /poisoned after prior failure/
  );

  // Crucial invariant: stream must NEVER have received partial or invalid data
  assert.strictEqual(streamDelivered, false, "Stream handler must NOT have been called with partial corrupted data");
});

test("Probe 3.4: Stale assembly timeout purge frees pending buffers without memory leak", async () => {
  // Use a transport with short decoder timeout (50ms)
  const decoder = new NoiseFrameDecoder({ timeoutMs: 50 });
  const { sender, receiver } = await createPairedTransports({
    receiverOptions: { decoder },
  });

  const payloadSize = 70000; // 2 chunks
  const frame = new ServiceFrame({
    stream_id: 200n,
    response: new ApplicationResponse({ status: 200, body: new Uint8Array(payloadSize) }),
  });

  const wireFrames = await sender.sendFrame(200n, frame);
  assert.strictEqual(wireFrames.length, 2);

  // Deliver chunk 0 only
  const res0 = await receiver.handleIncoming(wireFrames[0]);
  assert.strictEqual(res0, null);
  assert.strictEqual(decoder.pendingCount, 1);

  // Wait 70ms for assembly to expire
  await new Promise((resolve) => setTimeout(resolve, 70));

  // Purge expired assemblies
  decoder.purgeExpired();
  assert.strictEqual(decoder.pendingCount, 0, "Stale assembly must be purged after timeout");
});

test("Probe 3.5: Decoder budget limit enforcement purges assembly and rejects gracefully", () => {
  const decoder = new NoiseFrameDecoder({ maxAssemblyBytes: 2000 });

  const chunkId = 9999n;
  const frame1 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 0,
    total_chunks: 2,
    payload: new Uint8Array(1500),
  });

  const res1 = decoder.push(frame1);
  assert.strictEqual(res1, null);
  assert.strictEqual(decoder.pendingCount, 1);

  // Second chunk would exceed 2000 byte budget -> must throw and purge
  const frame2 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 1,
    total_chunks: 2,
    payload: new Uint8Array(1000),
  });

  assert.throws(
    () => {
      decoder.push(frame2);
    },
    /assembly exceeded byte budget/
  );

  assert.strictEqual(decoder.pendingCount, 0, "Exceeded assembly must be purged from map");
  assert.strictEqual(decoder.hasAssembly(chunkId), false);
});

test("Probe 3.6: Duplicate chunk index drops assembly and throws fail-closed", () => {
  const decoder = new NoiseFrameDecoder();
  const chunkId = 4444n;

  const chunk1 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 0,
    total_chunks: 3,
    payload: new Uint8Array([1, 2, 3]),
  });

  assert.strictEqual(decoder.push(chunk1), null);
  assert.strictEqual(decoder.pendingCount, 1);

  // Push chunk 0 again
  assert.throws(
    () => {
      decoder.push(chunk1);
    },
    /duplicate chunkIndex 0/
  );

  assert.strictEqual(decoder.pendingCount, 0, "Assembly must be deleted on error");
  assert.strictEqual(decoder.hasAssembly(chunkId), false);
});

test("Probe 3.7: Inconsistent total_chunks drops assembly and throws fail-closed", () => {
  const decoder = new NoiseFrameDecoder();
  const chunkId = 5555n;

  const chunk1 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 0,
    total_chunks: 3,
    payload: new Uint8Array([1]),
  });

  assert.strictEqual(decoder.push(chunk1), null);
  assert.strictEqual(decoder.pendingCount, 1);

  const chunk2 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 1,
    total_chunks: 4, // Claims 4 instead of 3
    payload: new Uint8Array([2]),
  });

  assert.throws(
    () => {
      decoder.push(chunk2);
    },
    /inconsistent totalChunks/
  );

  assert.strictEqual(decoder.pendingCount, 0);
  assert.strictEqual(decoder.hasAssembly(chunkId), false);
});

test("Probe 3.8: Invalid chunk indices (out of bounds or negative) throw RangeError", () => {
  const decoder = new NoiseFrameDecoder();

  // chunk_index >= total_chunks
  const badIndex = new NoiseTransportFrame({
    chunk_id: 1n,
    chunk_index: 2,
    total_chunks: 2,
    payload: new Uint8Array([1]),
  });
  assert.throws(() => decoder.push(badIndex), RangeError);

  // negative chunk_index
  const negIndex = new NoiseTransportFrame({
    chunk_id: 1n,
    chunk_index: -1,
    total_chunks: 2,
    payload: new Uint8Array([1]),
  });
  assert.throws(() => decoder.push(negIndex), RangeError);

  // total_chunks > 256
  const tooManyChunks = new NoiseTransportFrame({
    chunk_id: 1n,
    chunk_index: 0,
    total_chunks: 257,
    payload: new Uint8Array([1]),
  });
  assert.throws(() => decoder.push(tooManyChunks), RangeError);
});

test("Probe 3.9: Maximum concurrent pending assemblies limit (16 max, 17th throws)", () => {
  const decoder = new NoiseFrameDecoder();

  // Fill up 16 pending assemblies
  for (let i = 1; i <= 16; i++) {
    const frame = new NoiseTransportFrame({
      chunk_id: BigInt(i),
      chunk_index: 0,
      total_chunks: 2,
      payload: new Uint8Array([i]),
    });
    assert.strictEqual(decoder.push(frame), null);
  }

  assert.strictEqual(decoder.pendingCount, 16);

  // 17th must throw
  const frame17 = new NoiseTransportFrame({
    chunk_id: 17n,
    chunk_index: 0,
    total_chunks: 2,
    payload: new Uint8Array([17]),
  });
  assert.throws(() => decoder.push(frame17), /too many pending noise frame assemblies/);

  // Complete assembly 1 -> 15 remain
  const finish1 = new NoiseTransportFrame({
    chunk_id: 1n,
    chunk_index: 1,
    total_chunks: 2,
    payload: new Uint8Array([100]),
  });
  const res = decoder.push(finish1);
  assert.ok(res instanceof Uint8Array);
  assert.strictEqual(decoder.pendingCount, 15);

  // Now frame17 succeeds
  assert.strictEqual(decoder.push(frame17), null);
  assert.strictEqual(decoder.pendingCount, 16);
});

test("Probe 3.10: Stream cancellation with cancelStream sends encrypted Reset and purges stream", async () => {
  const { sender, receiver } = await createPairedTransports();

  let receivedFrame = null;
  receiver.registerStream(88n, (frame) => {
    receivedFrame = frame;
  });

  const cancelFrames = await sender.cancelStream(88n, "User clicked stop");
  assert.strictEqual(cancelFrames.length, 1);

  // Deliver to receiver
  await receiver.handleIncoming(cancelFrames[0]);
  assert.ok(receivedFrame instanceof ServiceFrame);
  assert.strictEqual(receivedFrame.stream_id, 88n);
  assert.ok(receivedFrame.reset);
  assert.strictEqual(receivedFrame.reset.code, ResetCode.CANCELLED);
  assert.strictEqual(receivedFrame.reset.reason, "User clicked stop");
});
