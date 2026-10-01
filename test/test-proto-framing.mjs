/**
 * test/test-proto-framing.mjs
 *
 * Comprehensive test suite for R2 & R3:
 * - Binary Protobuf wire framing encode/decode bitwise roundtrip:
 *   NoiseTransportFrame, Header, ApplicationRequest, ApplicationResponse, BodyChunk, Reset, ServiceFrame, ServiceRequest, ServiceResponse
 * - NoiseFrameDecoder multi-chunk reassembly, out-of-order handling, single-chunk bypass
 * - NoiseFrameDecoder boundary & DoS protections (16 concurrent assemblies, 16 MiB budget, 60s timeout purge, duplicate index, inconsistent total)
 * - End-to-end NoiseTransport loopback (encrypted frame splitting -> reassembly -> decryption -> ServiceFrame match)
 * - Stream multiplexing, monotonic BigInt stream IDs, and stream cancellation
 *
 * Pure Node 20+ built-ins (node:test, node:assert/strict). Zero external dependencies.
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  NoiseTransportFrame,
  Header,
  ApplicationRequest,
  ApplicationResponse,
  BodyChunk,
  Reset,
  ServiceFrame,
  ServiceRequest,
  ServiceResponse,
  ServiceType,
  ResetCode,
  encodeNoiseTransportFrame,
  decodeNoiseTransportFrame,
  encodeHeader,
  decodeHeader,
  encodeApplicationRequest,
  decodeApplicationRequest,
  encodeApplicationResponse,
  decodeApplicationResponse,
  encodeBodyChunk,
  decodeBodyChunk,
  encodeReset,
  decodeReset,
  encodeServiceFrame,
  decodeServiceFrame,
  encodeServiceRequest,
  decodeServiceRequest,
  encodeServiceResponse,
  decodeServiceResponse,
  writeVarint,
  readVarint,
} from "../lib/noise/proto.mjs";

import { CipherState } from "../lib/noise/crypto.mjs";
import {
  NoiseFrameDecoder,
  NoiseTransport,
  MAX_PAYLOAD_CHUNK_SIZE,
  MAX_CONCURRENT_ASSEMBLIES,
  MAX_ASSEMBLY_BYTES,
} from "../lib/noise/transport.mjs";

/**
 * Generates a deterministic pseudo-random byte array of given length for testing.
 * @param {number} length
 * @param {number} seed
 * @returns {Uint8Array}
 */
function generateTestPayload(length, seed = 42) {
  const bytes = new Uint8Array(length);
  let state = seed;
  for (let i = 0; i < length; i++) {
    state = (state * 1664525 + 1013904223) >>> 0;
    bytes[i] = state & 0xff;
  }
  return bytes;
}

// =============================================================================
// Suite 1: Protobuf Wire Framing Bitwise Exact Roundtrip
// =============================================================================

test("Suite 1.1: Compact LEB128 varint encode/decode for uint32 and int64", () => {
  const testValues = [
    0,
    1,
    127,
    128,
    300,
    16384,
    2097151,
    2097152,
    0xffffffff,
    0n,
    1n,
    65489n,
    123456789012345678n,
    -1n,
    -123456789012345678n,
  ];

  for (const val of testValues) {
    const encoded = writeVarint(null, val);
    const decoded = readVarint(encoded);
    if (typeof val === "bigint") {
      if (val < 0n) {
        // Two's complement 64-bit comparison
        assert.strictEqual(BigInt.asIntN(64, decoded.value), val);
      } else {
        assert.strictEqual(decoded.value, val);
      }
    } else {
      assert.strictEqual(Number(decoded.value), val);
    }
  }
});

test("Suite 1.2: NoiseTransportFrame bitwise exact encode/decode roundtrip", () => {
  const frames = [
    new NoiseTransportFrame({
      chunk_id: 12345678901234n,
      chunk_index: 0,
      total_chunks: 3,
      payload: new Uint8Array([1, 2, 3, 4, 5]),
    }),
    new NoiseTransportFrame({
      chunk_id: -98765432109876n,
      chunk_index: 2,
      total_chunks: 5,
      payload: generateTestPayload(256, 11),
    }),
    new NoiseTransportFrame({
      chunk_id: 0n,
      chunk_index: 0,
      total_chunks: 1,
      payload: new Uint8Array(0),
    }),
  ];

  for (const original of frames) {
    const encoded = encodeNoiseTransportFrame(original);
    assert(encoded.length > 0, "Encoded frame must not be empty");
    const decoded = decodeNoiseTransportFrame(encoded);

    assert.strictEqual(decoded.chunk_id, original.chunk_id);
    assert.strictEqual(decoded.chunk_index, original.chunk_index);
    assert.strictEqual(decoded.total_chunks, original.total_chunks);
    assert.deepStrictEqual(decoded.payload, original.payload);

    // Re-encoding decoded message produces byte-identical representation
    const reEncoded = encodeNoiseTransportFrame(decoded);
    assert.deepStrictEqual(reEncoded, encoded);
  }
});

test("Suite 1.3: Header bitwise exact roundtrip", () => {
  const headers = [
    new Header({ key: "content-type", value: "application/json" }),
    new Header({ key: "x-request-id", value: "f7d7b00b-b7c0-4041-b24d" }),
    new Header({ key: "", value: "" }),
  ];

  for (const h of headers) {
    const encoded = encodeHeader(h);
    const decoded = decodeHeader(encoded);
    assert.strictEqual(decoded.key, h.key);
    assert.strictEqual(decoded.value, h.value);
    assert.deepStrictEqual(encodeHeader(decoded), encoded);
  }
});

test("Suite 1.4: ApplicationRequest bitwise exact roundtrip", () => {
  const req1 = new ApplicationRequest({
    verb: "POST",
    path: "/chat/stream",
    headers: [
      new Header({ key: "content-type", value: "application/json" }),
      new Header({ key: "x-app-id", value: "hatch-web" }),
    ],
    body: new TextEncoder().encode('{"prompt":"hello world"}'),
    end_body: true,
  });

  const encoded1 = encodeApplicationRequest(req1);
  const decoded1 = decodeApplicationRequest(encoded1);
  assert.strictEqual(decoded1.verb, "POST");
  assert.strictEqual(decoded1.path, "/chat/stream");
  assert.strictEqual(decoded1.headers.length, 2);
  assert.strictEqual(decoded1.headers[0].key, "content-type");
  assert.strictEqual(decoded1.headers[0].value, "application/json");
  assert.strictEqual(decoded1.headers[1].key, "x-app-id");
  assert.strictEqual(decoded1.headers[1].value, "hatch-web");
  assert.deepStrictEqual(decoded1.body, req1.body);
  assert.strictEqual(decoded1.end_body, true);
  assert.deepStrictEqual(encodeApplicationRequest(decoded1), encoded1);

  // Unary request with empty body
  const req2 = new ApplicationRequest({
    verb: "GET",
    path: "/chat/history-window",
    headers: [],
    body: new Uint8Array(0),
    end_body: false,
  });
  const encoded2 = encodeApplicationRequest(req2);
  const decoded2 = decodeApplicationRequest(encoded2);
  assert.strictEqual(decoded2.verb, "GET");
  assert.strictEqual(decoded2.path, "/chat/history-window");
  assert.strictEqual(decoded2.end_body, false);
  assert.deepStrictEqual(encodeApplicationRequest(decoded2), encoded2);
});

test("Suite 1.5: ApplicationResponse bitwise exact roundtrip", () => {
  const res = new ApplicationResponse({
    status: 200,
    headers: [new Header({ key: "content-type", value: "text/event-stream" })],
    body: new TextEncoder().encode("data: initial chunk\n\n"),
    end_body: false,
  });

  const encoded = encodeApplicationResponse(res);
  const decoded = decodeApplicationResponse(encoded);
  assert.strictEqual(decoded.status, 200);
  assert.strictEqual(decoded.headers.length, 1);
  assert.strictEqual(decoded.headers[0].key, "content-type");
  assert.strictEqual(decoded.headers[0].value, "text/event-stream");
  assert.deepStrictEqual(decoded.body, res.body);
  assert.strictEqual(decoded.end_body, false);
  assert.deepStrictEqual(encodeApplicationResponse(decoded), encoded);
});

test("Suite 1.6: BodyChunk bitwise exact roundtrip", () => {
  const chunk1 = new BodyChunk({
    data: new TextEncoder().encode("delta text stream slice"),
    end_body: false,
  });
  const encoded1 = encodeBodyChunk(chunk1);
  const decoded1 = decodeBodyChunk(encoded1);
  assert.deepStrictEqual(decoded1.data, chunk1.data);
  assert.strictEqual(decoded1.end_body, false);
  assert.deepStrictEqual(encodeBodyChunk(decoded1), encoded1);

  // Final chunk
  const chunk2 = new BodyChunk({
    data: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    end_body: true,
  });
  const encoded2 = encodeBodyChunk(chunk2);
  const decoded2 = decodeBodyChunk(encoded2);
  assert.deepStrictEqual(decoded2.data, chunk2.data);
  assert.strictEqual(decoded2.end_body, true);
  assert.deepStrictEqual(encodeBodyChunk(decoded2), encoded2);
});

test("Suite 1.7: Reset bitwise exact roundtrip", () => {
  const codes = [
    { code: ResetCode.CANCELLED, reason: "user initiated stream abort" },
    { code: ResetCode.TIMEOUT, reason: "keepalive heartbeat expired" },
    { code: ResetCode.PROTOCOL_ERROR, reason: "unexpected framing tag" },
    { code: ResetCode.INTERNAL_ERROR, reason: "server panic" },
  ];

  for (const item of codes) {
    const reset = new Reset(item);
    const encoded = encodeReset(reset);
    const decoded = decodeReset(encoded);
    assert.strictEqual(decoded.code, item.code);
    assert.strictEqual(decoded.reason, item.reason);
    assert.deepStrictEqual(encodeReset(decoded), encoded);
  }
});

test("Suite 1.8: ServiceFrame oneof multiplexing bitwise exact roundtrip", () => {
  // 1. ServiceFrame with ApplicationRequest
  const frameReq = new ServiceFrame({
    stream_id: 1n,
    request: new ApplicationRequest({
      verb: "POST",
      path: "/client/register-capabilities",
      body: new TextEncoder().encode('{"tools":[]}'),
      end_body: true,
    }),
  });
  const encReq = encodeServiceFrame(frameReq);
  const decReq = decodeServiceFrame(encReq);
  assert.strictEqual(decReq.stream_id, 1n);
  assert.strictEqual(decReq.kind.case, "request");
  assert.strictEqual(decReq.request.verb, "POST");
  assert.strictEqual(decReq.request.path, "/client/register-capabilities");
  assert.deepStrictEqual(encodeServiceFrame(decReq), encReq);

  // 2. ServiceFrame with ApplicationResponse
  const frameRes = new ServiceFrame({
    stream_id: 2n,
    response: new ApplicationResponse({
      status: 200,
      body: new TextEncoder().encode('{"ok":true}'),
      end_body: true,
    }),
  });
  const encRes = encodeServiceFrame(frameRes);
  const decRes = decodeServiceFrame(encRes);
  assert.strictEqual(decRes.stream_id, 2n);
  assert.strictEqual(decRes.kind.case, "response");
  assert.strictEqual(decRes.response.status, 200);
  assert.deepStrictEqual(encodeServiceFrame(decRes), encRes);

  // 3. ServiceFrame with BodyChunk
  const frameChunk = new ServiceFrame({
    stream_id: 3n,
    body_chunk: new BodyChunk({
      data: new Uint8Array([1, 3, 3, 7]),
      end_body: false,
    }),
  });
  const encChunk = encodeServiceFrame(frameChunk);
  const decChunk = decodeServiceFrame(encChunk);
  assert.strictEqual(decChunk.stream_id, 3n);
  assert.strictEqual(decChunk.kind.case, "body_chunk");
  assert.deepStrictEqual(decChunk.body_chunk.data, new Uint8Array([1, 3, 3, 7]));
  assert.strictEqual(decChunk.body_chunk.end_body, false);
  assert.deepStrictEqual(encodeServiceFrame(decChunk), encChunk);

  // 4. ServiceFrame with Reset
  const frameReset = new ServiceFrame({
    stream_id: 4n,
    reset: new Reset({
      code: ResetCode.CANCELLED,
      reason: "cancelled",
    }),
  });
  const encReset = encodeServiceFrame(frameReset);
  const decReset = decodeServiceFrame(encReset);
  assert.strictEqual(decReset.stream_id, 4n);
  assert.strictEqual(decReset.kind.case, "reset");
  assert.strictEqual(decReset.reset.code, ResetCode.CANCELLED);
  assert.strictEqual(decReset.reset.reason, "cancelled");
  assert.deepStrictEqual(encodeServiceFrame(decReset), encReset);
});

test("Suite 1.9: ServiceRequest and ServiceResponse envelopes roundtrip", () => {
  const sampleFrameBytes = new Uint8Array([0x08, 0x01, 0x12, 0x04, 0x74, 0x65, 0x73, 0x74]);

  const req = new ServiceRequest({
    service: ServiceType.SERVICE_DAEMON,
    payload: sampleFrameBytes,
  });
  const encReq = encodeServiceRequest(req);
  const decReq = decodeServiceRequest(encReq);
  assert.strictEqual(decReq.service, ServiceType.SERVICE_DAEMON);
  assert.deepStrictEqual(decReq.payload, sampleFrameBytes);
  assert.deepStrictEqual(encodeServiceRequest(decReq), encReq);

  const res = new ServiceResponse({
    payload: sampleFrameBytes,
  });
  const encRes = encodeServiceResponse(res);
  const decRes = decodeServiceResponse(encRes);
  assert.deepStrictEqual(decRes.payload, sampleFrameBytes);
  assert.deepStrictEqual(encodeServiceResponse(decRes), encRes);
});

// =============================================================================
// Suite 2: NoiseFrameDecoder Chunking & Reassembly
// =============================================================================

test("Suite 2.1: NoiseFrameDecoder fast single-chunk bypass when total_chunks === 1", () => {
  const decoder = new NoiseFrameDecoder();
  const payload = generateTestPayload(500, 77);

  const frame = new NoiseTransportFrame({
    chunk_id: 1001n,
    chunk_index: 0,
    total_chunks: 1,
    payload,
  });

  const assembled = decoder.push(frame);
  assert.deepStrictEqual(assembled, payload, "Single-chunk frame must bypass assembly and return payload directly");
  assert.strictEqual(decoder.pendingCount, 0, "No pending assembly entry retained for single-chunk");
});

test("Suite 2.2: Multi-chunk splitting (> 65,489 bytes) and full in-order reassembly", () => {
  const decoder = new NoiseFrameDecoder();
  const originalPayload = generateTestPayload(150_000, 12345); // 150 KB synthetic payload
  const chunkId = 8888n;

  // Split into chunks <= 65,489 bytes
  const totalChunks = Math.ceil(originalPayload.length / MAX_PAYLOAD_CHUNK_SIZE);
  assert.strictEqual(totalChunks, 3, "150,000 bytes requires exactly 3 chunks of <= 65,489 bytes");

  const chunkFrames = [];
  for (let i = 0; i < totalChunks; i++) {
    const start = i * MAX_PAYLOAD_CHUNK_SIZE;
    const end = Math.min(start + MAX_PAYLOAD_CHUNK_SIZE, originalPayload.length);
    const slice = originalPayload.subarray(start, end);
    assert(slice.length <= MAX_PAYLOAD_CHUNK_SIZE);

    chunkFrames.push(
      encodeNoiseTransportFrame(
        new NoiseTransportFrame({
          chunk_id: chunkId,
          chunk_index: i,
          total_chunks: totalChunks,
          payload: slice,
        })
      )
    );
  }

  // Push Chunk 0: pending
  const res0 = decoder.push(chunkFrames[0]);
  assert.strictEqual(res0, null, "Chunk 0 must return null (awaiting remaining chunks)");
  assert.strictEqual(decoder.pendingCount, 1);
  assert.strictEqual(decoder.hasAssembly(chunkId), true);

  // Push Chunk 1: pending
  const res1 = decoder.push(chunkFrames[1]);
  assert.strictEqual(res1, null, "Chunk 1 must return null (awaiting remaining chunks)");
  assert.strictEqual(decoder.pendingCount, 1);

  // Push Chunk 2: completed
  const assembled = decoder.push(chunkFrames[2]);
  assert(assembled instanceof Uint8Array, "Final chunk must return reassembled Uint8Array");
  assert.strictEqual(assembled.length, 150_000, "Reassembled byte length must match original");
  assert.deepStrictEqual(assembled, originalPayload, "Reassembled bytes must be bitwise identical to original");
  assert.strictEqual(decoder.pendingCount, 0, "Pending assembly map must be cleared after completion");
  assert.strictEqual(decoder.hasAssembly(chunkId), false);
});

test("Suite 2.3: Out-of-order chunk reassembly (chunk 2 before chunk 0)", () => {
  const decoder = new NoiseFrameDecoder();
  const originalPayload = generateTestPayload(150_000, 9999);
  const chunkId = 7777n;
  const totalChunks = Math.ceil(originalPayload.length / MAX_PAYLOAD_CHUNK_SIZE);

  const chunks = [];
  for (let i = 0; i < totalChunks; i++) {
    const start = i * MAX_PAYLOAD_CHUNK_SIZE;
    const end = Math.min(start + MAX_PAYLOAD_CHUNK_SIZE, originalPayload.length);
    chunks.push(
      new NoiseTransportFrame({
        chunk_id: chunkId,
        chunk_index: i,
        total_chunks: totalChunks,
        payload: originalPayload.subarray(start, end),
      })
    );
  }

  // Arrival order: Chunk 2, then Chunk 0, then Chunk 1
  const step1 = decoder.push(chunks[2]);
  assert.strictEqual(step1, null);
  assert.strictEqual(decoder.pendingCount, 1);

  const step2 = decoder.push(chunks[0]);
  assert.strictEqual(step2, null);
  assert.strictEqual(decoder.pendingCount, 1);

  const assembled = decoder.push(chunks[1]);
  assert(assembled instanceof Uint8Array);
  assert.strictEqual(assembled.length, 150_000);
  assert.deepStrictEqual(assembled, originalPayload, "Out-of-order delivery must reassemble in exact index order");
  assert.strictEqual(decoder.pendingCount, 0);
});

test("Suite 2.4: Interleaved concurrent multi-chunk assemblies", () => {
  const decoder = new NoiseFrameDecoder();
  const payloadA = generateTestPayload(100_000, 111);
  const payloadB = generateTestPayload(120_000, 222);

  const idA = 100n;
  const idB = 200n;

  const totalA = Math.ceil(payloadA.length / MAX_PAYLOAD_CHUNK_SIZE); // 2 chunks
  const totalB = Math.ceil(payloadB.length / MAX_PAYLOAD_CHUNK_SIZE); // 2 chunks

  const frameA0 = new NoiseTransportFrame({
    chunk_id: idA,
    chunk_index: 0,
    total_chunks: totalA,
    payload: payloadA.subarray(0, MAX_PAYLOAD_CHUNK_SIZE),
  });
  const frameA1 = new NoiseTransportFrame({
    chunk_id: idA,
    chunk_index: 1,
    total_chunks: totalA,
    payload: payloadA.subarray(MAX_PAYLOAD_CHUNK_SIZE),
  });

  const frameB0 = new NoiseTransportFrame({
    chunk_id: idB,
    chunk_index: 0,
    total_chunks: totalB,
    payload: payloadB.subarray(0, MAX_PAYLOAD_CHUNK_SIZE),
  });
  const frameB1 = new NoiseTransportFrame({
    chunk_id: idB,
    chunk_index: 1,
    total_chunks: totalB,
    payload: payloadB.subarray(MAX_PAYLOAD_CHUNK_SIZE),
  });

  // Interleave pushes: A0 -> B0 -> A1 (completes A) -> B1 (completes B)
  assert.strictEqual(decoder.push(frameA0), null);
  assert.strictEqual(decoder.pendingCount, 1);

  assert.strictEqual(decoder.push(frameB0), null);
  assert.strictEqual(decoder.pendingCount, 2);

  const assembledA = decoder.push(frameA1);
  assert.deepStrictEqual(assembledA, payloadA, "Payload A must reassemble cleanly despite interleaved chunks");
  assert.strictEqual(decoder.pendingCount, 1);

  const assembledB = decoder.push(frameB1);
  assert.deepStrictEqual(assembledB, payloadB, "Payload B must reassemble cleanly despite interleaved chunks");
  assert.strictEqual(decoder.pendingCount, 0);
});

// =============================================================================
// Suite 3: Boundary & DoS Protections
// =============================================================================

test("Suite 3.1: Max payload chunk size enforcement (> 65,489 bytes throws)", () => {
  const decoder = new NoiseFrameDecoder();
  const oversizedPayload = new Uint8Array(MAX_PAYLOAD_CHUNK_SIZE + 1);

  const oversizedFrame = new NoiseTransportFrame({
    chunk_id: 1n,
    chunk_index: 0,
    total_chunks: 1,
    payload: oversizedPayload,
  });

  assert.throws(
    () => decoder.push(oversizedFrame),
    /payload too large for noise frame/,
    "Must throw when payload exceeds 65,489 bytes"
  );

  // Exactly 65,489 bytes is allowed
  const exactMaxPayload = new Uint8Array(MAX_PAYLOAD_CHUNK_SIZE);
  const validFrame = new NoiseTransportFrame({
    chunk_id: 2n,
    chunk_index: 0,
    total_chunks: 1,
    payload: exactMaxPayload,
  });
  const result = decoder.push(validFrame);
  assert.strictEqual(result.length, MAX_PAYLOAD_CHUNK_SIZE);
});

test("Suite 3.2: Total chunks range validation (1 to 256)", () => {
  const decoder = new NoiseFrameDecoder();

  // total_chunks = 0 throws
  assert.throws(
    () =>
      decoder.push(
        new NoiseTransportFrame({
          chunk_id: 1n,
          chunk_index: 0,
          total_chunks: 0,
          payload: new Uint8Array(10),
        })
      ),
    /invalid totalChunks/,
    "total_chunks = 0 must throw"
  );

  // total_chunks = 257 throws
  assert.throws(
    () =>
      decoder.push(
        new NoiseTransportFrame({
          chunk_id: 2n,
          chunk_index: 0,
          total_chunks: 257,
          payload: new Uint8Array(10),
        })
      ),
    /invalid totalChunks/,
    "total_chunks = 257 must throw"
  );
});

test("Suite 3.3: Chunk index range validation (0 <= chunk_index < total_chunks)", () => {
  const decoder = new NoiseFrameDecoder();

  // chunk_index < 0 throws
  assert.throws(
    () =>
      decoder.push(
        new NoiseTransportFrame({
          chunk_id: 1n,
          chunk_index: -1,
          total_chunks: 3,
          payload: new Uint8Array(10),
        })
      ),
    /chunkIndex.*out of range/,
    "Negative chunkIndex must throw"
  );

  // chunk_index >= total_chunks throws
  assert.throws(
    () =>
      decoder.push(
        new NoiseTransportFrame({
          chunk_id: 2n,
          chunk_index: 3,
          total_chunks: 3,
          payload: new Uint8Array(10),
        })
      ),
    /chunkIndex.*out of range/,
    "chunkIndex equal to total_chunks must throw"
  );
});

test("Suite 3.4: Max concurrent pending assemblies limit (16 max, 17th throws)", () => {
  const decoder = new NoiseFrameDecoder();

  // Start 16 distinct pending assemblies
  for (let i = 1; i <= MAX_CONCURRENT_ASSEMBLIES; i++) {
    const frame = new NoiseTransportFrame({
      chunk_id: BigInt(i),
      chunk_index: 0,
      total_chunks: 2,
      payload: new Uint8Array([i]),
    });
    assert.strictEqual(decoder.push(frame), null);
  }
  assert.strictEqual(decoder.pendingCount, 16);

  // Attempt to start 17th assembly -> throws
  const frame17 = new NoiseTransportFrame({
    chunk_id: 17n,
    chunk_index: 0,
    total_chunks: 2,
    payload: new Uint8Array([17]),
  });
  assert.throws(
    () => decoder.push(frame17),
    /too many pending noise frame assemblies/,
    "Starting 17th pending assembly must throw DoS limit error"
  );

  // Completing assembly 1 frees a slot
  const finishFrame1 = new NoiseTransportFrame({
    chunk_id: 1n,
    chunk_index: 1,
    total_chunks: 2,
    payload: new Uint8Array([99]),
  });
  const assembled1 = decoder.push(finishFrame1);
  assert(assembled1 !== null);
  assert.strictEqual(decoder.pendingCount, 15);

  // Now 17th assembly succeeds
  assert.strictEqual(decoder.push(frame17), null);
  assert.strictEqual(decoder.pendingCount, 16);
});

test("Suite 3.5: Cumulative byte budget limit (exceeding purges assembly)", () => {
  const decoder = new NoiseFrameDecoder({ maxAssemblyBytes: 100 });
  const chunkId = 555n;
  const totalChunks = 3;

  const chunk0 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 0,
    total_chunks: totalChunks,
    payload: new Uint8Array(60),
  });
  assert.strictEqual(decoder.push(chunk0), null);
  assert.strictEqual(decoder.hasAssembly(chunkId), true);

  const chunk1 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 1,
    total_chunks: totalChunks,
    payload: new Uint8Array(60),
  });

  assert.throws(
    () => decoder.push(chunk1),
    /assembly exceeded byte budget/,
    "Exceeding cumulative assembly bytes must throw"
  );
  assert.strictEqual(decoder.hasAssembly(chunkId), false, "Assembly must be purged from map upon budget violation");
});

test("Suite 3.6: Duplicate chunk_index drops assembly and throws", () => {
  const decoder = new NoiseFrameDecoder();
  const chunkId = 333n;

  // Push chunk 0
  const frame0 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 0,
    total_chunks: 3,
    payload: new Uint8Array([1, 2, 3]),
  });
  assert.strictEqual(decoder.push(frame0), null);
  assert.strictEqual(decoder.hasAssembly(chunkId), true);

  // Push duplicate chunk 0
  assert.throws(
    () => decoder.push(frame0),
    /duplicate chunkIndex 0/,
    "Duplicate chunk index must throw"
  );
  assert.strictEqual(decoder.hasAssembly(chunkId), false, "Assembly must be dropped after duplicate chunk error");
});

test("Suite 3.7: Inconsistent total_chunks drops assembly and throws", () => {
  const decoder = new NoiseFrameDecoder();
  const chunkId = 444n;

  // Start with total_chunks = 3
  const frame0 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 0,
    total_chunks: 3,
    payload: new Uint8Array([1, 2]),
  });
  assert.strictEqual(decoder.push(frame0), null);
  assert.strictEqual(decoder.hasAssembly(chunkId), true);

  // Next chunk has total_chunks = 4
  const frameInconsistent = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 1,
    total_chunks: 4,
    payload: new Uint8Array([3, 4]),
  });

  assert.throws(
    () => decoder.push(frameInconsistent),
    /inconsistent totalChunks for chunkId/,
    "Mismatched totalChunks must throw"
  );
  assert.strictEqual(decoder.hasAssembly(chunkId), false, "Assembly must be dropped after inconsistent totalChunks error");
});

test("Suite 3.8: Stale assembly expiration purge (60s timeout)", async () => {
  // Test with configurable short timeout for testability
  const decoder = new NoiseFrameDecoder({ timeoutMs: 50 });
  const chunkId = 666n;

  const frame0 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 0,
    total_chunks: 2,
    payload: new Uint8Array([1]),
  });
  assert.strictEqual(decoder.push(frame0), null);
  assert.strictEqual(decoder.hasAssembly(chunkId), true);

  // Wait 60ms for timeout to expire
  await new Promise((r) => setTimeout(r, 60));

  // Purge expired
  decoder.purgeExpired();
  assert.strictEqual(decoder.hasAssembly(chunkId), false, "Stale assembly must be deleted after expiration");
});

// =============================================================================
// Suite 4: End-to-End NoiseTransport Loopback & Multiplexing
// =============================================================================

test("Suite 4.1: End-to-end encrypted loopback with small ServiceFrame", async () => {
  const sharedKey = new Uint8Array(32).fill(0x5a);
  const txCipher = new CipherState(sharedKey);
  const rxCipher = new CipherState(sharedKey);

  const loopbackFrames = [];
  const transport = new NoiseTransport(txCipher, rxCipher, (raw) => {
    loopbackFrames.push(raw);
  });

  const originalFrame = new ServiceFrame({
    stream_id: 1n,
    request: new ApplicationRequest({
      verb: "POST",
      path: "/chat/stream",
      headers: [new Header({ key: "content-type", value: "application/json" })],
      body: new TextEncoder().encode('{"prompt":"Say hello in three words."}'),
      end_body: true,
    }),
  });

  const sent = await transport.sendFrame(1n, originalFrame);
  assert.strictEqual(sent.length, 1);
  assert.strictEqual(loopbackFrames.length, 1);

  // Verify that the sent raw frame is encrypted (AES-GCM tag present, ciphertext does not contain plaintext string)
  const decodedTransportFrame = decodeNoiseTransportFrame(loopbackFrames[0]);
  const rawString = new TextDecoder().decode(decodedTransportFrame.payload);
  assert.strictEqual(rawString.includes("Say hello in three words."), false, "Payload over wire must be ciphertext");

  // Loopback to receiver
  const received = await transport.handleIncoming(loopbackFrames[0]);
  assert(received instanceof ServiceFrame);
  assert.strictEqual(received.stream_id, 1n);
  assert.strictEqual(received.kind.case, "request");
  assert.strictEqual(received.request.verb, "POST");
  assert.strictEqual(received.request.path, "/chat/stream");
  assert.deepStrictEqual(received.request.body, originalFrame.request.body);
  assert.strictEqual(received.request.end_body, true);
});

test("Suite 4.2: End-to-end encrypted loopback with large payload (> 65,489 bytes splitting)", async () => {
  const sharedKey = new Uint8Array(32).fill(0x6b);
  const txCipher = new CipherState(sharedKey);
  const rxCipher = new CipherState(sharedKey);

  const loopbackFrames = [];
  const transport = new NoiseTransport(txCipher, rxCipher, (raw) => {
    loopbackFrames.push(raw);
  });

  const largeBody = generateTestPayload(150_000, 777); // 150 KB
  const originalFrame = new ServiceFrame({
    stream_id: 2n,
    request: new ApplicationRequest({
      verb: "POST",
      path: "/upload",
      body: largeBody,
      end_body: true,
    }),
  });

  const sentFrames = await transport.sendFrame(2n, originalFrame);
  assert(sentFrames.length > 1, `150 KB must split into multiple frames, got ${sentFrames.length}`);
  assert.strictEqual(sentFrames.length, loopbackFrames.length);

  // Feed chunks to receiver
  for (let i = 0; i < sentFrames.length - 1; i++) {
    const intermediate = await transport.handleIncoming(sentFrames[i]);
    assert.strictEqual(intermediate, null, `Chunk ${i} must return null`);
  }

  const finalFrame = await transport.handleIncoming(sentFrames[sentFrames.length - 1]);
  assert(finalFrame instanceof ServiceFrame);
  assert.strictEqual(finalFrame.stream_id, 2n);
  assert.strictEqual(finalFrame.request.verb, "POST");
  assert.strictEqual(finalFrame.request.path, "/upload");
  assert.strictEqual(finalFrame.request.body.length, 150_000);
  assert.deepStrictEqual(finalFrame.request.body, largeBody, "Large body must reassemble and decrypt with exact bitwise equality");
});

test("Suite 4.3: End-to-end loopback with out-of-order encrypted transport chunks", async () => {
  const sharedKey = new Uint8Array(32).fill(0x7c);
  const txCipher = new CipherState(sharedKey);
  const rxCipher = new CipherState(sharedKey);

  const loopbackFrames = [];
  const transport = new NoiseTransport(txCipher, rxCipher, (raw) => {
    loopbackFrames.push(raw);
  });

  const largeBody = generateTestPayload(150_000, 888);
  const originalFrame = new ServiceFrame({
    stream_id: 3n,
    request: new ApplicationRequest({
      verb: "POST",
      path: "/data",
      body: largeBody,
      end_body: true,
    }),
  });

  const sent = await transport.sendFrame(3n, originalFrame);
  assert.strictEqual(sent.length, 3);

  // Reorder chunks: 2, 0, 1
  const step1 = await transport.handleIncoming(sent[2]);
  assert.strictEqual(step1, null);

  const step2 = await transport.handleIncoming(sent[0]);
  assert.strictEqual(step2, null);

  const finalFrame = await transport.handleIncoming(sent[1]);
  assert(finalFrame instanceof ServiceFrame);
  assert.strictEqual(finalFrame.stream_id, 3n);
  assert.deepStrictEqual(finalFrame.request.body, largeBody, "Out-of-order encrypted chunks must reassemble and decrypt properly");
});

test("Suite 4.4: Stream multiplexing with monotonic stream IDs and callbacks", async () => {
  const clientTxKey = new Uint8Array(32).fill(0x8d);
  const serverTxKey = new Uint8Array(32).fill(0x8e);

  const clientTxCipher = new CipherState(clientTxKey);
  const clientRxCipher = new CipherState(serverTxKey);
  const serverTxCipher = new CipherState(serverTxKey);
  const serverRxCipher = new CipherState(clientTxKey);

  const clientTransport = new NoiseTransport(clientTxCipher, clientRxCipher, () => {});
  const serverTransport = new NoiseTransport(serverTxCipher, serverRxCipher, () => {});

  const framesStream1 = [];
  const framesStream2 = [];

  // Send request on stream 1
  const req1 = await clientTransport.sendRequest(
    "POST",
    "/chat/stream",
    [],
    '{"id":1}',
    true,
    (frame) => framesStream1.push(frame)
  );
  assert.strictEqual(req1.streamId, 1n);

  // Send request on stream 2
  const req2 = await clientTransport.sendRequest(
    "GET",
    "/api/ping",
    [],
    "",
    true,
    (frame) => framesStream2.push(frame)
  );
  assert.strictEqual(req2.streamId, 2n);

  // Server sends responses back to client
  // Create response for stream 1
  const respFrame1 = new ServiceFrame({
    stream_id: 1n,
    body_chunk: new BodyChunk({
      data: new TextEncoder().encode("delta for stream 1"),
      end_body: true,
    }),
  });
  const encResp1 = await serverTransport.sendFrame(1n, respFrame1);

  // Create response for stream 2
  const respFrame2 = new ServiceFrame({
    stream_id: 2n,
    response: new ApplicationResponse({
      status: 200,
      body: new TextEncoder().encode('{"pong":true}'),
      end_body: true,
    }),
  });
  const encResp2 = await serverTransport.sendFrame(2n, respFrame2);

  // Feed to client handleIncoming
  await clientTransport.handleIncoming(encResp1[0]);
  assert.strictEqual(framesStream1.length, 1);
  assert.strictEqual(framesStream1[0].stream_id, 1n);
  assert.strictEqual(framesStream1[0].kind.case, "body_chunk");

  await clientTransport.handleIncoming(encResp2[0]);
  assert.strictEqual(framesStream2.length, 1);
  assert.strictEqual(framesStream2[0].stream_id, 2n);
  assert.strictEqual(framesStream2[0].kind.case, "response");
  assert.strictEqual(framesStream2[0].response.status, 200);
});

test("Suite 4.5: Stream cancellation with Reset frame", async () => {
  const sharedKey = new Uint8Array(32).fill(0x9e);
  const txCipher = new CipherState(sharedKey);
  const rxCipher = new CipherState(sharedKey);

  const sentFrames = [];
  const transport = new NoiseTransport(txCipher, rxCipher, (raw) => {
    sentFrames.push(raw);
  });

  transport.registerStream(5n, () => {});
  assert.strictEqual(transport.streams.has(5n), true);

  const resetFrames = await transport.cancelStream(5n, "user_stop");
  assert.strictEqual(transport.streams.has(5n), false, "Stream 5 must be deleted upon cancellation");
  assert(resetFrames.length > 0);

  // Receive the reset frame on receiver
  const received = await transport.handleIncoming(resetFrames[0]);
  assert.strictEqual(received.stream_id, 5n);
  assert.strictEqual(received.kind.case, "reset");
  assert.strictEqual(received.reset.code, ResetCode.CANCELLED);
  assert.strictEqual(received.reset.reason, "user_stop");
});

test("Suite 4.6: Empty ServiceResponse payload rejection", async () => {
  const sharedKey = new Uint8Array(32).fill(0xaf);
  const txCipher = new CipherState(sharedKey);
  const rxCipher = new CipherState(sharedKey);

  const transport = new NoiseTransport(txCipher, rxCipher);

  // Create an empty ServiceResponse: tag 1 (0x0a), length 0 (0x00)
  const emptyServiceResponse = new Uint8Array([0x0a, 0x00]);
  const ciphertext = await txCipher.encryptWithAd(new Uint8Array(0), emptyServiceResponse);

  const transportFrame = new NoiseTransportFrame({
    chunk_id: 1111n,
    chunk_index: 0,
    total_chunks: 1,
    payload: ciphertext,
  });
  const encoded = encodeNoiseTransportFrame(transportFrame);

  await assert.rejects(
    async () => transport.handleIncoming(encoded),
    /empty ServiceResponse payload/,
    "Empty ServiceResponse payload must be rejected"
  );
});
