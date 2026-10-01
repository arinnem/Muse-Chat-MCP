/**
 * test/test-adversarial-probe.mjs
 * ------------------------------------------------------------------
 * Adversarial Stress-Testing and Empirical Edge-Case Verification Suite
 * for Phase 2 Headless Noise Client and Native Tool Calling.
 *
 * Authored by: challenger_final_1 (Empirical Challenger)
 * Scope:
 *   1. Cryptographic Edge Cases (lib/noise/crypto.mjs)
 *   2. Wire Framing & Transport Edge Cases (lib/noise/proto.mjs, lib/noise/transport.mjs)
 *   3. Network, Token & Fallback Edge Cases (lib/noise/token-manager.mjs, lib/noise/noise-client.mjs, muse-transport.mjs)
 * ------------------------------------------------------------------
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import http from 'node:http'

import {
  CipherState,
  SymmetricState,
  NoiseXXInitiator,
  x25519DH,
  generateX25519KeyPair,
  destroyX25519KeyPair,
  isLowOrderPoint,
  CURVE25519_LOW_ORDER_POINTS,
  ALL_ZEROS_32,
  formatNonce,
  zeroize,
  concat,
  toBufferSource,
  constantTimeEqual,
} from '../lib/noise/crypto.mjs'

import {
  BinaryWriter,
  BinaryReader,
  WireType,
  ResetCode,
  ServiceType,
  NoiseTransportFrame,
  ServiceRequest,
  ServiceResponse,
  ServiceFrame,
  ApplicationRequest,
  ApplicationResponse,
  BodyChunk,
  Reset,
  Header,
  encodeNoiseTransportFrame,
  decodeNoiseTransportFrame,
  encodeServiceFrame,
  decodeServiceFrame,
  encodeApplicationRequest,
  decodeApplicationRequest,
  encodeApplicationResponse,
  decodeApplicationResponse,
  encodeBodyChunk,
  decodeBodyChunk,
  encodeReset,
  decodeReset,
  encodeHeader,
  decodeHeader,
} from '../lib/noise/proto.mjs'

import {
  NoiseFrameDecoder,
  NoiseTransport,
  MAX_PAYLOAD_CHUNK_SIZE,
  MAX_TOTAL_CHUNKS,
  MAX_CONCURRENT_ASSEMBLIES,
  MAX_ASSEMBLY_BYTES,
  DEFAULT_ASSEMBLY_TIMEOUT_MS,
} from '../lib/noise/transport.mjs'

import {
  TokenManager,
  AuthSessionExpiredError,
  parseCookieString,
  formatCookieHeader,
  normalizeCookies,
} from '../lib/noise/token-manager.mjs'

import { NoiseClient } from '../lib/noise/noise-client.mjs'
import { MuseTransport } from '../muse-transport.mjs'

// =============================================================================
// CATEGORY 1: Cryptographic Edge Cases (lib/noise/crypto.mjs)
// =============================================================================

test('1.1 Nonce counter overflow at Number.MAX_SAFE_INTEGER and state poisoning', async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const cipher = new CipherState();
  await cipher.initializeKey(key, Number.MAX_SAFE_INTEGER);

  assert.strictEqual(cipher.nonce, Number.MAX_SAFE_INTEGER);

  const plaintext = new TextEncoder().encode('confidential payload');
  const ad = new TextEncoder().encode('auth_data');

  // Attempting to encrypt at Number.MAX_SAFE_INTEGER must throw and poison cipher
  await assert.rejects(
    async () => {
      await cipher.encryptWithAd(ad, plaintext);
    },
    (err) => {
      assert.match(err.message, /nonce exhausted/);
      return true;
    }
  );

  // Subsequent encrypt MUST fail due to poisoning, even if counter could somehow reset
  await assert.rejects(
    async () => {
      await cipher.encryptWithAd(ad, plaintext);
    },
    (err) => {
      assert.match(err.message, /poisoned after prior failure/);
      return true;
    }
  );

  // Subsequent decrypt MUST ALSO fail due to poisoning
  await assert.rejects(
    async () => {
      await cipher.decryptWithAd(ad, new Uint8Array(32));
    },
    (err) => {
      assert.match(err.message, /poisoned after prior failure/);
      return true;
    }
  );

  // Test decrypt at Number.MAX_SAFE_INTEGER also exhausts and poisons
  const cipher2 = new CipherState();
  const key2 = crypto.getRandomValues(new Uint8Array(32));
  await cipher2.initializeKey(key2, Number.MAX_SAFE_INTEGER);

  await assert.rejects(
    async () => {
      await cipher2.decryptWithAd(ad, new Uint8Array(32));
    },
    (err) => {
      assert.match(err.message, /nonce exhausted/);
      return true;
    }
  );

  // Verify cipher2 is poisoned
  await assert.rejects(
    async () => {
      await cipher2.decryptWithAd(ad, new Uint8Array(32));
    },
    (err) => {
      assert.match(err.message, /poisoned after prior failure/);
      return true;
    }
  );
});

test('1.2 Rejection of all 7 canonical low-order Curve25519 points', async () => {
  assert.strictEqual(CURVE25519_LOW_ORDER_POINTS.length, 7);

  const localKp = await generateX25519KeyPair();
  try {
    for (let i = 0; i < CURVE25519_LOW_ORDER_POINTS.length; i++) {
      const pt = CURVE25519_LOW_ORDER_POINTS[i];
      assert.strictEqual(pt.length, 32, `Point ${i} must be 32 bytes`);

      // isLowOrderPoint must recognize it
      assert.strictEqual(isLowOrderPoint(pt), true, `Point ${i} must be identified as low-order`);

      // x25519DH must reject it with exact error message
      await assert.rejects(
        async () => {
          await x25519DH(localKp.privateKey, pt);
        },
        (err) => {
          assert.match(err.message, /x25519: rejected low-order public key/);
          return true;
        },
        `x25519DH must reject low-order point index ${i}`
      );
    }

    // Verify a legitimate point is not flagged as low-order
    assert.strictEqual(isLowOrderPoint(localKp.publicKeyBytes), false);
  } finally {
    destroyX25519KeyPair(localKp);
  }
});

test('1.3 Rejection of all-zeros DH scalar multiplication and invalid key sizes', async () => {
  const localKp = await generateX25519KeyPair();
  try {
    // 1. Invalid remote public key length
    for (const len of [0, 16, 31, 33, 64]) {
      const badPub = new Uint8Array(len);
      await assert.rejects(
        async () => {
          await x25519DH(localKp.privateKey, badPub);
        },
        (err) => {
          assert.match(err.message, /x25519: invalid public key length/);
          return true;
        }
      );
    }

    // 2. Invalid private key length
    for (const len of [16, 31, 33]) {
      const badPriv = new Uint8Array(len);
      await assert.rejects(
        async () => {
          await x25519DH(badPriv, localKp.publicKeyBytes);
        },
        (err) => {
          assert.match(err.message, /x25519: invalid private key length/);
          return true;
        }
      );
    }

    // 3. Rejection of unsupported private key type
    await assert.rejects(
      async () => {
        await x25519DH('not_a_valid_key', localKp.publicKeyBytes);
      },
      (err) => {
        assert.match(err.message, /x25519: unsupported private key type/);
        return true;
      }
    );
  } finally {
    destroyX25519KeyPair(localKp);
  }
});

test('1.4 Truncated or tampered handshake messages (< 96 bytes Message 2)', async () => {
  // Test truncated Message 2 at various boundaries
  for (const len of [0, 1, 32, 48, 64, 95]) {
    const initiator = new NoiseXXInitiator();
    await initiator.writeMessage1();

    const truncated = new Uint8Array(len);
    await assert.rejects(
      async () => {
        await initiator.readMessage2(truncated);
      },
      (err) => {
        assert.match(err.message, /NoiseXX: message 2 too short/);
        return true;
      }
    );

    // Initiator must be in dead phase 6
    await assert.rejects(
      async () => {
        await initiator.writeMessage3();
      },
      (err) => {
        assert.match(err.message, /dead handshake/);
        return true;
      }
    );
  }

  // Test tampered Message 2 (bit flip in ciphertext)
  // To construct a valid Message 2, perform real handshake step with a responder
  const initiator = new NoiseXXInitiator();
  const msg1 = await initiator.writeMessage1();

  const responderE = await generateX25519KeyPair();
  const responderS = await generateX25519KeyPair();
  const sym = new SymmetricState();
  await sym.initialize();

  // Responder processes msg1
  const rePub = msg1.subarray(0, 32);
  await sym.mixHash(rePub);
  await sym.decryptAndHash(msg1.subarray(32));

  // Responder writes msg2
  await sym.mixHash(responderE.publicKeyBytes);
  const ee = await x25519DH(responderE.privateKey, rePub);
  await sym.mixKey(ee);
  zeroize(ee);

  const encRs = await sym.encryptAndHash(responderS.publicKeyBytes);
  const es = await x25519DH(responderS.privateKey, rePub);
  await sym.mixKey(es);
  zeroize(es);

  const payload = new TextEncoder().encode('valid server attestation');
  const encPayload = await sym.encryptAndHash(payload);

  const validMsg2 = concat(responderE.publicKeyBytes, encRs, encPayload);
  assert.ok(validMsg2.length >= 96);

  // Corrupt 1 byte in rs ciphertext tag (byte 50)
  const tamperedMsg2 = new Uint8Array(validMsg2);
  tamperedMsg2[50] ^= 0x01;

  await assert.rejects(
    async () => {
      await initiator.readMessage2(tamperedMsg2);
    },
    /operation failed|decrypt/i
  );

  // Initiator must be dead after corruption
  await assert.rejects(
    async () => {
      await initiator.split();
    },
    (err) => {
      assert.match(err.message, /dead handshake/);
      return true;
    }
  );

  destroyX25519KeyPair(responderE);
  destroyX25519KeyPair(responderS);
});

test('1.5 Sensitive key zeroization verification', async () => {
  // 1. Verify CipherState.initializeKey zeroizes input buffer
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const snapshot = new Uint8Array(rawKey);
  assert.ok(!constantTimeEqual(rawKey, ALL_ZEROS_32));

  const cipher = new CipherState();
  await cipher.initializeKey(rawKey);

  // rawKey buffer must now be zeroed
  assert.ok(constantTimeEqual(rawKey, ALL_ZEROS_32), 'initializeKey must zero input buffer');

  // 2. Verify CipherState.zeroize resets keys
  cipher.zeroize();
  assert.strictEqual(cipher.hasKey(), false);
  assert.strictEqual(cipher.nonce, 0);

  // 3. Verify destroyX25519KeyPair zeroizes publicKeyBytes
  const kp = await generateX25519KeyPair();
  assert.ok(!constantTimeEqual(kp.publicKeyBytes, ALL_ZEROS_32));
  destroyX25519KeyPair(kp);
  assert.ok(constantTimeEqual(kp.publicKeyBytes, ALL_ZEROS_32), 'destroyX25519KeyPair must zero public key');

  // 4. Verify zeroize() utility function
  const testBuf = new Uint8Array([1, 2, 3, 4, 5]);
  zeroize(testBuf);
  assert.deepStrictEqual(Array.from(testBuf), [0, 0, 0, 0, 0]);
});

// =============================================================================
// CATEGORY 2: Wire Framing & Transport Edge Cases
// =============================================================================

test('2.1 Malformed varints (> 10 bytes), truncated varints, wire type mismatches', () => {
  // 1. Malformed varint exceeding 10 bytes (11 continuous 0x80 bytes)
  const tooLongVarint = new Uint8Array(12).fill(0x80);
  const reader1 = new BinaryReader(tooLongVarint);
  assert.throws(
    () => {
      reader1.readVarint64();
    },
    (err) => {
      assert.match(err.message, /malformed varint exceeds 10 bytes/);
      return true;
    }
  );

  // 2. Truncated varint (byte with MSB 1 at EOF)
  const truncatedVarint = new Uint8Array([0x80]);
  const reader2 = new BinaryReader(truncatedVarint);
  assert.throws(
    () => {
      reader2.readVarint64();
    },
    (err) => {
      assert.match(err.message, /truncated varint64/);
      return true;
    }
  );

  // 3. Wire type mismatch in decodeNoiseTransportFrame
  // Field 1 (chunk_id) expects VARINT (0), provide LENGTH_DELIMITED (2)
  const badWireWriter = new BinaryWriter();
  badWireWriter.writeTag(1, WireType.LENGTH_DELIMITED);
  badWireWriter.writeLengthDelimited(new Uint8Array([1, 2, 3]));
  const badWireBytes = badWireWriter.finish();

  assert.throws(
    () => {
      decodeNoiseTransportFrame(badWireBytes);
    },
    (err) => {
      assert.match(err.message, /expected wireType 0, got 2/);
      return true;
    }
  );

  // 4. Invalid field number 0
  const zeroFieldTagWriter = new BinaryWriter();
  zeroFieldTagWriter.writeVarint32(0); // field 0, wireType 0
  const zeroTagBytes = zeroFieldTagWriter.finish();
  const zeroTagReader = new BinaryReader(zeroTagBytes);
  assert.throws(
    () => {
      zeroTagReader.readTag();
    },
    (err) => {
      assert.match(err.message, /invalid field number 0/);
      return true;
    }
  );

  // 5. Truncated length-delimited byte stream
  const truncatedLengthWriter = new BinaryWriter();
  truncatedLengthWriter.writeVarint32(100); // Claims 100 bytes follow
  truncatedLengthWriter.writeBytes(new Uint8Array([1, 2, 3])); // Only 3 bytes follow
  const truncatedLengthBytes = truncatedLengthWriter.finish();
  const truncatedReader = new BinaryReader(truncatedLengthBytes);
  assert.throws(
    () => {
      truncatedReader.readLengthDelimited();
    },
    (err) => {
      assert.match(err.message, /unexpected end of buffer/);
      return true;
    }
  );
});

test('2.2 Chunk splitting and out-of-order reassembly of large payloads (> 65,489 bytes)', () => {
  const decoder = new NoiseFrameDecoder();

  // Create a large 200,000-byte payload using node:crypto randomBytes
  const original = new Uint8Array(crypto.randomBytes(200000));
  const chunkId = 987654321n;

  // Split into chunks of MAX_PAYLOAD_CHUNK_SIZE
  const chunks = [];
  const totalChunks = Math.ceil(original.length / MAX_PAYLOAD_CHUNK_SIZE);
  assert.strictEqual(totalChunks, 4);

  for (let i = 0; i < totalChunks; i++) {
    const start = i * MAX_PAYLOAD_CHUNK_SIZE;
    const end = Math.min(start + MAX_PAYLOAD_CHUNK_SIZE, original.length);
    const slice = original.subarray(start, end);
    chunks.push(new NoiseTransportFrame({
      chunk_id: chunkId,
      chunk_index: i,
      total_chunks: totalChunks,
      payload: slice,
    }));
  }

  // Push chunks in non-sequential order: [2, 0, 3, 1]
  const shuffleOrder = [2, 0, 3, 1];
  let assembled = null;

  for (let step = 0; step < shuffleOrder.length; step++) {
    const idx = shuffleOrder[step];
    const encoded = encodeNoiseTransportFrame(chunks[idx]);
    const res = decoder.push(encoded);
    if (step < shuffleOrder.length - 1) {
      assert.strictEqual(res, null, `Step ${step} with chunk ${idx} must return null (still pending)`);
    } else {
      assembled = res;
    }
  }

  assert.ok(assembled instanceof Uint8Array, 'Final step must return assembled Uint8Array');
  assert.strictEqual(assembled.length, original.length);
  assert.ok(constantTimeEqual(assembled, original), 'Reassembled bytes must be bitwise identical');
  assert.strictEqual(decoder.pendingCount, 0, 'Decoder must have 0 pending assemblies after completion');
});

test('2.3 Assembly limits: max 16 concurrent pending assemblies (17th rejected)', () => {
  const decoder = new NoiseFrameDecoder();

  // Fill up 16 concurrent pending assemblies
  for (let i = 1; i <= 16; i++) {
    const frame = new NoiseTransportFrame({
      chunk_id: BigInt(i),
      chunk_index: 0,
      total_chunks: 2,
      payload: new Uint8Array([i]),
    });
    const res = decoder.push(frame);
    assert.strictEqual(res, null);
  }

  assert.strictEqual(decoder.pendingCount, 16);

  // 17th pending assembly must throw
  const frame17 = new NoiseTransportFrame({
    chunk_id: 17n,
    chunk_index: 0,
    total_chunks: 2,
    payload: new Uint8Array([17]),
  });

  assert.throws(
    () => {
      decoder.push(frame17);
    },
    (err) => {
      assert.match(err.message, /too many pending noise frame assemblies/);
      return true;
    }
  );

  // Complete one assembly (chunkId 1)
  const finishFrame1 = new NoiseTransportFrame({
    chunk_id: 1n,
    chunk_index: 1,
    total_chunks: 2,
    payload: new Uint8Array([101]),
  });
  const completed = decoder.push(finishFrame1);
  assert.ok(completed instanceof Uint8Array);
  assert.strictEqual(decoder.pendingCount, 15);

  // Now frame17 can be accepted without error
  const res17 = decoder.push(frame17);
  assert.strictEqual(res17, null);
  assert.strictEqual(decoder.pendingCount, 16);
});

test('2.4 Cumulative byte budget limits (16 MiB max)', () => {
  // Use a decoder with a small test budget to test budget enforcement
  const decoder = new NoiseFrameDecoder({ maxAssemblyBytes: 1000 });

  const chunkId = 555n;
  const chunk1 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 0,
    total_chunks: 3,
    payload: new Uint8Array(600),
  });

  // 600 bytes is within 1000 byte budget
  const res1 = decoder.push(chunk1);
  assert.strictEqual(res1, null);
  assert.strictEqual(decoder.hasAssembly(chunkId), true);

  // Next chunk adds 500 bytes -> total 1100 > 1000 byte budget -> must throw and purge
  const chunk2 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 1,
    total_chunks: 3,
    payload: new Uint8Array(500),
  });

  assert.throws(
    () => {
      decoder.push(chunk2);
    },
    (err) => {
      assert.match(err.message, /assembly exceeded byte budget/);
      return true;
    }
  );

  // Assembly must be deleted from decoder so no memory leak
  assert.strictEqual(decoder.hasAssembly(chunkId), false);
  assert.strictEqual(decoder.pendingCount, 0);
});

test('2.5 Stale assembly timeout purge (60s)', () => {
  const decoder = new NoiseFrameDecoder({ timeoutMs: 50 }); // 50ms timeout for testing

  const chunkId = 777n;
  const chunk1 = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 0,
    total_chunks: 2,
    payload: new Uint8Array([1, 2, 3]),
  });

  decoder.push(chunk1);
  assert.strictEqual(decoder.hasAssembly(chunkId), true);

  // Wait 70ms for expiration
  return new Promise((resolve) => {
    setTimeout(() => {
      // Pushing a new chunk triggers purgeExpired()
      const newChunk = new NoiseTransportFrame({
        chunk_id: 888n,
        chunk_index: 0,
        total_chunks: 2,
        payload: new Uint8Array([4, 5, 6]),
      });
      decoder.push(newChunk);

      // Stale assembly 777 must have been purged
      assert.strictEqual(decoder.hasAssembly(chunkId), false);
      assert.strictEqual(decoder.hasAssembly(888n), true);
      assert.strictEqual(decoder.pendingCount, 1);
      resolve();
    }, 70);
  });
});

test('2.6 Duplicate chunk index and inconsistent total_chunks handling', () => {
  const decoder = new NoiseFrameDecoder();
  const chunkId = 999n;

  // 1. Duplicate chunk index
  const chunk0a = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 0,
    total_chunks: 3,
    payload: new Uint8Array([1]),
  });
  decoder.push(chunk0a);

  const chunk0b = new NoiseTransportFrame({
    chunk_id: chunkId,
    chunk_index: 0,
    total_chunks: 3,
    payload: new Uint8Array([1]),
  });

  assert.throws(
    () => {
      decoder.push(chunk0b);
    },
    (err) => {
      assert.match(err.message, /duplicate chunkIndex 0/);
      return true;
    }
  );
  // Must purge on error
  assert.strictEqual(decoder.hasAssembly(chunkId), false);

  // 2. Inconsistent total_chunks
  const id2 = 1000n;
  const chunkA = new NoiseTransportFrame({
    chunk_id: id2,
    chunk_index: 0,
    total_chunks: 3,
    payload: new Uint8Array([1]),
  });
  decoder.push(chunkA);

  const chunkB = new NoiseTransportFrame({
    chunk_id: id2,
    chunk_index: 1,
    total_chunks: 4, // Inconsistent with 3
    payload: new Uint8Array([2]),
  });

  assert.throws(
    () => {
      decoder.push(chunkB);
    },
    (err) => {
      assert.match(err.message, /inconsistent totalChunks/);
      return true;
    }
  );
  assert.strictEqual(decoder.hasAssembly(id2), false);

  // 3. Payload size exceeding MAX_PAYLOAD_CHUNK_SIZE (65,489)
  const oversized = new NoiseTransportFrame({
    chunk_id: 1001n,
    chunk_index: 0,
    total_chunks: 1,
    payload: new Uint8Array(65490),
  });
  assert.throws(
    () => {
      decoder.push(oversized);
    },
    (err) => {
      assert.match(err.message, /payload too large/);
      return true;
    }
  );

  // 4. Invalid total_chunks (> 256 or < 1)
  assert.throws(() => {
    decoder.push(new NoiseTransportFrame({ chunk_id: 1002n, chunk_index: 0, total_chunks: 257, payload: new Uint8Array(1) }));
  }, /invalid totalChunks/);

  assert.throws(() => {
    decoder.push(new NoiseTransportFrame({ chunk_id: 1003n, chunk_index: 0, total_chunks: 0, payload: new Uint8Array(1) }));
  }, /invalid totalChunks/);

  // 5. Chunk index >= total_chunks
  assert.throws(() => {
    decoder.push(new NoiseTransportFrame({ chunk_id: 1004n, chunk_index: 3, total_chunks: 3, payload: new Uint8Array(1) }));
  }, /chunkIndex 3 out of range/);
});

// =============================================================================
// CATEGORY 3: Network, Token & Fallback Edge Cases
// =============================================================================

test('3.1 Unreachable gateway (ECONNREFUSED) / handshake timeout / closed port', async () => {
  // Connect to a closed local port
  class MockTokenManager extends TokenManager {
    constructor() {
      super({ cookies: { c_user: '123' } })
    }
    async ensureValidSession() {
      return {
        vm_id: 'vm-test-unreachable',
        endpoint_url: 'ws://127.0.0.1:59999/v1/noise',
        auth_token: 'tok-test',
        notary_token: 'notary-test',
        expiresAt: Date.now() + 3600000,
      }
    }
    invalidateToken() {}
  }

  const fakeTokenManager = new MockTokenManager();

  const client = new NoiseClient({
    tokenManager: fakeTokenManager,
    wsUrl: 'ws://127.0.0.1:59999/v1/noise',
    timeoutMs: 1000,
  });

  await assert.rejects(
    async () => {
      await client.connect();
    },
    /connection error|handshake/i
  );

  // Test that MuseTransport gracefully handles this connection error
  let fallbackBrowserChatCalled = false;
  const mockBrowserDriver = {
    status: async () => ({ browserRunning: true, loggedIn: true }),
    chat: async (prompt) => {
      fallbackBrowserChatCalled = true;
      return { text: `Browser reply to: ${prompt}`, reply: `Browser reply to: ${prompt}` };
    },
    close: async () => {},
  };

  const transport = new MuseTransport({
    driver: mockBrowserDriver,
    noiseClient: client,
    tokenManager: fakeTokenManager,
  });

  const chatRes = await transport.chat('Hello world');
  assert.strictEqual(fallbackBrowserChatCalled, true);
  assert.strictEqual(transport.fallbackActive, true);
  assert.strictEqual(transport.activeTransport, 'browser');
  assert.match(transport.fallbackReason, /WebSocket connection error/i);
});

test('3.2 Stale session cookies and expired Ed25519 tokens (HTTP 401/403)', async () => {
  // Mock fetch returning HTTP 403 on wakeVm
  const mockFetch403 = async (url, opts) => {
    return {
      status: 403,
      ok: false,
      statusText: 'Forbidden',
      json: async () => ({ error: 'Forbidden' }),
      text: async () => JSON.stringify({ error: 'Forbidden' }),
    };
  };

  const tm403 = new TokenManager({
    cookies: { c_user: '12345', xs: 'abcde' },
    fetch: mockFetch403,
  });

  await assert.rejects(
    async () => {
      await tm403.wakeVm();
    },
    (err) => {
      assert.ok(err instanceof AuthSessionExpiredError);
      assert.strictEqual(err.status, 403);
      assert.match(err.message, /Auth session expired or forbidden/);
      return true;
    }
  );

  // Mock fetch returning HTTP 401 on getToken
  const mockFetch401 = async (url, opts) => {
    return {
      status: 401,
      ok: false,
      statusText: 'Unauthorized',
      json: async () => ({ error: 'Session Expired' }),
      text: async () => JSON.stringify({ error: 'Session Expired' }),
    };
  };

  const tm401 = new TokenManager({
    cookies: { c_user: '12345', xs: 'abcde' },
    fetch: mockFetch401,
  });

  await assert.rejects(
    async () => {
      await tm401.getToken('vm-123');
    },
    (err) => {
      assert.ok(err instanceof AuthSessionExpiredError);
      assert.strictEqual(err.status, 401);
      return true;
    }
  );
});

test('3.3 Mandatory browser security headers (origin, referer, sec-fetch-*)', async () => {
  let capturedHeaders = null;
  let capturedUrl = null;

  const mockFetch = async (url, opts) => {
    capturedUrl = url;
    capturedHeaders = opts.headers;
    return {
      status: 200,
      ok: true,
      json: async () => ({ ok: true, vm_id: 'vm-test', auth_token: 'auth-test' }),
      text: async () => JSON.stringify({ ok: true }),
    };
  };

  const tm = new TokenManager({
    cookies: { c_user: '1000', xs: 'secret_token', datr: 'datr_token' },
    fetch: mockFetch,
  });

  await tm.wakeVm();

  assert.ok(capturedHeaders, 'Headers must be captured on outgoing fetch');
  assert.strictEqual(capturedHeaders['origin'], 'https://muse.ai');
  assert.strictEqual(capturedHeaders['referer'], 'https://muse.ai/');
  assert.strictEqual(capturedHeaders['sec-fetch-site'], 'same-origin');
  assert.strictEqual(capturedHeaders['sec-fetch-mode'], 'cors');
  assert.strictEqual(capturedHeaders['content-type'], 'application/json');
  assert.ok(capturedHeaders['user-agent'].includes('Chrome'), 'User-Agent must identify as Chrome browser');
  assert.ok(capturedHeaders['cookie'].includes('c_user=1000'), 'Cookie header must be present');
});

test('3.4 Circuit breaker stickiness and reset behavior', async () => {
  let browserChatCount = 0;
  let noiseConnectAttemptCount = 0;

  const mockDriver = {
    status: async () => ({ browserRunning: true, loggedIn: true }),
    chat: async (p) => {
      browserChatCount++;
      return { text: `Browser reply ${browserChatCount}`, reply: `Browser reply ${browserChatCount}` };
    },
    close: async () => {},
  };

  class MockFailingClient {
    constructor() {
      this.connected = false;
    }
    async connect() {
      noiseConnectAttemptCount++;
      throw new Error('Connection refused');
    }
    async close() {}
  }

  const transport = new MuseTransport({
    driver: mockDriver,
    NoiseClientClass: MockFailingClient,
  });

  assert.strictEqual(transport.activeTransport, 'noise');
  assert.strictEqual(transport.fallbackActive, false);

  // Request 1: fails Noise -> triggers fallback
  await transport.chat('Prompt 1');
  assert.strictEqual(noiseConnectAttemptCount, 1);
  assert.strictEqual(browserChatCount, 1);
  assert.strictEqual(transport.fallbackActive, true);
  assert.strictEqual(transport.activeTransport, 'browser');

  // Request 2: circuit breaker is sticky! Directly routes to browser without touching Noise
  await transport.chat('Prompt 2');
  assert.strictEqual(noiseConnectAttemptCount, 1, 'Should NOT attempt Noise connection while breaker is open');
  assert.strictEqual(browserChatCount, 2);

  // Reset circuit breaker
  transport.resetFallback();
  assert.strictEqual(transport.fallbackActive, false);
  assert.strictEqual(transport.activeTransport, 'noise');

  // Request 3: attempts Noise again
  await transport.chat('Prompt 3');
  assert.strictEqual(noiseConnectAttemptCount, 2, 'Should re-attempt Noise after circuit breaker reset');
  assert.strictEqual(browserChatCount, 3);
  assert.strictEqual(transport.fallbackActive, true);
});

test('3.5 Mid-stream socket drops without unhandled promise rejections', async () => {
  // Simulate mid-stream failure during chatStream
  let browserStreamCalled = false;
  const mockDriver = {
    chatStream: async (prompt, opts) => {
      browserStreamCalled = true;
      if (opts.onDelta) opts.onDelta('Fallback stream data');
      return { text: 'Fallback stream data', reply: 'Fallback stream data' };
    },
    close: async () => {},
  };

  const mockDroppingClient = {
    connected: true,
    chatStream: async () => {
      throw new Error('WebSocket closed prematurely during generation');
    },
    close: async () => {},
  };

  const transport = new MuseTransport({
    driver: mockDriver,
    noiseClient: mockDroppingClient,
  });

  let deltaReceived = '';
  const result = await transport.chatStream('Stream test prompt', {
    onDelta: (d) => { deltaReceived = d; },
  });

  assert.strictEqual(browserStreamCalled, true);
  assert.strictEqual(deltaReceived, 'Fallback stream data');
  assert.strictEqual(result.text, 'Fallback stream data');
  assert.strictEqual(transport.fallbackActive, true);
});

test('3.6 Seamless fallback across all auxiliary methods with zero client crashes', async () => {
  const mockDriver = {
    newChat: async () => ({ ok: true, activeChat: null, transport: 'browser' }),
    listChats: async () => [{ id: 'chat_1', title: 'Chat 1' }],
    openChat: async () => ({ ok: true }),
    readChat: async () => ({ messages: [{ role: 'assistant', text: 'Hello' }] }),
    readLast: async () => ({ reply: 'Latest response' }),
    chatMedia: async () => [],
    login: async () => true,
    dumpDom: async () => '<html><body>OK</body></html>',
    status: async () => ({ browserRunning: true, loggedIn: true }),
    close: async () => {},
  };

  const mockFailingClient = {
    connected: false,
    connect: async () => { throw new Error('Noise RPC offline'); },
    close: async () => {},
  };

  const transport = new MuseTransport({
    driver: mockDriver,
    noiseClient: mockFailingClient,
  });

  // Verify each auxiliary method gracefully degrades without crashing
  const newChatRes = await transport.newChat();
  assert.strictEqual(newChatRes.ok, true);

  const listRes = await transport.listChats();
  assert.strictEqual(listRes.length, 1);

  const openRes = await transport.openChat('chat_1');
  assert.strictEqual(openRes.ok, true);

  const readRes = await transport.readChat();
  assert.strictEqual(readRes.messages.length, 1);

  const readLastRes = await transport.readLast();
  assert.strictEqual(readLastRes.reply, 'Latest response');

  const mediaRes = await transport.chatMedia('chat_1');
  assert.deepStrictEqual(mediaRes, []);

  const loginRes = await transport.login();
  assert.strictEqual(loginRes, true);

  const domRes = await transport.dumpDom();
  assert.strictEqual(domRes, '<html><body>OK</body></html>');

  const statusRes = await transport.status();
  assert.strictEqual(statusRes.browserRunning, true);
  assert.strictEqual(statusRes.fallbackActive, true);

  await transport.close();
});
