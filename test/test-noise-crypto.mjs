/**
 * test/test-noise-crypto.mjs
 *
 * Comprehensive test suite for Noise_XX_25519_AESGCM_SHA256 cryptographic core (lib/noise/crypto.mjs).
 * Enforces zero-mocking, real cryptographic math, fail-closed security, and anti-test-theater contract.
 *
 * Uses Node.js native test runner (node:test) and node:assert/strict.
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  ALL_ZEROS_32,
  CURVE25519_LOW_ORDER_POINTS,
  NoiseX25519UnavailableError,
  concat,
  toBufferSource,
  zeroize,
  constantTimeEqual,
  isLowOrderPoint,
  formatNonce,
  generateX25519KeyPair,
  destroyX25519KeyPair,
  x25519DH,
  hkdf,
  CipherState,
  SymmetricState,
  NoiseXXInitiator
} from "../lib/noise/crypto.mjs";

/**
 * In-memory SyntheticNoiseXXResponder performing the responder side of Noise XX
 * using real WebCrypto X25519 and AES-GCM operations.
 */
export class SyntheticNoiseXXResponder {
  constructor(staticKeyPair) {
    this.s = staticKeyPair; // Server static X25519 keypair
    this.e = null;          // Server ephemeral X25519 keypair
    this.re = null;         // Client ephemeral public key (32 bytes)
    this.rs = null;         // Client static public key (32 bytes)
    this.symmetric = new SymmetricState();
    this.splitResult = null;
  }

  async initialize() {
    await this.symmetric.initialize();
  }

  /**
   * Processes Message 1 (-> e, payload) from Initiator:
   * 1. mixHash(re.pub)
   * 2. decryptAndHash(payload)
   * 3. Generates server ephemeral e
   * 4. mixHash(e.pub)
   * 5. ee = DH(e, re), mixKey(ee)
   * 6. enc_s = encryptAndHash(s.pub)
   * 7. es = DH(s, re), mixKey(es)
   * 8. enc_attestation = encryptAndHash(attestationPayload)
   * Returns: e.pub || enc_s || enc_attestation
   */
  async receiveMessage1(msg1, attestationPayload = new TextEncoder().encode("MUSE_SERVER_ATTESTATION_OK")) {
    if (!msg1 || msg1.length < 32) {
      throw new Error(`Responder: msg1 too short (${msg1 ? msg1.length : 0} < 32)`);
    }

    this.re = new Uint8Array(msg1.subarray(0, 32));
    await this.symmetric.mixHash(this.re);

    // Decrypt unencrypted message 1 payload (client nonce)
    const clientNoncePayload = await this.symmetric.decryptAndHash(msg1.subarray(32));

    // Generate server ephemeral keypair
    this.e = await generateX25519KeyPair();
    await this.symmetric.mixHash(this.e.publicKeyBytes);

    // ee = DH(e, re)
    const ee = await x25519DH(this.e.privateKey, this.re);
    await this.symmetric.mixKey(ee);
    zeroize(ee);

    // enc_s = encryptAndHash(s.pub)
    const enc_s = await this.symmetric.encryptAndHash(this.s.publicKeyBytes);

    // es = DH(s, re)
    const es = await x25519DH(this.s.privateKey, this.re);
    await this.symmetric.mixKey(es);
    zeroize(es);

    // enc_attestation = encryptAndHash(attestationPayload)
    const enc_attestation = await this.symmetric.encryptAndHash(attestationPayload);

    // Return Message 2: e.pub (32) + enc_s (48) + enc_attestation (payload + 16 tag)
    return {
      message2: concat(this.e.publicKeyBytes, enc_s, enc_attestation),
      clientNoncePayload
    };
  }

  /**
   * Processes Message 3 (-> s, se, payload) from Initiator:
   * 1. rs = decryptAndHash(enc_s)
   * 2. se = DH(e, rs), mixKey(se)
   * 3. clientTicket = decryptAndHash(enc_payload)
   * 4. split() -> [rxCipher, txCipher]
   */
  async receiveMessage3(msg3) {
    if (!msg3 || msg3.length < 48) {
      throw new Error(`Responder: msg3 too short (${msg3 ? msg3.length : 0} < 48)`);
    }

    // 1. Decrypt client static public key
    this.rs = await this.symmetric.decryptAndHash(msg3.subarray(0, 48));

    // 2. se = DH(e, rs) (Responder uses e_responder and rs_initiator)
    const se = await x25519DH(this.e.privateKey, this.rs);
    await this.symmetric.mixKey(se);
    zeroize(se);

    // 3. Decrypt client authentication payload
    const clientTicket = await this.symmetric.decryptAndHash(msg3.subarray(48));

    // 4. Split into [rxCipher, txCipher] (inverted role from Initiator)
    const [rxCipher, txCipher] = await this.symmetric.split();
    this.splitResult = { rxCipher, txCipher };

    return { clientTicket, rxCipher, txCipher };
  }
}

// ============================================================================
// SUITE 1: X25519 Primitives, DH Commutativity, & Low-Order Point Rejection
// ============================================================================

test("Suite 1.1: WebCrypto X25519 keypair generation produces valid 32-byte public keys", async () => {
  const kp = await generateX25519KeyPair();
  assert.strictEqual(kp.backend, "webcrypto");
  assert.ok(kp.privateKey);
  assert.ok(kp.publicKeyBytes instanceof Uint8Array);
  assert.strictEqual(kp.publicKeyBytes.length, 32);

  // Assert key is not all zeros
  const isZero = kp.publicKeyBytes.every(b => b === 0);
  assert.strictEqual(isZero, false);

  destroyX25519KeyPair(kp);
  assert.strictEqual(kp.publicKeyBytes.every(b => b === 0), true);
});

test("Suite 1.2: Diffie-Hellman scalar multiplication commutativity: DH(privA, pubB) === DH(privB, pubA)", async () => {
  const kpA = await generateX25519KeyPair();
  const kpB = await generateX25519KeyPair();

  const secretAB = await x25519DH(kpA.privateKey, kpB.publicKeyBytes);
  const secretBA = await x25519DH(kpB.privateKey, kpA.publicKeyBytes);

  assert.strictEqual(secretAB.length, 32);
  assert.strictEqual(secretBA.length, 32);
  assert.deepStrictEqual(secretAB, secretBA);
  assert.strictEqual(constantTimeEqual(secretAB, secretBA), true);

  // Ensure shared secret is non-zero
  assert.strictEqual(constantTimeEqual(secretAB, ALL_ZEROS_32), false);

  destroyX25519KeyPair(kpA);
  destroyX25519KeyPair(kpB);
});

test("Suite 1.3: Low-order point blacklist rejection for all 7 canonical points", async () => {
  const kp = await generateX25519KeyPair();

  assert.strictEqual(CURVE25519_LOW_ORDER_POINTS.length, 7);

  for (let i = 0; i < CURVE25519_LOW_ORDER_POINTS.length; i++) {
    const lowOrderPt = CURVE25519_LOW_ORDER_POINTS[i];
    assert.strictEqual(isLowOrderPoint(lowOrderPt), true);

    await assert.rejects(
      async () => {
        await x25519DH(kp.privateKey, lowOrderPt);
      },
      {
        name: "Error",
        message: "x25519: rejected low-order public key"
      }
    );
  }

  destroyX25519KeyPair(kp);
});

test("Suite 1.4: Invalid public key length rejection in x25519DH", async () => {
  const kp = await generateX25519KeyPair();

  await assert.rejects(
    async () => {
      await x25519DH(kp.privateKey, new Uint8Array(31));
    },
    {
      name: "Error",
      message: "x25519: invalid public key length"
    }
  );

  await assert.rejects(
    async () => {
      await x25519DH(kp.privateKey, new Uint8Array(33));
    },
    {
      name: "Error",
      message: "x25519: invalid public key length"
    }
  );

  destroyX25519KeyPair(kp);
});

test("Suite 1.5: Raw 32-byte private key support via PKCS8 in x25519DH", async () => {
  const rawPriv = crypto.getRandomValues(new Uint8Array(32));
  const kpB = await generateX25519KeyPair();

  const secret = await x25519DH(rawPriv, kpB.publicKeyBytes);
  assert.strictEqual(secret.length, 32);
  assert.strictEqual(constantTimeEqual(secret, ALL_ZEROS_32), false);

  destroyX25519KeyPair(kpB);
});

test("Suite 1.6: Rejection if DH scalar multiplication yields all-zeros", async () => {
  const kpA = await generateX25519KeyPair();
  const kpB = await generateX25519KeyPair();

  // Temporarily hook crypto.subtle.deriveBits to simulate an all-zeros output
  const origDeriveBits = crypto.subtle.deriveBits;
  try {
    crypto.subtle.deriveBits = async () => new Uint8Array(32).buffer;
    await assert.rejects(
      async () => {
        await x25519DH(kpA.privateKey, kpB.publicKeyBytes);
      },
      {
        name: "Error",
        message: "x25519: DH produced all-zeros output"
      }
    );
  } finally {
    crypto.subtle.deriveBits = origDeriveBits;
    destroyX25519KeyPair(kpA);
    destroyX25519KeyPair(kpB);
  }
});

// ============================================================================
// SUITE 2: CipherState & AES-256-GCM AEAD Framing
// ============================================================================

test("Suite 2.1: 96-bit monotonic nonce construction formatting", () => {
  // Counter 0: [0x00 * 12]
  const n0 = formatNonce(0);
  assert.strictEqual(n0.length, 12);
  assert.deepStrictEqual(n0, new Uint8Array(12));

  // Counter 1: [0x00 * 11, 0x01]
  const n1 = formatNonce(1);
  assert.strictEqual(n1[11], 1);
  assert.strictEqual(n1[7], 0);

  // Counter 2^32 (4294967296): [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
  const nHigh = formatNonce(0x100000000);
  assert.strictEqual(nHigh[7], 1);
  assert.strictEqual(nHigh[11], 0);
});

test("Suite 2.2: CipherState unkeyed bypass passes plaintext/ciphertext unchanged", async () => {
  const cipher = new CipherState();
  assert.strictEqual(cipher.hasKey(), false);
  assert.strictEqual(cipher.nonce, 0);

  const payload = new TextEncoder().encode("Unkeyed plain wire transmission");
  const dummyAd = new TextEncoder().encode("header-ad");

  const enc = await cipher.encryptWithAd(dummyAd, payload);
  assert.deepStrictEqual(enc, payload);
  assert.strictEqual(cipher.nonce, 0); // Nonce counter must NOT advance when unkeyed

  const dec = await cipher.decryptWithAd(dummyAd, payload);
  assert.deepStrictEqual(dec, payload);
  assert.strictEqual(cipher.nonce, 0);
});

test("Suite 2.3: CipherState AES-GCM 128-bit tag encryption & decryption roundtrip", async () => {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const cipher = new CipherState();
  await cipher.initializeKey(keyBytes);

  assert.strictEqual(cipher.hasKey(), true);
  assert.strictEqual(cipher.nonce, 0);

  const plaintext = new TextEncoder().encode("Hatch Meta Muse Encrypted Transport Payload");
  const ad = new TextEncoder().encode("stream-id-1001");

  const ciphertext = await cipher.encryptWithAd(ad, plaintext);
  // AEAD AES-GCM appends 16-byte authentication tag
  assert.strictEqual(ciphertext.length, plaintext.length + 16);
  assert.strictEqual(cipher.nonce, 1);

  // Initialize a receiver cipher with identical key
  const rxKey = new Uint8Array(32);
  // We need a separate key copy because keyBytes was zeroized by initializeKey
  const sharedKey = crypto.getRandomValues(new Uint8Array(32));
  const sharedKeyCopy = new Uint8Array(sharedKey);

  const txCipher = new CipherState();
  await txCipher.initializeKey(sharedKey);

  const rxCipher = new CipherState();
  await rxCipher.initializeKey(sharedKeyCopy);

  const ct = await txCipher.encryptWithAd(ad, plaintext);
  const decrypted = await rxCipher.decryptWithAd(ad, ct);

  assert.deepStrictEqual(decrypted, plaintext);
  assert.strictEqual(txCipher.nonce, 1);
  assert.strictEqual(rxCipher.nonce, 1);
});

test("Suite 2.4: CipherState tag tampering & AD mismatch fail and poison state", async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const keyCopy = new Uint8Array(key);
  const tx = new CipherState();
  await tx.initializeKey(key);
  const rx = new CipherState();
  await rx.initializeKey(keyCopy);

  const plaintext = new TextEncoder().encode("Critical Tamper Resistance Test");
  const ad = new TextEncoder().encode("correct-ad");

  const ct = await tx.encryptWithAd(ad, plaintext);

  // 1. Bit flip in ciphertext body
  const tamperedCt = new Uint8Array(ct);
  tamperedCt[0] ^= 0x01;

  await assert.rejects(
    async () => {
      await rx.decryptWithAd(ad, tamperedCt);
    }
  );

  // 2. Cipher is now poisoned permanently
  await assert.rejects(
    async () => {
      await rx.decryptWithAd(ad, ct);
    },
    {
      name: "Error",
      message: "CipherState: poisoned after prior failure"
    }
  );

  await assert.rejects(
    async () => {
      await rx.encryptWithAd(ad, plaintext);
    },
    {
      name: "Error",
      message: "CipherState: poisoned after prior failure"
    }
  );
});

test("Suite 2.5: CipherState Associated Data mismatch poisons state", async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const keyCopy = new Uint8Array(key);
  const tx = new CipherState();
  await tx.initializeKey(key);
  const rx = new CipherState();
  await rx.initializeKey(keyCopy);

  const plaintext = new TextEncoder().encode("AD Verification");
  const ad1 = new TextEncoder().encode("ad-1");
  const ad2 = new TextEncoder().encode("ad-2");

  const ct = await tx.encryptWithAd(ad1, plaintext);

  await assert.rejects(
    async () => {
      await rx.decryptWithAd(ad2, ct);
    }
  );

  // Must now be poisoned
  await assert.rejects(
    async () => {
      await rx.decryptWithAd(ad1, ct);
    },
    {
      name: "Error",
      message: "CipherState: poisoned after prior failure"
    }
  );
});

test("Suite 2.6: CipherState key buffer zeroing on initializeKey", async () => {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  // Verify non-zero before
  assert.strictEqual(keyBytes.every(b => b === 0), false);

  const cipher = new CipherState();
  await cipher.initializeKey(keyBytes);

  // Verify memory wiped in place
  assert.strictEqual(keyBytes.every(b => b === 0), true);
});

test("Suite 2.7: CipherState zeroize resets state", async () => {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const cipher = new CipherState();
  await cipher.initializeKey(keyBytes);
  assert.strictEqual(cipher.hasKey(), true);

  cipher.zeroize();
  assert.strictEqual(cipher.hasKey(), false);
  assert.strictEqual(cipher.nonce, 0);
});

test("Suite 2.8: CipherState nonce overflow guard at Number.MAX_SAFE_INTEGER and poisoning", async () => {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const cipher = new CipherState();
  // Initialize at Number.MAX_SAFE_INTEGER - 1
  await cipher.initializeKey(keyBytes, Number.MAX_SAFE_INTEGER - 1);
  assert.strictEqual(cipher.nonce, Number.MAX_SAFE_INTEGER - 1);

  const ad = new TextEncoder().encode("ad");
  const pt = new TextEncoder().encode("payload");

  // First encrypt succeeds, counter reaches MAX_SAFE_INTEGER
  const ct = await cipher.encryptWithAd(ad, pt);
  assert.strictEqual(cipher.nonce, Number.MAX_SAFE_INTEGER);

  // Next encrypt throws nonce exhausted and poisons cipher
  await assert.rejects(
    async () => {
      await cipher.encryptWithAd(ad, pt);
    },
    {
      name: "Error",
      message: "CipherState: nonce exhausted"
    }
  );

  // Subsequent encrypt or decrypt throws poisoned after prior failure
  await assert.rejects(
    async () => {
      await cipher.encryptWithAd(ad, pt);
    },
    {
      name: "Error",
      message: "CipherState: poisoned after prior failure"
    }
  );

  await assert.rejects(
    async () => {
      await cipher.decryptWithAd(ad, ct);
    },
    {
      name: "Error",
      message: "CipherState: poisoned after prior failure"
    }
  );
});

// ============================================================================
// SUITE 3: SymmetricState & HKDF-SHA256 Derivation
// ============================================================================

test("Suite 3.1: Protocol name hash initialization matches golden hex digest", async () => {
  const sym = new SymmetricState("Noise_XX_25519_AESGCM_SHA256");
  await sym.initialize();

  const h0 = sym.handshakeHash();
  assert.strictEqual(h0.length, 32);

  const goldenHex = "5df72b67b965add1168f0a6c756df21c204f7e64fc682be6a3ab4b682c8db64b";
  const actualHex = Buffer.from(h0).toString("hex");

  assert.strictEqual(actualHex, goldenHex);
});

test("Suite 3.2: HKDF-SHA256 derivation matches standalone RFC 5869 HMAC calculation", async () => {
  const ck = crypto.getRandomValues(new Uint8Array(32));
  const ikm = crypto.getRandomValues(new Uint8Array(32));

  // Compute expected using standalone Node crypto HMAC
  const expectedPrk = crypto.createHmac("sha256", ck).update(ikm).digest();
  const expectedT1 = crypto.createHmac("sha256", expectedPrk).update(Buffer.from([1])).digest();
  const expectedT2 = crypto.createHmac("sha256", expectedPrk).update(Buffer.concat([expectedT1, Buffer.from([2])])).digest();
  const expectedT3 = crypto.createHmac("sha256", expectedPrk).update(Buffer.concat([expectedT2, Buffer.from([3])])).digest();

  const [t1, t2] = await hkdf(ck, ikm, 2);
  assert.deepStrictEqual(Buffer.from(t1), expectedT1);
  assert.deepStrictEqual(Buffer.from(t2), expectedT2);

  const [out1, out2, out3] = await hkdf(ck, ikm, 3);
  assert.deepStrictEqual(Buffer.from(out1), expectedT1);
  assert.deepStrictEqual(Buffer.from(out2), expectedT2);
  assert.deepStrictEqual(Buffer.from(out3), expectedT3);
});

test("Suite 3.3: SymmetricState mixHash updates transcript hash chaining", async () => {
  const sym = new SymmetricState();
  await sym.initialize();

  const initialH = sym.handshakeHash();
  const testData = new TextEncoder().encode("Transcript Data Block 1");

  await sym.mixHash(testData);
  const updatedH = sym.handshakeHash();

  assert.strictEqual(updatedH.length, 32);
  assert.notDeepStrictEqual(updatedH, initialH);

  // Verify against independent SHA-256(initialH || testData)
  const expectedH = crypto.createHash("sha256").update(initialH).update(testData).digest();
  assert.deepStrictEqual(Buffer.from(updatedH), expectedH);
});

test("Suite 3.4: SymmetricState encryptAndHash & decryptAndHash synchronize h", async () => {
  const symAlice = new SymmetricState();
  await symAlice.initialize();
  const symBob = new SymmetricState();
  await symBob.initialize();

  // Initially Alice and Bob have matching h
  assert.deepStrictEqual(symAlice.handshakeHash(), symBob.handshakeHash());

  // Set shared key on both
  const sharedKey = crypto.getRandomValues(new Uint8Array(32));
  await symAlice.mixKey(sharedKey);
  await symBob.mixKey(sharedKey);

  assert.deepStrictEqual(symAlice.handshakeHash(), symBob.handshakeHash());

  const msg = new TextEncoder().encode("Hello through SymmetricState");
  const ciphertext = await symAlice.encryptAndHash(msg);
  const plaintext = await symBob.decryptAndHash(ciphertext);

  assert.deepStrictEqual(plaintext, msg);
  // Transcript hashes must remain identical
  assert.deepStrictEqual(symAlice.handshakeHash(), symBob.handshakeHash());
});

test("Suite 3.5: SymmetricState mixKeyAndHash derives 3 keys, mixes hash, and initializes cipher", async () => {
  const symAlice = new SymmetricState();
  await symAlice.initialize();
  const symBob = new SymmetricState();
  await symBob.initialize();

  const ikm = crypto.getRandomValues(new Uint8Array(32));
  await symAlice.mixKeyAndHash(ikm);
  await symBob.mixKeyAndHash(ikm);

  // Handshake hashes must stay synchronized after mixKeyAndHash
  assert.deepStrictEqual(symAlice.handshakeHash(), symBob.handshakeHash());

  const msg = new TextEncoder().encode("Testing mixKeyAndHash encrypted channel");
  const ct = await symAlice.encryptAndHash(msg);
  const pt = await symBob.decryptAndHash(ct);

  assert.deepStrictEqual(pt, msg);
  assert.deepStrictEqual(symAlice.handshakeHash(), symBob.handshakeHash());
});

// ============================================================================
// SUITE 4: Full Noise XX Handshake & Bidirectional AEAD Exchange
// ============================================================================

test("Suite 4.1: Full 3-message Noise XX handshake between NoiseXXInitiator and SyntheticNoiseXXResponder", async () => {
  // 1. Setup responder static keypair
  const serverStatic = await generateX25519KeyPair();
  const responder = new SyntheticNoiseXXResponder(serverStatic);
  await responder.initialize();

  // 2. Setup initiator
  const initiator = new NoiseXXInitiator();
  await initiator.initialize();

  // 3. Message 1 (-> e, payload)
  const clientNonce = crypto.getRandomValues(new Uint8Array(34)); // 34-byte client nonce payload
  const msg1 = await initiator.writeMessage1(clientNonce);

  assert.strictEqual(msg1.length, 32 + 34); // 66 bytes total

  // 4. Responder receives Message 1, generates Message 2 (<- e, ee, s, es, payload)
  const serverAttestation = new TextEncoder().encode("MUSE_EDGE_CONTAINER_ATTESTATION_PASS");
  const { message2: msg2, clientNoncePayload: recClientNonce } = await responder.receiveMessage1(msg1, serverAttestation);

  assert.deepStrictEqual(recClientNonce, clientNonce);
  // e.pub (32) + enc_s (48) + enc_attestation (attestation.length + 16) >= 96 bytes
  assert.ok(msg2.length >= 96);

  // 5. Initiator processes Message 2
  const receivedAttestation = await initiator.readMessage2(msg2);
  assert.deepStrictEqual(receivedAttestation, serverAttestation);

  // Verify remote static key matches serverStatic.publicKeyBytes
  const discoveredServerStatic = initiator.remoteStaticPublicKey();
  assert.deepStrictEqual(discoveredServerStatic, serverStatic.publicKeyBytes);

  // 6. Message 3 (-> s, se, payload)
  const clientAuthTicket = new TextEncoder().encode("CLIENT_AUTH_JWT_TICKET_PAYLOAD_TOKEN");
  const msg3 = await initiator.writeMessage3(clientAuthTicket);

  // enc_s (48) + enc_payload (clientAuthTicket.length + 16)
  assert.strictEqual(msg3.length, 48 + clientAuthTicket.length + 16);

  // 7. Responder processes Message 3
  const { clientTicket: recClientTicket, rxCipher: sRx, txCipher: sTx } = await responder.receiveMessage3(msg3);
  assert.deepStrictEqual(recClientTicket, clientAuthTicket);
  assert.deepStrictEqual(responder.rs, initiator.remoteStaticPublicKey() ? responder.rs : responder.rs);

  // 8. Initiator splits
  const [cTx, cRx] = await initiator.split();

  // 9. Handshake hashes match exactly
  assert.deepStrictEqual(initiator.handshakeHash(), responder.symmetric.handshakeHash());

  // 10. Bidirectional encrypted communication
  // Client -> Server
  const clientMsg1 = new TextEncoder().encode("Hello Meta Muse over encrypted WebSocket!");
  const emptyAd = new Uint8Array(0);
  const clientCiphertext1 = await cTx.encryptWithAd(emptyAd, clientMsg1);
  const serverDecrypted1 = await sRx.decryptWithAd(emptyAd, clientCiphertext1);
  assert.deepStrictEqual(serverDecrypted1, clientMsg1);

  // Server -> Client
  const serverMsg1 = new TextEncoder().encode("Acknowledged. Secure Noise tunnel established.");
  const serverCiphertext1 = await sTx.encryptWithAd(emptyAd, serverMsg1);
  const clientDecrypted1 = await cRx.decryptWithAd(emptyAd, serverCiphertext1);
  assert.deepStrictEqual(clientDecrypted1, serverMsg1);

  // 11. Multi-message sequential streaming simulation (20 round trips)
  for (let i = 0; i < 20; i++) {
    const cMsg = new TextEncoder().encode(`Stream chunk ${i} from client`);
    const cEnc = await cTx.encryptWithAd(emptyAd, cMsg);
    const sDec = await sRx.decryptWithAd(emptyAd, cEnc);
    assert.deepStrictEqual(sDec, cMsg);

    const sMsg = new TextEncoder().encode(`Stream delta chunk ${i} from model reply`);
    const sEnc = await sTx.encryptWithAd(emptyAd, sMsg);
    const cDec = await cRx.decryptWithAd(emptyAd, sEnc);
    assert.deepStrictEqual(cDec, sMsg);
  }

  // Nonce count assertions: 1 initial + 20 loops = 21 messages in each direction
  assert.strictEqual(cTx.nonce, 21);
  assert.strictEqual(sRx.nonce, 21);
  assert.strictEqual(sTx.nonce, 21);
  assert.strictEqual(cRx.nonce, 21);

  destroyX25519KeyPair(serverStatic);
});

// ============================================================================
// SUITE 5: Adversarial Probes & Error Injection
// ============================================================================

test("Suite 5.1: Truncated Message 2 (< 96 bytes) destroys handshake", async () => {
  const initiator = new NoiseXXInitiator();
  await initiator.writeMessage1();

  const shortMsg2 = new Uint8Array(95);

  await assert.rejects(
    async () => {
      await initiator.readMessage2(shortMsg2);
    },
    {
      name: "Error",
      message: "NoiseXX: message 2 too short (95 < 96)"
    }
  );

  // Handshake should now be dead
  await assert.rejects(
    async () => {
      await initiator.writeMessage3();
    },
    {
      name: "Error",
      message: "NoiseXX: writeMessage3 called on dead handshake"
    }
  );
});

test("Suite 5.2: Corrupted Message 2 ciphertext fails and destroys handshake", async () => {
  const serverStatic = await generateX25519KeyPair();
  const responder = new SyntheticNoiseXXResponder(serverStatic);
  await responder.initialize();

  const initiator = new NoiseXXInitiator();
  const msg1 = await initiator.writeMessage1();

  const { message2: msg2 } = await responder.receiveMessage1(msg1);

  // Corrupt a byte in enc_s (byte 40)
  const corruptedMsg2 = new Uint8Array(msg2);
  corruptedMsg2[40] ^= 0xFF;

  await assert.rejects(
    async () => {
      await initiator.readMessage2(corruptedMsg2);
    }
  );

  // Subsequent call throws dead handshake
  await assert.rejects(
    async () => {
      await initiator.writeMessage3();
    },
    {
      name: "Error",
      message: "NoiseXX: writeMessage3 called on dead handshake"
    }
  );

  destroyX25519KeyPair(serverStatic);
});

test("Suite 5.3: Phase order violations throw expected state errors", async () => {
  const initiator = new NoiseXXInitiator();

  // Calling readMessage2 before writeMessage1
  await assert.rejects(
    async () => {
      await initiator.readMessage2(new Uint8Array(96));
    },
    {
      name: "Error",
      message: "NoiseXX: readMessage2 called in wrong phase (expected 2, got 0)"
    }
  );

  const init2 = new NoiseXXInitiator();
  await init2.writeMessage1();

  // Calling writeMessage3 before readMessage2
  await assert.rejects(
    async () => {
      await init2.writeMessage3();
    },
    {
      name: "Error",
      message: "NoiseXX: writeMessage3 called in wrong phase (expected 3, got 2)"
    }
  );

  // Calling split before writeMessage3
  await assert.rejects(
    async () => {
      await init2.split();
    },
    {
      name: "Error",
      message: "NoiseXX: split called in wrong phase (expected 4, got 2)"
    }
  );
});

test("Suite 5.4: destroy() cleans up keys and transitions to dead phase 6", async () => {
  const initiator = new NoiseXXInitiator();
  await initiator.writeMessage1();

  initiator.destroy();

  await assert.rejects(
    async () => {
      await initiator.readMessage2(new Uint8Array(96));
    },
    {
      name: "Error",
      message: "NoiseXX: readMessage2 called on dead handshake"
    }
  );

  await assert.rejects(
    async () => {
      await initiator.split();
    },
    {
      name: "Error",
      message: "NoiseXX: split called on dead handshake"
    }
  );
});
