/**
 * lib/noise/crypto.mjs
 *
 * Pure Node 20+ implementation of Noise_XX_25519_AESGCM_SHA256 cryptographic core.
 * Zero external npm dependencies.
 *
 * Implements:
 * - X25519 key generation, validation (7 low-order points rejection, all-zero output guard), and DH scalar multiplication
 * - CipherState: 96-bit nonce counter [0x00, 0x00, 0x00, 0x00, hi_32, lo_32], AES-GCM AEAD (128-bit tag),
 *   Number.MAX_SAFE_INTEGER overflow guard, error poisoning, unkeyed bypass, zeroize.
 * - SymmetricState: transcript hash chaining (mixHash), HKDF-SHA256 key derivation (mixKey, mixKeyAndHash),
 *   encryptAndHash, decryptAndHash, and split() into [txCipher, rxCipher].
 * - NoiseXXInitiator: 3-message initiator state machine for pattern XX, explicit memory zeroing on finish or error.
 */

import crypto from "node:crypto";

// 32-byte zero buffer for checks and zeroing
export const ALL_ZEROS_32 = new Uint8Array(32);

/**
 * 7 canonical low-order points on Curve25519 (RFC 7748 / libsodium).
 * Any remote public key matching these is immediately rejected.
 */
export const CURVE25519_LOW_ORDER_POINTS = Object.freeze([
  // Point 1: 0 (order 1, 2, 4, 8)
  new Uint8Array(32),
  // Point 2: 1 (order 1)
  new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
  // Point 3: Small order point
  new Uint8Array([224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0]),
  // Point 4: Small order point
  new Uint8Array([95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87]),
  // Point 5: 2^255 - 19 - 1
  new Uint8Array([236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127]),
  // Point 6: 2^255 - 19
  new Uint8Array([237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127]),
  // Point 7: 2^255 - 19 + 1
  new Uint8Array([238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127])
]);

/**
 * Custom error thrown when X25519 operations are unavailable.
 */
export class NoiseX25519UnavailableError extends Error {
  kind = "noise_x25519_unavailable";
  constructor(message, options) {
    super(message);
    this.name = "NoiseX25519UnavailableError";
    if (options && "cause" in options) {
      this.cause = options.cause;
    }
  }
}

/**
 * Concatenates multiple Uint8Array instances into a single contiguous Uint8Array.
 * @param {...Uint8Array} arrays
 * @returns {Uint8Array}
 */
export function concat(...arrays) {
  let totalLength = 0;
  for (const arr of arrays) {
    if (arr) totalLength += arr.length;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    if (arr) {
      result.set(arr, offset);
      offset += arr.length;
    }
  }
  return result;
}

/**
 * Safely extracts an ArrayBuffer slice from any BufferSource.
 * Prevents WebCrypto issues with shared buffers or non-zero byte offsets.
 * @param {Uint8Array|ArrayBuffer|Buffer} buf
 * @returns {ArrayBuffer}
 */
export function toBufferSource(buf) {
  if (!buf) return new ArrayBuffer(0);
  if (buf instanceof ArrayBuffer) return buf;
  if (ArrayBuffer.isView(buf)) {
    if (buf.byteOffset === 0 && buf.byteLength === buf.buffer.byteLength) {
      return buf.buffer;
    }
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  const u8 = new Uint8Array(buf);
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

/**
 * Securely overwrites typed array memory with zeros.
 * @param {Uint8Array|Buffer|ArrayBufferView} buf
 */
export function zeroize(buf) {
  if (buf && typeof buf.fill === "function") {
    buf.fill(0);
  } else if (ArrayBuffer.isView(buf)) {
    new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).fill(0);
  }
}

/**
 * Constant-time byte-level comparison of two Uint8Arrays.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function constantTimeEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Checks if a 32-byte public key matches any of the 7 low-order points.
 * @param {Uint8Array} pubKeyBytes
 * @returns {boolean}
 */
export function isLowOrderPoint(pubKeyBytes) {
  if (!pubKeyBytes || pubKeyBytes.length !== 32) return false;
  for (const pt of CURVE25519_LOW_ORDER_POINTS) {
    if (constantTimeEqual(pubKeyBytes, pt)) {
      return true;
    }
  }
  return false;
}

/**
 * Formats a 64-bit unsigned integer counter into a 96-bit (12-byte) AES-GCM nonce:
 * [0x00, 0x00, 0x00, 0x00, hi_32, lo_32]
 * @param {number} counter
 * @returns {Uint8Array}
 */
export function formatNonce(counter) {
  const nonce = new Uint8Array(12);
  const view = new DataView(nonce.buffer, nonce.byteOffset, 12);
  view.setUint32(0, 0, false);
  view.setUint32(4, Math.floor(counter / 0x100000000), false);
  view.setUint32(8, counter >>> 0, false);
  return nonce;
}

/**
 * Generates an ephemeral or static X25519 keypair using WebCrypto.
 * @returns {Promise<{backend: string, privateKey: {backend: string, key: CryptoKey}, publicKeyBytes: Uint8Array}>}
 */
export async function generateX25519KeyPair() {
  try {
    const keyPair = await crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveBits"]
    );
    const rawPub = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    return {
      backend: "webcrypto",
      privateKey: { backend: "webcrypto", key: keyPair.privateKey },
      publicKeyBytes: new Uint8Array(rawPub)
    };
  } catch (err) {
    throw new NoiseX25519UnavailableError("Failed to generate X25519 keypair via WebCrypto", { cause: err });
  }
}

/**
 * Destroys an X25519 keypair by zeroing public key bytes and any raw private keys.
 * @param {{publicKeyBytes?: Uint8Array, privateKey?: any}} keyPair
 */
export function destroyX25519KeyPair(keyPair) {
  if (!keyPair) return;
  if (keyPair.publicKeyBytes) {
    zeroize(keyPair.publicKeyBytes);
  }
  if (keyPair.privateKey && keyPair.privateKey.bytes) {
    zeroize(keyPair.privateKey.bytes);
  }
}

// 16-byte standard PKCS#8 prefix for Curve25519 private keys:
// 30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20 [32 bytes private key]
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
]);

/**
 * Performs Diffie-Hellman scalar multiplication between a private key and a remote public key.
 * Enforces Curve25519 low-order blacklist rejection and all-zero shared secret checks.
 *
 * @param {CryptoKey|{backend: string, key: CryptoKey}|Uint8Array} privateKey
 * @param {Uint8Array} remotePublicKey
 * @returns {Promise<Uint8Array>} 32-byte shared secret
 */
export async function x25519DH(privateKey, remotePublicKey) {
  if (!remotePublicKey || remotePublicKey.length !== 32) {
    throw new Error("x25519: invalid public key length");
  }

  // 1. Blacklist rejection for 7 canonical low-order points
  if (isLowOrderPoint(remotePublicKey)) {
    throw new Error("x25519: rejected low-order public key");
  }

  // 2. Resolve WebCrypto private CryptoKey
  let privKey;
  let tempRawPriv = null;
  if (privateKey && privateKey.key && privateKey.key.algorithm) {
    privKey = privateKey.key;
  } else if (privateKey && privateKey.algorithm) {
    privKey = privateKey;
  } else if (privateKey instanceof Uint8Array || Buffer.isBuffer(privateKey)) {
    if (privateKey.length !== 32) {
      throw new Error("x25519: invalid private key length");
    }
    tempRawPriv = concat(X25519_PKCS8_PREFIX, privateKey);
    privKey = await crypto.subtle.importKey(
      "pkcs8",
      toBufferSource(tempRawPriv),
      { name: "X25519" },
      false,
      ["deriveBits"]
    );
    zeroize(tempRawPriv);
  } else {
    throw new Error("x25519: unsupported private key type");
  }

  // 3. Import remote public key
  let pubKey;
  try {
    pubKey = await crypto.subtle.importKey(
      "raw",
      toBufferSource(remotePublicKey),
      { name: "X25519" },
      false,
      []
    );
  } catch (err) {
    // If WebCrypto rejects the public key format
    throw new Error("x25519: rejected low-order public key", { cause: err });
  }

  // 4. Derive shared bits
  let derivedBits;
  try {
    derivedBits = await crypto.subtle.deriveBits(
      { name: "X25519", public: pubKey },
      privKey,
      256
    );
  } catch (err) {
    throw new Error("x25519: DH scalar multiplication failed", { cause: err });
  }

  const sharedSecret = new Uint8Array(derivedBits);

  // 5. Rejection if DH scalar multiplication yields all-zeros
  if (constantTimeEqual(sharedSecret, ALL_ZEROS_32)) {
    zeroize(sharedSecret);
    throw new Error("x25519: DH produced all-zeros output");
  }

  return sharedSecret;
}

/**
 * Computes HMAC-SHA256(key, data) using WebCrypto.
 * @param {Uint8Array} key
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
async function hmacSha256(key, data) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    toBufferSource(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, toBufferSource(data));
  return new Uint8Array(signature);
}

/**
 * Noise HKDF implementation using HMAC-SHA256 (RFC 5869 / Noise Spec Section 5.1):
 * PRK = HMAC-HASH(salt = ck, ikm = ikm)
 * T1 = HMAC-HASH(PRK, 0x01)
 * T2 = HMAC-HASH(PRK, T1 || 0x02)
 * T3 = HMAC-HASH(PRK, T2 || 0x03)
 *
 * @param {Uint8Array} ck Chaining key (salt)
 * @param {Uint8Array} ikm Input key material
 * @param {number} numOutputs Number of 32-byte outputs (2 or 3)
 * @returns {Promise<Uint8Array[]>}
 */
export async function hkdf(ck, ikm, numOutputs = 2) {
  const prk = await hmacSha256(ck, ikm);
  try {
    const t1 = await hmacSha256(prk, new Uint8Array([1]));
    const t2 = await hmacSha256(prk, concat(t1, new Uint8Array([2])));
    if (numOutputs === 2) {
      return [t1, t2];
    }
    const t3 = await hmacSha256(prk, concat(t2, new Uint8Array([3])));
    return [t1, t2, t3];
  } finally {
    zeroize(prk);
  }
}

/**
 * CipherState manages a symmetric key and a 64-bit monotonic nonce for AES-256-GCM.
 * Handles unkeyed bypass, failure poisoning, and nonce exhaustion guards.
 */
export class CipherState {
  #encKey = null;
  #decKey = null;
  #hasKey = false;
  #counter = 0;
  #poisoned = false;
  #mutex = Promise.resolve();
  #initPromise = null;

  constructor(key) {
    if (key) {
      this.#initPromise = this.initializeKey(key);
    }
  }

  #checkPoisoned() {
    if (this.#poisoned) {
      throw new Error("CipherState: poisoned after prior failure");
    }
  }

  /**
   * Initializes CipherState with a 32-byte symmetric key.
   * Securely zeroes the input key buffer.
   * @param {Uint8Array} keyBytes
   * @param {number} [initialNonce=0]
   */
  async initializeKey(keyBytes, initialNonce = 0) {
    this.#checkPoisoned();
    if (!keyBytes || keyBytes.length !== 32) {
      throw new Error("CipherState: key must be exactly 32 bytes");
    }

    const raw = new Uint8Array(keyBytes);
    const buf = toBufferSource(raw);

    const [enc, dec] = await Promise.all([
      crypto.subtle.importKey("raw", buf, "AES-GCM", false, ["encrypt"]),
      crypto.subtle.importKey("raw", buf, "AES-GCM", false, ["decrypt"])
    ]);

    this.#encKey = enc;
    this.#decKey = dec;
    this.#hasKey = true;
    this.#counter = typeof initialNonce === "number" ? initialNonce : 0;

    // Securely zeroize input buffer and intermediate memory
    zeroize(raw);
    zeroize(new Uint8Array(buf));
    zeroize(keyBytes);
  }

  /**
   * Returns true if a key has been configured.
   * @returns {boolean}
   */
  hasKey() {
    return this.#hasKey;
  }

  /**
   * Returns the current nonce counter value.
   * @returns {number}
   */
  get nonce() {
    return this.#counter;
  }

  /**
   * Encrypts plaintext with associated data using AES-GCM (128-bit tag).
   * Monotonically increments 96-bit nonce IV.
   * Unkeyed bypass: returns plaintext as-is if no key is set.
   *
   * @param {Uint8Array} ad Associated data
   * @param {Uint8Array} plaintext Plaintext buffer
   * @returns {Promise<Uint8Array>} Ciphertext with appended 128-bit tag
   */
  async encryptWithAd(ad, plaintext) {
    return this.#serialize(async () => {
      this.#checkPoisoned();
      if (this.#initPromise) {
        await this.#initPromise;
        this.#initPromise = null;
      }

      // Unkeyed bypass
      if (!this.#hasKey) {
        return plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext || 0);
      }

      // Nonce exhaustion guard
      if (this.#counter >= Number.MAX_SAFE_INTEGER) {
        this.#poisoned = true;
        throw new Error("CipherState: nonce exhausted");
      }

      const iv = formatNonce(this.#counter++);
      try {
        const encrypted = await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: toBufferSource(iv),
            additionalData: toBufferSource(ad),
            tagLength: 128
          },
          this.#encKey,
          toBufferSource(plaintext)
        );
        return new Uint8Array(encrypted);
      } catch (err) {
        this.#poisoned = true;
        throw err;
      }
    });
  }

  /**
   * Decrypts ciphertext with associated data using AES-GCM (128-bit tag).
   * Monotonically increments 96-bit nonce IV.
   * Unkeyed bypass: returns ciphertext as-is if no key is set.
   *
   * @param {Uint8Array} ad Associated data
   * @param {Uint8Array} ciphertext Ciphertext buffer (with 16-byte tag)
   * @returns {Promise<Uint8Array>} Decrypted plaintext
   */
  async decryptWithAd(ad, ciphertext) {
    return this.#serialize(async () => {
      this.#checkPoisoned();
      if (this.#initPromise) {
        await this.#initPromise;
        this.#initPromise = null;
      }

      // Unkeyed bypass
      if (!this.#hasKey) {
        return ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext || 0);
      }

      // Nonce exhaustion guard
      if (this.#counter >= Number.MAX_SAFE_INTEGER) {
        this.#poisoned = true;
        throw new Error("CipherState: nonce exhausted");
      }

      const iv = formatNonce(this.#counter++);
      try {
        const decrypted = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: toBufferSource(iv),
            additionalData: toBufferSource(ad),
            tagLength: 128
          },
          this.#decKey,
          toBufferSource(ciphertext)
        );
        return new Uint8Array(decrypted);
      } catch (err) {
        this.#poisoned = true;
        throw err;
      }
    });
  }

  /**
   * Zeroizes internal key references and resets state.
   */
  zeroize() {
    this.#encKey = null;
    this.#decKey = null;
    this.#hasKey = false;
    this.#counter = 0;
    this.#poisoned = false;
  }

  /**
   * Serializes calls to prevent race conditions or nonce reuse under concurrency.
   * @param {() => Promise<any>} fn
   * @returns {Promise<any>}
   */
  async #serialize(fn) {
    let unlock;
    const prev = this.#mutex;
    this.#mutex = new Promise(resolve => { unlock = resolve; });
    await prev;
    try {
      return await fn();
    } finally {
      unlock();
    }
  }
}

/**
 * SymmetricState maintains the chaining key (ck), handshake hash (h), and an internal CipherState.
 */
export class SymmetricState {
  #protocolName = "Noise_XX_25519_AESGCM_SHA256";
  #ck = new Uint8Array(32);
  #h = new Uint8Array(32);
  #cipher = new CipherState();
  #initialized = false;

  constructor(protocolName = "Noise_XX_25519_AESGCM_SHA256") {
    this.#protocolName = protocolName;
  }

  /**
   * Initializes ck and h from protocol name.
   * ck = protocol_name padded to 32 bytes with zeros.
   * h = SHA-256(ck || empty) = SHA-256(ck).
   */
  async initialize() {
    const nameBytes = new TextEncoder().encode(this.#protocolName);
    const pad = new Uint8Array(32);
    pad.set(nameBytes);
    this.#ck = pad;
    this.#h = new Uint8Array(this.#ck);
    this.#cipher = new CipherState();
    this.#initialized = true;
    await this.mixHash(new Uint8Array(0));
  }

  async #ensureInitialized() {
    if (!this.#initialized) {
      await this.initialize();
    }
  }

  /**
   * Updates h = SHA-256(h || data).
   * @param {Uint8Array} data
   */
  async mixHash(data) {
    await this.#ensureInitialized();
    const digest = await crypto.subtle.digest("SHA-256", toBufferSource(concat(this.#h, data)));
    this.#h = new Uint8Array(digest);
  }

  /**
   * Derives [ck_next, temp_k] = HKDF(ck, ikm, 2).
   * Initializes internal CipherState with temp_k.
   * Zeroizes ck and intermediate buffers.
   * @param {Uint8Array} ikm
   */
  async mixKey(ikm) {
    await this.#ensureInitialized();
    const [ck_next, temp_k] = await hkdf(this.#ck, ikm, 2);
    zeroize(this.#ck);
    this.#ck = ck_next;
    this.#cipher = new CipherState();
    await this.#cipher.initializeKey(temp_k);
    zeroize(temp_k);
  }

  /**
   * Derives [ck_next, temp_h, temp_k] = HKDF(ck, ikm, 3).
   * mixHash(temp_h).
   * Initializes internal CipherState with temp_k.
   * @param {Uint8Array} ikm
   */
  async mixKeyAndHash(ikm) {
    await this.#ensureInitialized();
    const [ck_next, temp_h, temp_k] = await hkdf(this.#ck, ikm, 3);
    zeroize(this.#ck);
    this.#ck = ck_next;
    await this.mixHash(temp_h);
    zeroize(temp_h);
    this.#cipher = new CipherState();
    await this.#cipher.initializeKey(temp_k);
    zeroize(temp_k);
  }

  /**
   * Encrypts plaintext with AD = h, mixes ciphertext into h, and returns ciphertext.
   * @param {Uint8Array} plaintext
   * @returns {Promise<Uint8Array>}
   */
  async encryptAndHash(plaintext) {
    await this.#ensureInitialized();
    const ciphertext = await this.#cipher.encryptWithAd(this.#h, plaintext);
    await this.mixHash(ciphertext);
    return ciphertext;
  }

  /**
   * Decrypts ciphertext with AD = h, mixes ciphertext into h, and returns plaintext.
   * @param {Uint8Array} ciphertext
   * @returns {Promise<Uint8Array>}
   */
  async decryptAndHash(ciphertext) {
    await this.#ensureInitialized();
    const plaintext = await this.#cipher.decryptWithAd(this.#h, ciphertext);
    await this.mixHash(ciphertext);
    return plaintext;
  }

  /**
   * Derives [txKey, rxKey] = HKDF(ck, empty_ikm, 2).
   * Zeroizes ck and h.
   * Returns [txCipher, rxCipher].
   * @returns {Promise<[CipherState, CipherState]>}
   */
  async split() {
    await this.#ensureInitialized();
    const [k1, k2] = await hkdf(this.#ck, new Uint8Array(0), 2);
    zeroize(this.#ck);
    zeroize(this.#h);

    const txCipher = new CipherState();
    await txCipher.initializeKey(k1);
    zeroize(k1);

    const rxCipher = new CipherState();
    await rxCipher.initializeKey(k2);
    zeroize(k2);

    return [txCipher, rxCipher];
  }

  /**
   * Returns a copy of the current handshake hash (h).
   * @returns {Uint8Array}
   */
  handshakeHash() {
    return new Uint8Array(this.#h);
  }
}

/**
 * NoiseXXInitiator implements the Initiator role in the Noise XX handshake pattern:
 * -> e
 * <- e, ee, s, es
 * -> s, se
 *
 * Phase lifecycle:
 * 0: uninitialized
 * 1: initialized (ready for writeMessage1)
 * 2: msg1_sent (ready for readMessage2)
 * 3: msg2_read (ready for writeMessage3)
 * 4: msg3_sent (ready for split)
 * 5: split
 * 6: dead / destroyed
 */
export class NoiseXXInitiator {
  #symmetric = new SymmetricState();
  #e = null;   // Local ephemeral keypair
  #s = null;   // Local static keypair
  #re = null;  // Remote ephemeral public key (32 bytes)
  #rs = null;  // Remote static public key (32 bytes)
  #phase = 0;
  #options = {};
  #splitResult = null;

  constructor(options = {}) {
    this.#options = options || {};
  }

  #checkPhase(expected, fnName) {
    if (this.#phase === 6) {
      throw new Error(`NoiseXX: ${fnName} called on dead handshake`);
    }
    if (this.#phase !== expected) {
      throw new Error(`NoiseXX: ${fnName} called in wrong phase (expected ${expected}, got ${this.#phase})`);
    }
  }

  #wipe() {
    if (this.#re) { zeroize(this.#re); this.#re = null; }
    if (this.#rs) { zeroize(this.#rs); this.#rs = null; }
    if (this.#e) { destroyX25519KeyPair(this.#e); this.#e = null; }
    if (this.#s) { destroyX25519KeyPair(this.#s); this.#s = null; }
  }

  /**
   * Initializes the symmetric state and applies any optional prologue.
   */
  async initialize() {
    this.#checkPhase(0, "initialize");
    await this.#symmetric.initialize();
    if (this.#options.prologue && this.#options.prologue.length > 0) {
      await this.#symmetric.mixHash(this.#options.prologue);
    }
    this.#phase = 1;
  }

  /**
   * Writes Handshake Message 1 (-> e):
   * Generates local ephemeral key e.
   * mixHash(e.pub)
   * encryptAndHash(payload) (unencrypted payload)
   * Returns: e.pub (32 bytes) || payload
   *
   * @param {Uint8Array} [payload=new Uint8Array(0)]
   * @returns {Promise<Uint8Array>}
   */
  async writeMessage1(payload = new Uint8Array(0)) {
    if (this.#phase === 0) {
      await this.initialize();
    }
    this.#checkPhase(1, "writeMessage1");

    try {
      this.#e = await generateX25519KeyPair();
      if (this.#phase !== 1) {
        destroyX25519KeyPair(this.#e);
        throw new Error("NoiseXX: writeMessage1 canceled during key generation");
      }
      await this.#symmetric.mixHash(this.#e.publicKeyBytes);
      const encPayload = await this.#symmetric.encryptAndHash(payload);
      this.#phase = 2;
      return concat(this.#e.publicKeyBytes, encPayload);
    } catch (err) {
      this.destroy();
      throw err;
    }
  }

  /**
   * Reads Handshake Message 2 (<- e, ee, s, es):
   * Parses remote ephemeral re (32 bytes).
   * mixHash(re)
   * mixKey(DH(e, re))
   * Decrypts remote static rs (48 bytes: 32B + 16B tag).
   * mixKey(DH(e, rs))
   * Decrypts server attestation payload.
   *
   * @param {Uint8Array} message2Bytes
   * @returns {Promise<Uint8Array>} Decrypted server payload
   */
  async readMessage2(message2Bytes) {
    this.#checkPhase(2, "readMessage2");
    if (!message2Bytes || message2Bytes.length < 96) {
      this.destroy();
      throw new Error(`NoiseXX: message 2 too short (${message2Bytes ? message2Bytes.length : 0} < 96)`);
    }

    try {
      let offset = 0;

      // 1. Remote ephemeral re (32 bytes)
      this.#re = new Uint8Array(message2Bytes.subarray(offset, offset + 32));
      offset += 32;
      await this.#symmetric.mixHash(this.#re);

      // 2. ee = DH(e, re)
      const ee = await x25519DH(this.#e.privateKey, this.#re);
      await this.#symmetric.mixKey(ee);
      zeroize(ee);

      // 3. Decrypt remote static rs (32 bytes pubkey + 16 bytes tag = 48 bytes)
      const encRs = message2Bytes.subarray(offset, offset + 48);
      offset += 48;
      this.#rs = await this.#symmetric.decryptAndHash(encRs);

      // 4. es = DH(e, rs)
      const es = await x25519DH(this.#e.privateKey, this.#rs);
      await this.#symmetric.mixKey(es);
      zeroize(es);

      // 5. Decrypt server payload
      const encPayload = message2Bytes.subarray(offset);
      const payload = await this.#symmetric.decryptAndHash(encPayload);

      this.#phase = 3;
      return payload;
    } catch (err) {
      this.destroy();
      throw err;
    }
  }

  /**
   * Writes Handshake Message 3 (-> s, se):
   * Generates or uses client static key s.
   * encryptAndHash(s.pub) (48 bytes: 32B + 16B tag).
   * mixKey(DH(s, re)).
   * encryptAndHash(payload).
   * Returns: enc_s || enc_payload.
   *
   * @param {Uint8Array} [payload=new Uint8Array(0)]
   * @returns {Promise<Uint8Array>}
   */
  async writeMessage3(payload = new Uint8Array(0)) {
    this.#checkPhase(3, "writeMessage3");

    try {
      if (!this.#s) {
        if (this.#options.staticKey) {
          if (this.#options.staticKey.publicKeyBytes && this.#options.staticKey.privateKey) {
            this.#s = this.#options.staticKey;
          } else {
            // Raw 32 bytes private key
            const privBytes = new Uint8Array(this.#options.staticKey);
            const pkcs8 = concat(X25519_PKCS8_PREFIX, privBytes);
            const privKey = await crypto.subtle.importKey(
              "pkcs8",
              toBufferSource(pkcs8),
              { name: "X25519" },
              true,
              ["deriveBits"]
            );
            // Export public key
            const rawPub = await crypto.subtle.exportKey("raw", privKey);
            this.#s = {
              backend: "webcrypto",
              privateKey: { backend: "webcrypto", key: privKey },
              publicKeyBytes: new Uint8Array(rawPub)
            };
            zeroize(pkcs8);
          }
        } else {
          this.#s = await generateX25519KeyPair();
        }
      }

      if (this.#phase !== 3) {
        destroyX25519KeyPair(this.#s);
        throw new Error("NoiseXX: writeMessage3 canceled during key generation");
      }

      // 1. Encrypt static public key
      const enc_s = await this.#symmetric.encryptAndHash(this.#s.publicKeyBytes);

      // 2. se = DH(s, re)
      const se = await x25519DH(this.#s.privateKey, this.#re);
      await this.#symmetric.mixKey(se);
      zeroize(se);

      // 3. Encrypt payload
      const enc_payload = await this.#symmetric.encryptAndHash(payload);

      this.#phase = 4;
      return concat(enc_s, enc_payload);
    } catch (err) {
      this.destroy();
      throw err;
    }
  }

  /**
   * Finalizes the handshake and splits the symmetric state into operational [txCipher, rxCipher].
   * Securely zeroes all ephemeral and static keys and intermediate hashes.
   * @returns {Promise<[CipherState, CipherState]>}
   */
  async split() {
    if (this.#phase === 6) {
      throw new Error("NoiseXX: split called on dead handshake");
    }
    if (this.#phase === 5 && this.#splitResult) {
      return this.#splitResult;
    }
    this.#checkPhase(4, "split");

    this.#phase = 5;
    const ciphers = await this.#symmetric.split();
    this.#wipe();
    this.#splitResult = ciphers;
    return ciphers;
  }

  /**
   * Zeroes all sensitive key material, clears state, and marks handshake dead.
   */
  destroy() {
    this.#wipe();
    this.#phase = 6;
  }

  /**
   * Returns a copy of the remote static public key discovered in Message 2.
   * @returns {Uint8Array|null}
   */
  remoteStaticPublicKey() {
    return this.#rs ? new Uint8Array(this.#rs) : null;
  }

  /**
   * Returns a copy of the handshake hash.
   * @returns {Uint8Array}
   */
  handshakeHash() {
    return this.#symmetric.handshakeHash();
  }

  /**
   * Returns the active X25519 cryptographic backend identifier.
   * @returns {string}
   */
  x25519Backend() {
    return "webcrypto";
  }
}
