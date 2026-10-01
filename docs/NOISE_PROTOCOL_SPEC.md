# Noise Protocol Wire Specification: Meta Muse Hatch Gateway

This document provides the definitive wire-level specification of the encrypted WebSocket transport used by Meta Muse (`https://muse.ai/`), extracted directly from the client production bundles (`3v3h8u5gphw1m.js`, `0h1y2r2my7bvv.js`).

---

## 1. Connection Architecture

### 1.1 Endpoint
* **URL**: `wss://hatch.metaaivm.com/v1/noise`
* **Query Parameters**:
  * `vm_id`: UUID of the container VM (from `/api/session`).
  * `auth_token`: Ed25519-signed JWT token (`s0:...`).
  * `notary_token`: Notary endorsement token (`endorsement.v1...`).
  * `app_id`: `hatch-web`.
  * `request_id`: Client UUID for the connection session.

### 1.2 Handshake Protocol Suite
* **Protocol Name**: `Noise_XX_25519_AESGCM_SHA256`
* **Cryptographic Primitives**:
  * **DH**: Curve25519 (`X25519`)
  * **Cipher**: `AES-256-GCM` with a 96-bit (12-byte) nonce and 128-bit authentication tag
  * **Hash**: `SHA-256`
  * **Key Derivation**: `HKDF-SHA256`

---

## 2. Handshake State Machine

### 2.1 Variables & Initialization
```text
h  = SHA-256("Noise_XX_25519_AESGCM_SHA256")  // 32-byte handshake hash
ck = h                                        // 32-byte chaining key
e  = null                                     // Client ephemeral keypair (X25519)
re = null                                     // Remote server ephemeral public key (32 bytes)
s  = clientStaticKeyPair                      // Client static keypair (X25519)
rs = null                                     // Remote server static public key (32 bytes)
```

### 2.2 Message 1: Client -> Server
* Client generates ephemeral keypair `e = generateKeyPair('x25519')`.
* `mixHash(e.publicKey)`
* **Payload**: `e.publicKey` (32 bytes raw).
* **Frame**: 32 bytes sent as Base64 string over WebSocket.

### 2.3 Message 2: Server -> Client
* Server sends binary frame consisting of:
  * `re.publicKey` (32 bytes)
  * Encrypted `rs.publicKey` + MAC tag (48 bytes: 32 bytes ciphertext + 16 bytes tag)
  * Encrypted payload + MAC tag (attestation payload + 16 bytes tag)
* Client processing:
  1. `mixHash(re)`
  2. `mixKey(DH(e, re))`
  3. `rs = decryptAndHash(encrypted_rs)`
  4. `mixKey(DH(e, rs))`
  5. `payload = decryptAndHash(encrypted_payload)` (attestation verification)

### 2.4 Message 3: Client -> Server
* Client creates Message 3:
  1. `encrypted_s = encryptAndHash(s.publicKey)` (48 bytes: 32 bytes ciphertext + 16 bytes tag)
  2. `mixKey(DH(s, re))`
  3. `encrypted_ticket = encryptAndHash(authTicket)`
* Transmitted frame: `encrypted_s || encrypted_ticket`.

### 2.5 Split into Operational Transport
* After Message 3:
  ```javascript
  [txKey, rxKey] = HKDF(ck, zeroBytes, 2);
  txCipher = new CipherState(txKey);
  rxCipher = new CipherState(rxKey);
  ```
* All subsequent WebSocket messages are encrypted using `txCipher` and decrypted with `rxCipher`.

---

## 3. Wire Framing & Protobuf Definitions

### 3.1 Transport Frame (`ingress_rev_proxy.NoiseTransportFrame`)
Frames sent over WebSocket are Base64 encoded protobuf envelopes:

```protobuf
syntax = "proto3";
package ingress_rev_proxy;

message NoiseTransportFrame {
  int64 chunk_id = 1;        // Grouping identifier for reassembly
  uint32 chunk_index = 2;    // Zero-indexed chunk number
  uint32 total_chunks = 3;   // Total number of chunks in this payload
  bytes payload = 4;         // Encrypted payload slice (<= 65,489 bytes)
}
```

### 3.2 Service Frame (`hatch.noise.ServiceFrame`)
Decrypted payloads contain a multiplexed service frame:

```protobuf
syntax = "proto3";
package hatch.noise;

enum ServiceType {
  SERVICE_DAEMON = 0;
  SERVICE_SENTINEL = 1;
  SERVICE_VAULT = 2;
  SERVICE_AUTHD = 3;
}

message ServiceFrame {
  uint64 stream_id = 1;      // Unique stream identifier
  oneof kind {
    ApplicationRequest request = 2;
    ApplicationResponse response = 3;
    BodyChunk body_chunk = 4;
    Reset reset = 5;
  }
}

message Header {
  string key = 1;
  string value = 2;
}

message ApplicationRequest {
  string verb = 1;           // HTTP verb (e.g. "POST", "GET")
  string path = 2;           // Request path (e.g. "/chat/stream")
  repeated Header headers = 3;
  bytes body = 4;
  bool end_body = 5;
}

message ApplicationResponse {
  uint32 status = 1;         // HTTP status code (e.g. 200)
  repeated Header headers = 2;
  bytes body = 3;
  bool end_body = 4;
}

message BodyChunk {
  bytes data = 1;
  bool end_body = 2;
}

message Reset {
  enum Code {
    CODE_UNSPECIFIED = 0;
    CANCELLED = 1;
    TIMEOUT = 2;
    PROTOCOL_ERROR = 3;
    REFUSED_STREAM = 4;
    INTERNAL_ERROR = 5;
    SERVICE_UNAVAILABLE = 6;
  }
  Code code = 1;
  string reason = 2;
}
```

---

## 4. RPC Route Catalog

All operations inside the encrypted tunnel run over `service: SERVICE_DAEMON` (0) unless specified:

| Route Path | HTTP Method | Service | Mode | Description |
| :--- | :--- | :--- | :--- | :--- |
| `/chat/stream` | `POST` | `daemon` | `subscription` | Initiates streaming conversation with model |
| `/chat/stream-events` | `POST` | `daemon` | `subscription` | Auxiliary event stream |
| `/chat/subscribe` | `POST` | `daemon` | `subscription` | Subscribes to conversation state updates |
| `/client/register-capabilities` | `POST` | `daemon` | `unary` | Registers client tool/function schemas |
| `/client/invoke-result` | `POST` | `daemon` | `unary` | Sends tool execution result back to model |
| `/api/ping` | `POST` | `daemon` | `unary` | Keep-alive heartbeat (sent every 25s) |
| `/chat/cancel` | `POST` | `daemon` | `unary` | Cancels in-flight generation on a stream |
| `/chat/history-window` | `GET` | `daemon` | `unary` | Retrieves conversation history window |
| `/chat/message` | `GET` | `daemon` | `unary` | Retrieves specific message details |
| `/model` | `GET` / `POST`| `daemon` | `unary` | Inspect or switch model capabilities |
| `/navigation/subscribe` | `POST` | `daemon` | `subscription` | Navigation and thread list updates |
