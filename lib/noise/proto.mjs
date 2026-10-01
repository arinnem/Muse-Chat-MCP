/**
 * lib/noise/proto.mjs
 *
 * Zero-dependency pure JavaScript Protobuf encoder/decoder for Meta Muse Noise transport.
 * Implements binary wire framing for:
 *   - ingress_rev_proxy.NoiseTransportFrame
 *   - hatch.noise.ServiceRequest
 *   - hatch.noise.ServiceResponse
 *   - hatch.noise.ServiceFrame (multiplexing ApplicationRequest, ApplicationResponse, BodyChunk, Reset)
 *   - hatch.noise.Header
 *
 * Conforms strictly to Meta's wire descriptors documented in docs/NOISE_PROTOCOL_SPEC.md,
 * docs/PHASE2_NOISE_PLAN.md, and docs/muse-noise-client-ref.js.
 * ZERO external npm dependencies.
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Standard Protobuf Wire Types (proto3).
 */
export const WireType = Object.freeze({
  VARINT: 0,
  FIXED64: 1,
  LENGTH_DELIMITED: 2,
  START_GROUP: 3,
  END_GROUP: 4,
  FIXED32: 5,
});

/**
 * hatch.noise.ServiceType enum.
 */
export const ServiceType = Object.freeze({
  SERVICE_DAEMON: 0,
  SERVICE_SENTINEL: 1,
  SERVICE_VAULT: 2,
  SERVICE_AUTHD: 3,
});

/**
 * hatch.noise.Reset.Code enum.
 */
export const ResetCode = Object.freeze({
  CODE_UNSPECIFIED: 0,
  CANCELLED: 1,
  TIMEOUT: 2,
  PROTOCOL_ERROR: 3,
  REFUSED_STREAM: 4,
  INTERNAL_ERROR: 5,
  SERVICE_UNAVAILABLE: 6,
});

/**
 * High-performance, zero-dependency BinaryWriter for Protobuf encoding.
 */
export class BinaryWriter {
  constructor(initialCapacity = 256) {
    this.buffer = new Uint8Array(initialCapacity);
    this.length = 0;
  }

  ensureCapacity(additional) {
    const required = this.length + additional;
    if (required > this.buffer.length) {
      let newCapacity = Math.max(this.buffer.length * 2, required);
      const newBuf = new Uint8Array(newCapacity);
      newBuf.set(this.buffer.subarray(0, this.length));
      this.buffer = newBuf;
    }
  }

  writeByte(byte) {
    this.ensureCapacity(1);
    this.buffer[this.length++] = byte & 0xff;
  }

  writeBytes(bytes) {
    if (!bytes || bytes.length === 0) return;
    this.ensureCapacity(bytes.length);
    this.buffer.set(bytes, this.length);
    this.length += bytes.length;
  }

  writeVarint32(value) {
    let v = value >>> 0;
    while (v >= 0x80) {
      this.writeByte((v & 0x7f) | 0x80);
      v >>>= 7;
    }
    this.writeByte(v);
  }

  writeVarint64(value) {
    let v = typeof value === "bigint" ? value : BigInt(value);
    if (v < 0n) {
      v = BigInt.asUintN(64, v);
    }
    while (v >= 0x80n) {
      this.writeByte(Number(v & 0x7fn) | 0x80);
      v >>= 7n;
    }
    this.writeByte(Number(v));
  }

  writeTag(fieldNo, wireType) {
    if (fieldNo <= 0 || fieldNo > 536870911) {
      throw new RangeError(`BinaryWriter: invalid field number ${fieldNo}`);
    }
    this.writeVarint32((fieldNo << 3) | (wireType & 0x07));
  }

  writeLengthDelimited(bytes) {
    const len = bytes ? bytes.length : 0;
    this.writeVarint32(len);
    if (len > 0) {
      this.writeBytes(bytes);
    }
  }

  writeString(str) {
    const encoded = textEncoder.encode(str);
    this.writeLengthDelimited(encoded);
  }

  finish() {
    return this.buffer.slice(0, this.length);
  }
}

/**
 * High-performance, zero-dependency BinaryReader for Protobuf decoding with strict boundary checks.
 */
export class BinaryReader {
  constructor(buffer) {
    if (!(buffer instanceof Uint8Array)) {
      if (ArrayBuffer.isView(buffer)) {
        buffer = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      } else if (buffer instanceof ArrayBuffer) {
        buffer = new Uint8Array(buffer);
      } else {
        throw new TypeError("BinaryReader: buffer must be Uint8Array or ArrayBuffer");
      }
    }
    this.buf = buffer;
    this.pos = 0;
    this.len = buffer.length;
  }

  get remaining() {
    return this.len - this.pos;
  }

  get isEOF() {
    return this.pos >= this.len;
  }

  readByte() {
    if (this.pos >= this.len) {
      throw new RangeError("BinaryReader: unexpected end of buffer reading byte");
    }
    return this.buf[this.pos++];
  }

  readBytes(count) {
    if (count < 0) {
      throw new RangeError(`BinaryReader: negative byte length ${count}`);
    }
    if (this.pos + count > this.len) {
      throw new RangeError(`BinaryReader: unexpected end of buffer reading ${count} bytes (remaining: ${this.len - this.pos})`);
    }
    const slice = this.buf.subarray(this.pos, this.pos + count);
    this.pos += count;
    return slice;
  }

  readVarint32() {
    if (this.pos >= this.len) {
      throw new RangeError("BinaryReader: unexpected end of buffer reading varint32");
    }
    const b0 = this.buf[this.pos++];
    if ((b0 & 0x80) === 0) {
      return b0;
    }
    let result = b0 & 0x7f;
    let shift = 7;
    while (true) {
      if (this.pos >= this.len) {
        throw new RangeError("BinaryReader: truncated varint32");
      }
      const b = this.buf[this.pos++];
      result |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) {
        return result >>> 0;
      }
      shift += 7;
      if (shift >= 35) {
        // Varint could be 64-bit/10-byte (e.g. negative int32 in proto3)
        let count = 5;
        while (count < 10 && (b & 0x80) !== 0) {
          if (this.pos >= this.len) throw new RangeError("BinaryReader: truncated varint32");
          const nextB = this.buf[this.pos++];
          count++;
          if ((nextB & 0x80) === 0) break;
        }
        return result >>> 0;
      }
    }
  }

  readVarint64() {
    if (this.pos >= this.len) {
      throw new RangeError("BinaryReader: unexpected end of buffer reading varint64");
    }
    const b0 = this.buf[this.pos++];
    if ((b0 & 0x80) === 0) {
      return BigInt(b0);
    }
    let result = BigInt(b0 & 0x7f);
    let shift = 7n;
    let count = 1;
    while (true) {
      if (this.pos >= this.len) {
        throw new RangeError("BinaryReader: truncated varint64");
      }
      const b = this.buf[this.pos++];
      result |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) {
        return result;
      }
      shift += 7n;
      count++;
      if (count >= 10) {
        throw new RangeError("BinaryReader: malformed varint exceeds 10 bytes");
      }
    }
  }

  readInt64() {
    return BigInt.asIntN(64, this.readVarint64());
  }

  readUint64() {
    return BigInt.asUintN(64, this.readVarint64());
  }

  readInt32() {
    return this.readVarint32() | 0;
  }

  readUint32() {
    return this.readVarint32() >>> 0;
  }

  readBool() {
    return this.readVarint32() !== 0;
  }

  readTag() {
    if (this.pos >= this.len) {
      return null;
    }
    const tag = this.readVarint32();
    const fieldNo = tag >>> 3;
    const wireType = tag & 0x07;
    if (fieldNo === 0) {
      throw new Error(`BinaryReader: invalid field number 0 in tag ${tag}`);
    }
    return { tag, fieldNo, wireType };
  }

  readLengthDelimited() {
    const length = this.readVarint32();
    return this.readBytes(length);
  }

  readString() {
    const bytes = this.readLengthDelimited();
    return textDecoder.decode(bytes);
  }

  skipType(wireType) {
    switch (wireType) {
      case WireType.VARINT:
        this.readVarint64();
        break;
      case WireType.FIXED64:
        this.readBytes(8);
        break;
      case WireType.LENGTH_DELIMITED:
        this.readLengthDelimited();
        break;
      case WireType.FIXED32:
        this.readBytes(4);
        break;
      default:
        throw new Error(`BinaryReader: cannot skip unsupported wire type ${wireType}`);
    }
  }
}

// Standalone primitive helper functions
export function writeVarint(writerOrBuf, value) {
  if (writerOrBuf instanceof BinaryWriter) {
    if (typeof value === "bigint" || value > 0xffffffff || value < 0) {
      writerOrBuf.writeVarint64(value);
    } else {
      writerOrBuf.writeVarint32(value);
    }
    return;
  }
  const w = new BinaryWriter(10);
  if (typeof value === "bigint" || value > 0xffffffff || value < 0) {
    w.writeVarint64(value);
  } else {
    w.writeVarint32(value);
  }
  return w.finish();
}

export function readVarint(readerOrBuf, offset = 0) {
  if (readerOrBuf instanceof BinaryReader) {
    return readerOrBuf.readVarint64();
  }
  const r = new BinaryReader(readerOrBuf.subarray ? readerOrBuf.subarray(offset) : new Uint8Array(readerOrBuf, offset));
  const val = r.readVarint64();
  return { value: val, bytesRead: r.pos, newOffset: offset + r.pos };
}

export function writeTag(writer, fieldNo, wireType) {
  if (writer instanceof BinaryWriter) {
    writer.writeTag(fieldNo, wireType);
    return;
  }
  const w = new BinaryWriter(5);
  w.writeTag(fieldNo, wireType);
  return w.finish();
}

export function readTag(readerOrBuf, offset = 0) {
  if (readerOrBuf instanceof BinaryReader) {
    return readerOrBuf.readTag();
  }
  const r = new BinaryReader(readerOrBuf.subarray ? readerOrBuf.subarray(offset) : new Uint8Array(readerOrBuf, offset));
  const tagInfo = r.readTag();
  if (!tagInfo) return null;
  return { ...tagInfo, bytesRead: r.pos, newOffset: offset + r.pos };
}

export function writeBytes(writer, fieldNo, bytes) {
  if (!(writer instanceof BinaryWriter)) {
    const w = new BinaryWriter();
    w.writeTag(fieldNo, WireType.LENGTH_DELIMITED);
    w.writeLengthDelimited(bytes);
    return w.finish();
  }
  writer.writeTag(fieldNo, WireType.LENGTH_DELIMITED);
  writer.writeLengthDelimited(bytes);
}

export function readBytes(reader, length) {
  if (reader instanceof BinaryReader) {
    return length !== undefined ? reader.readBytes(length) : reader.readLengthDelimited();
  }
  throw new TypeError("readBytes: reader must be BinaryReader instance");
}

export function writeString(writer, fieldNo, str) {
  if (!(writer instanceof BinaryWriter)) {
    const w = new BinaryWriter();
    w.writeTag(fieldNo, WireType.LENGTH_DELIMITED);
    w.writeString(str);
    return w.finish();
  }
  writer.writeTag(fieldNo, WireType.LENGTH_DELIMITED);
  writer.writeString(str);
}

export function readString(reader) {
  if (reader instanceof BinaryReader) {
    return reader.readString();
  }
  throw new TypeError("readString: reader must be BinaryReader instance");
}

// -----------------------------------------------------------------------------
// Message Classes & Codecs
// -----------------------------------------------------------------------------

/**
 * Message: Header
 */
export class Header {
  constructor(init = {}) {
    this.key = init.key ?? "";
    this.value = init.value ?? "";
  }
}

export function encodeHeader(msg) {
  if (!msg || typeof msg !== "object") {
    throw new TypeError("encodeHeader: msg must be an object");
  }
  const writer = new BinaryWriter();
  if (msg.key && msg.key.length > 0) {
    writer.writeTag(1, WireType.LENGTH_DELIMITED);
    writer.writeString(msg.key);
  }
  if (msg.value && msg.value.length > 0) {
    writer.writeTag(2, WireType.LENGTH_DELIMITED);
    writer.writeString(msg.value);
  }
  return writer.finish();
}

export function decodeHeader(buf) {
  const reader = new BinaryReader(buf);
  let key = "";
  let value = "";

  let tagInfo;
  while ((tagInfo = reader.readTag()) !== null) {
    const { fieldNo, wireType } = tagInfo;
    switch (fieldNo) {
      case 1:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeHeader: field 1 (key) expected wireType 2, got ${wireType}`);
        }
        key = reader.readString();
        break;
      case 2:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeHeader: field 2 (value) expected wireType 2, got ${wireType}`);
        }
        value = reader.readString();
        break;
      default:
        reader.skipType(wireType);
        break;
    }
  }

  return new Header({ key, value });
}

/**
 * Message: NoiseTransportFrame
 * ingress_rev_proxy.NoiseTransportFrame
 */
export class NoiseTransportFrame {
  constructor(init = {}) {
    const rawId = init.chunk_id !== undefined ? init.chunk_id : init.chunkId;
    this.chunk_id = rawId !== undefined ? (typeof rawId === "bigint" ? rawId : BigInt(rawId)) : 0n;

    const rawIdx = init.chunk_index !== undefined ? init.chunk_index : init.chunkIndex;
    this.chunk_index = rawIdx !== undefined ? Number(rawIdx) : 0;

    const rawTotal = init.total_chunks !== undefined ? init.total_chunks : init.totalChunks;
    this.total_chunks = rawTotal !== undefined ? Number(rawTotal) : 1;

    const rawPayload = init.payload;
    this.payload = rawPayload ? (rawPayload instanceof Uint8Array ? rawPayload : new Uint8Array(rawPayload)) : new Uint8Array(0);
  }

  get chunkId() { return this.chunk_id; }
  set chunkId(v) { this.chunk_id = typeof v === "bigint" ? v : BigInt(v); }

  get chunkIndex() { return this.chunk_index; }
  set chunkIndex(v) { this.chunk_index = Number(v); }

  get totalChunks() { return this.total_chunks; }
  set totalChunks(v) { this.total_chunks = Number(v); }
}

export function encodeNoiseTransportFrame(msg) {
  if (!msg || typeof msg !== "object") {
    throw new TypeError("encodeNoiseTransportFrame: msg must be an object");
  }
  const writer = new BinaryWriter();

  // chunk_id: tag 1, int64 (proto3_optional in descriptor, explicit presence)
  const chunkId = msg.chunk_id !== undefined ? msg.chunk_id : msg.chunkId;
  if (chunkId !== undefined && chunkId !== null) {
    writer.writeTag(1, WireType.VARINT);
    writer.writeVarint64(chunkId);
  }

  // chunk_index: tag 2, uint32
  const chunkIndex = msg.chunk_index !== undefined ? msg.chunk_index : msg.chunkIndex;
  if (chunkIndex !== undefined && chunkIndex !== null) {
    if (chunkIndex < 0 || !Number.isInteger(Number(chunkIndex))) {
      throw new RangeError(`encodeNoiseTransportFrame: chunk_index must be non-negative integer, got ${chunkIndex}`);
    }
    writer.writeTag(2, WireType.VARINT);
    writer.writeVarint32(Number(chunkIndex));
  }

  // total_chunks: tag 3, uint32
  const totalChunks = msg.total_chunks !== undefined ? msg.total_chunks : msg.totalChunks;
  if (totalChunks !== undefined && totalChunks !== null) {
    if (totalChunks < 0 || !Number.isInteger(Number(totalChunks))) {
      throw new RangeError(`encodeNoiseTransportFrame: total_chunks must be non-negative integer, got ${totalChunks}`);
    }
    writer.writeTag(3, WireType.VARINT);
    writer.writeVarint32(Number(totalChunks));
  }

  // payload: tag 4, bytes
  const payload = msg.payload;
  if (payload !== undefined && payload !== null) {
    const payloadBytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
    writer.writeTag(4, WireType.LENGTH_DELIMITED);
    writer.writeLengthDelimited(payloadBytes);
  }

  return writer.finish();
}

export function decodeNoiseTransportFrame(buf) {
  const reader = new BinaryReader(buf);
  let chunk_id = 0n;
  let chunk_index = 0;
  let total_chunks = 1;
  let payload = new Uint8Array(0);

  let tagInfo;
  while ((tagInfo = reader.readTag()) !== null) {
    const { fieldNo, wireType } = tagInfo;
    switch (fieldNo) {
      case 1:
        if (wireType !== WireType.VARINT) {
          throw new Error(`decodeNoiseTransportFrame: field 1 (chunk_id) expected wireType 0, got ${wireType}`);
        }
        chunk_id = reader.readInt64();
        break;
      case 2:
        if (wireType !== WireType.VARINT) {
          throw new Error(`decodeNoiseTransportFrame: field 2 (chunk_index) expected wireType 0, got ${wireType}`);
        }
        chunk_index = reader.readUint32();
        break;
      case 3:
        if (wireType !== WireType.VARINT) {
          throw new Error(`decodeNoiseTransportFrame: field 3 (total_chunks) expected wireType 0, got ${wireType}`);
        }
        total_chunks = reader.readUint32();
        break;
      case 4:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeNoiseTransportFrame: field 4 (payload) expected wireType 2, got ${wireType}`);
        }
        payload = reader.readLengthDelimited();
        break;
      default:
        reader.skipType(wireType);
        break;
    }
  }

  return new NoiseTransportFrame({
    chunk_id,
    chunk_index,
    total_chunks,
    payload,
  });
}

/**
 * Message: ServiceRequest
 * hatch.noise.ServiceRequest
 */
export class ServiceRequest {
  constructor(init = {}) {
    this.service = init.service !== undefined ? Number(init.service) : ServiceType.SERVICE_DAEMON;
    const rawPayload = init.payload;
    this.payload = rawPayload ? (rawPayload instanceof Uint8Array ? rawPayload : (typeof rawPayload === "string" ? textEncoder.encode(rawPayload) : new Uint8Array(rawPayload))) : new Uint8Array(0);
  }
}

export function encodeServiceRequest(msg) {
  if (!msg || typeof msg !== "object") {
    throw new TypeError("encodeServiceRequest: msg must be an object");
  }
  const writer = new BinaryWriter();

  const service = msg.service !== undefined ? Number(msg.service) : ServiceType.SERVICE_DAEMON;
  if (service !== ServiceType.SERVICE_DAEMON) {
    writer.writeTag(1, WireType.VARINT);
    writer.writeVarint32(service);
  }

  const payload = msg.payload;
  if (payload !== undefined && payload !== null && payload.length > 0) {
    const payloadBytes = payload instanceof Uint8Array ? payload : (typeof payload === "string" ? textEncoder.encode(payload) : new Uint8Array(payload));
    writer.writeTag(2, WireType.LENGTH_DELIMITED);
    writer.writeLengthDelimited(payloadBytes);
  }

  return writer.finish();
}

export function decodeServiceRequest(buf) {
  const reader = new BinaryReader(buf);
  let service = ServiceType.SERVICE_DAEMON;
  let payload = new Uint8Array(0);

  let tagInfo;
  while ((tagInfo = reader.readTag()) !== null) {
    const { fieldNo, wireType } = tagInfo;
    switch (fieldNo) {
      case 1:
        if (wireType !== WireType.VARINT) {
          throw new Error(`decodeServiceRequest: field 1 (service) expected wireType 0, got ${wireType}`);
        }
        service = reader.readUint32();
        break;
      case 2:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeServiceRequest: field 2 (payload) expected wireType 2, got ${wireType}`);
        }
        payload = reader.readLengthDelimited();
        break;
      default:
        reader.skipType(wireType);
        break;
    }
  }

  return new ServiceRequest({ service, payload });
}

/**
 * Message: ServiceResponse
 * hatch.noise.ServiceResponse
 */
export class ServiceResponse {
  constructor(init = {}) {
    const rawPayload = init.payload;
    this.payload = rawPayload ? (rawPayload instanceof Uint8Array ? rawPayload : (typeof rawPayload === "string" ? textEncoder.encode(rawPayload) : new Uint8Array(rawPayload))) : new Uint8Array(0);
  }
}

export function encodeServiceResponse(msg) {
  if (!msg || typeof msg !== "object") {
    throw new TypeError("encodeServiceResponse: msg must be an object");
  }
  const writer = new BinaryWriter();

  const payload = msg.payload;
  if (payload !== undefined && payload !== null && payload.length > 0) {
    const payloadBytes = payload instanceof Uint8Array ? payload : (typeof payload === "string" ? textEncoder.encode(payload) : new Uint8Array(payload));
    writer.writeTag(1, WireType.LENGTH_DELIMITED);
    writer.writeLengthDelimited(payloadBytes);
  }

  return writer.finish();
}

export function decodeServiceResponse(buf) {
  const reader = new BinaryReader(buf);
  let payload = new Uint8Array(0);

  let tagInfo;
  while ((tagInfo = reader.readTag()) !== null) {
    const { fieldNo, wireType } = tagInfo;
    switch (fieldNo) {
      case 1:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeServiceResponse: field 1 (payload) expected wireType 2, got ${wireType}`);
        }
        payload = reader.readLengthDelimited();
        break;
      default:
        reader.skipType(wireType);
        break;
    }
  }

  return new ServiceResponse({ payload });
}

/**
 * Message: ApplicationRequest
 * hatch.noise.ApplicationRequest
 */
export class ApplicationRequest {
  constructor(init = {}) {
    this.verb = init.verb ?? "";
    this.path = init.path ?? "";
    this.headers = Array.isArray(init.headers)
      ? init.headers.map(h => (h instanceof Header ? h : new Header(h)))
      : [];
    const rawBody = init.body;
    this.body = rawBody ? (rawBody instanceof Uint8Array ? rawBody : (typeof rawBody === "string" ? textEncoder.encode(rawBody) : new Uint8Array(rawBody))) : new Uint8Array(0);
    this.end_body = init.end_body !== undefined ? Boolean(init.end_body) : Boolean(init.endBody);
  }

  get endBody() { return this.end_body; }
  set endBody(v) { this.end_body = Boolean(v); }
}

export function encodeApplicationRequest(msg) {
  if (!msg || typeof msg !== "object") {
    throw new TypeError("encodeApplicationRequest: msg must be an object");
  }
  const writer = new BinaryWriter();

  if (msg.verb && msg.verb.length > 0) {
    writer.writeTag(1, WireType.LENGTH_DELIMITED);
    writer.writeString(msg.verb);
  }

  if (msg.path && msg.path.length > 0) {
    writer.writeTag(2, WireType.LENGTH_DELIMITED);
    writer.writeString(msg.path);
  }

  const headers = msg.headers;
  if (Array.isArray(headers)) {
    for (const h of headers) {
      const hBytes = encodeHeader(h);
      writer.writeTag(3, WireType.LENGTH_DELIMITED);
      writer.writeLengthDelimited(hBytes);
    }
  }

  const body = msg.body;
  if (body !== undefined && body !== null && body.length > 0) {
    const bodyBytes = body instanceof Uint8Array ? body : (typeof body === "string" ? textEncoder.encode(body) : new Uint8Array(body));
    writer.writeTag(4, WireType.LENGTH_DELIMITED);
    writer.writeLengthDelimited(bodyBytes);
  }

  const endBody = msg.end_body !== undefined ? msg.end_body : msg.endBody;
  if (endBody) {
    writer.writeTag(5, WireType.VARINT);
    writer.writeByte(1);
  }

  return writer.finish();
}

export function decodeApplicationRequest(buf) {
  const reader = new BinaryReader(buf);
  let verb = "";
  let path = "";
  const headers = [];
  let body = new Uint8Array(0);
  let end_body = false;

  let tagInfo;
  while ((tagInfo = reader.readTag()) !== null) {
    const { fieldNo, wireType } = tagInfo;
    switch (fieldNo) {
      case 1:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeApplicationRequest: field 1 (verb) expected wireType 2, got ${wireType}`);
        }
        verb = reader.readString();
        break;
      case 2:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeApplicationRequest: field 2 (path) expected wireType 2, got ${wireType}`);
        }
        path = reader.readString();
        break;
      case 3:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeApplicationRequest: field 3 (headers) expected wireType 2, got ${wireType}`);
        }
        headers.push(decodeHeader(reader.readLengthDelimited()));
        break;
      case 4:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeApplicationRequest: field 4 (body) expected wireType 2, got ${wireType}`);
        }
        body = reader.readLengthDelimited();
        break;
      case 5:
        if (wireType !== WireType.VARINT) {
          throw new Error(`decodeApplicationRequest: field 5 (end_body) expected wireType 0, got ${wireType}`);
        }
        end_body = reader.readBool();
        break;
      default:
        reader.skipType(wireType);
        break;
    }
  }

  return new ApplicationRequest({ verb, path, headers, body, end_body });
}

/**
 * Message: ApplicationResponse
 * hatch.noise.ApplicationResponse
 */
export class ApplicationResponse {
  constructor(init = {}) {
    this.status = init.status !== undefined ? Number(init.status) : 0;
    this.headers = Array.isArray(init.headers)
      ? init.headers.map(h => (h instanceof Header ? h : new Header(h)))
      : [];
    const rawBody = init.body;
    this.body = rawBody ? (rawBody instanceof Uint8Array ? rawBody : (typeof rawBody === "string" ? textEncoder.encode(rawBody) : new Uint8Array(rawBody))) : new Uint8Array(0);
    this.end_body = init.end_body !== undefined ? Boolean(init.end_body) : Boolean(init.endBody);
  }

  get endBody() { return this.end_body; }
  set endBody(v) { this.end_body = Boolean(v); }
}

export function encodeApplicationResponse(msg) {
  if (!msg || typeof msg !== "object") {
    throw new TypeError("encodeApplicationResponse: msg must be an object");
  }
  const writer = new BinaryWriter();

  const status = msg.status !== undefined ? Number(msg.status) : 0;
  if (status !== 0) {
    writer.writeTag(1, WireType.VARINT);
    writer.writeVarint32(status);
  }

  const headers = msg.headers;
  if (Array.isArray(headers)) {
    for (const h of headers) {
      const hBytes = encodeHeader(h);
      writer.writeTag(2, WireType.LENGTH_DELIMITED);
      writer.writeLengthDelimited(hBytes);
    }
  }

  const body = msg.body;
  if (body !== undefined && body !== null && body.length > 0) {
    const bodyBytes = body instanceof Uint8Array ? body : (typeof body === "string" ? textEncoder.encode(body) : new Uint8Array(body));
    writer.writeTag(3, WireType.LENGTH_DELIMITED);
    writer.writeLengthDelimited(bodyBytes);
  }

  const endBody = msg.end_body !== undefined ? msg.end_body : msg.endBody;
  if (endBody) {
    writer.writeTag(4, WireType.VARINT);
    writer.writeByte(1);
  }

  return writer.finish();
}

export function decodeApplicationResponse(buf) {
  const reader = new BinaryReader(buf);
  let status = 0;
  const headers = [];
  let body = new Uint8Array(0);
  let end_body = false;

  let tagInfo;
  while ((tagInfo = reader.readTag()) !== null) {
    const { fieldNo, wireType } = tagInfo;
    switch (fieldNo) {
      case 1:
        if (wireType !== WireType.VARINT) {
          throw new Error(`decodeApplicationResponse: field 1 (status) expected wireType 0, got ${wireType}`);
        }
        status = reader.readUint32();
        break;
      case 2:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeApplicationResponse: field 2 (headers) expected wireType 2, got ${wireType}`);
        }
        headers.push(decodeHeader(reader.readLengthDelimited()));
        break;
      case 3:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeApplicationResponse: field 3 (body) expected wireType 2, got ${wireType}`);
        }
        body = reader.readLengthDelimited();
        break;
      case 4:
        if (wireType !== WireType.VARINT) {
          throw new Error(`decodeApplicationResponse: field 4 (end_body) expected wireType 0, got ${wireType}`);
        }
        end_body = reader.readBool();
        break;
      default:
        reader.skipType(wireType);
        break;
    }
  }

  return new ApplicationResponse({ status, headers, body, end_body });
}

/**
 * Message: BodyChunk
 * hatch.noise.BodyChunk
 */
export class BodyChunk {
  constructor(init = {}) {
    const rawData = init.data;
    this.data = rawData ? (rawData instanceof Uint8Array ? rawData : (typeof rawData === "string" ? textEncoder.encode(rawData) : new Uint8Array(rawData))) : new Uint8Array(0);
    this.end_body = init.end_body !== undefined ? Boolean(init.end_body) : Boolean(init.endBody);
  }

  get endBody() { return this.end_body; }
  set endBody(v) { this.end_body = Boolean(v); }
}

export function encodeBodyChunk(msg) {
  if (!msg || typeof msg !== "object") {
    throw new TypeError("encodeBodyChunk: msg must be an object");
  }
  const writer = new BinaryWriter();

  const data = msg.data;
  if (data !== undefined && data !== null && data.length > 0) {
    const dataBytes = data instanceof Uint8Array ? data : (typeof data === "string" ? textEncoder.encode(data) : new Uint8Array(data));
    writer.writeTag(1, WireType.LENGTH_DELIMITED);
    writer.writeLengthDelimited(dataBytes);
  }

  const endBody = msg.end_body !== undefined ? msg.end_body : msg.endBody;
  if (endBody) {
    writer.writeTag(2, WireType.VARINT);
    writer.writeByte(1);
  }

  return writer.finish();
}

export function decodeBodyChunk(buf) {
  const reader = new BinaryReader(buf);
  let data = new Uint8Array(0);
  let end_body = false;

  let tagInfo;
  while ((tagInfo = reader.readTag()) !== null) {
    const { fieldNo, wireType } = tagInfo;
    switch (fieldNo) {
      case 1:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeBodyChunk: field 1 (data) expected wireType 2, got ${wireType}`);
        }
        data = reader.readLengthDelimited();
        break;
      case 2:
        if (wireType !== WireType.VARINT) {
          throw new Error(`decodeBodyChunk: field 2 (end_body) expected wireType 0, got ${wireType}`);
        }
        end_body = reader.readBool();
        break;
      default:
        reader.skipType(wireType);
        break;
    }
  }

  return new BodyChunk({ data, end_body });
}

/**
 * Message: Reset
 * hatch.noise.Reset
 */
export class Reset {
  static Code = ResetCode;

  constructor(init = {}) {
    this.code = init.code !== undefined ? Number(init.code) : ResetCode.CODE_UNSPECIFIED;
    this.reason = init.reason ?? "";
  }
}

export function encodeReset(msg) {
  if (!msg || typeof msg !== "object") {
    throw new TypeError("encodeReset: msg must be an object");
  }
  const writer = new BinaryWriter();

  const code = msg.code !== undefined ? Number(msg.code) : ResetCode.CODE_UNSPECIFIED;
  if (code !== ResetCode.CODE_UNSPECIFIED) {
    writer.writeTag(1, WireType.VARINT);
    writer.writeVarint32(code);
  }

  const reason = msg.reason;
  if (reason && reason.length > 0) {
    writer.writeTag(2, WireType.LENGTH_DELIMITED);
    writer.writeString(reason);
  }

  return writer.finish();
}

export function decodeReset(buf) {
  const reader = new BinaryReader(buf);
  let code = ResetCode.CODE_UNSPECIFIED;
  let reason = "";

  let tagInfo;
  while ((tagInfo = reader.readTag()) !== null) {
    const { fieldNo, wireType } = tagInfo;
    switch (fieldNo) {
      case 1:
        if (wireType !== WireType.VARINT) {
          throw new Error(`decodeReset: field 1 (code) expected wireType 0, got ${wireType}`);
        }
        code = reader.readUint32();
        break;
      case 2:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeReset: field 2 (reason) expected wireType 2, got ${wireType}`);
        }
        reason = reader.readString();
        break;
      default:
        reader.skipType(wireType);
        break;
    }
  }

  return new Reset({ code, reason });
}

/**
 * Message: ServiceFrame
 * hatch.noise.ServiceFrame
 * Multiplexed frame with oneof kind (request | response | body_chunk | reset).
 */
export class ServiceFrame {
  constructor(init = {}) {
    const sid = init.stream_id !== undefined ? init.stream_id : init.streamId;
    this.stream_id = sid !== undefined ? (typeof sid === "bigint" ? sid : BigInt(sid)) : 0n;

    let req = init.request ?? null;
    let res = init.response ?? null;
    let chunk = init.body_chunk ?? init.bodyChunk ?? null;
    let rst = init.reset ?? null;

    if (init.kind && typeof init.kind === "object") {
      const k = init.kind.case;
      const v = init.kind.value;
      if (k === "request") req = v;
      else if (k === "response") res = v;
      else if (k === "body_chunk" || k === "bodyChunk") chunk = v;
      else if (k === "reset") rst = v;
    }

    this.request = req ? (req instanceof ApplicationRequest ? req : new ApplicationRequest(req)) : null;
    this.response = res ? (res instanceof ApplicationResponse ? res : new ApplicationResponse(res)) : null;
    this.body_chunk = chunk ? (chunk instanceof BodyChunk ? chunk : new BodyChunk(chunk)) : null;
    this.reset = rst ? (rst instanceof Reset ? rst : new Reset(rst)) : null;

    if (this.request) {
      this.kind = { case: "request", value: this.request };
    } else if (this.response) {
      this.kind = { case: "response", value: this.response };
    } else if (this.body_chunk) {
      this.kind = { case: "body_chunk", value: this.body_chunk };
    } else if (this.reset) {
      this.kind = { case: "reset", value: this.reset };
    } else {
      this.kind = null;
    }
  }

  get streamId() { return this.stream_id; }
  set streamId(v) { this.stream_id = typeof v === "bigint" ? v : BigInt(v); }

  get bodyChunk() { return this.body_chunk; }
  set bodyChunk(v) {
    this.body_chunk = v ? (v instanceof BodyChunk ? v : new BodyChunk(v)) : null;
    if (this.body_chunk) {
      this.kind = { case: "body_chunk", value: this.body_chunk };
    }
  }
}

export function encodeServiceFrame(msg) {
  if (!msg || typeof msg !== "object") {
    throw new TypeError("encodeServiceFrame: msg must be an object");
  }
  const writer = new BinaryWriter();

  const streamId = msg.stream_id !== undefined ? msg.stream_id : msg.streamId;
  if (streamId !== undefined && streamId !== null && streamId !== 0n && streamId !== 0) {
    writer.writeTag(1, WireType.VARINT);
    writer.writeVarint64(streamId);
  }

  let request = msg.request;
  let response = msg.response;
  let bodyChunk = msg.body_chunk ?? msg.bodyChunk;
  let reset = msg.reset;

  if (msg.kind && typeof msg.kind === "object") {
    const k = msg.kind.case;
    const v = msg.kind.value;
    if (k === "request") request = v;
    else if (k === "response") response = v;
    else if (k === "body_chunk" || k === "bodyChunk") bodyChunk = v;
    else if (k === "reset") reset = v;
  }

  if (request !== undefined && request !== null) {
    const bytes = encodeApplicationRequest(request);
    writer.writeTag(2, WireType.LENGTH_DELIMITED);
    writer.writeLengthDelimited(bytes);
  } else if (response !== undefined && response !== null) {
    const bytes = encodeApplicationResponse(response);
    writer.writeTag(3, WireType.LENGTH_DELIMITED);
    writer.writeLengthDelimited(bytes);
  } else if (bodyChunk !== undefined && bodyChunk !== null) {
    const bytes = encodeBodyChunk(bodyChunk);
    writer.writeTag(4, WireType.LENGTH_DELIMITED);
    writer.writeLengthDelimited(bytes);
  } else if (reset !== undefined && reset !== null) {
    const bytes = encodeReset(reset);
    writer.writeTag(5, WireType.LENGTH_DELIMITED);
    writer.writeLengthDelimited(bytes);
  }

  return writer.finish();
}

export function decodeServiceFrame(buf) {
  const reader = new BinaryReader(buf);
  let stream_id = 0n;
  let request = null;
  let response = null;
  let body_chunk = null;
  let reset = null;
  let kind = null;

  let tagInfo;
  while ((tagInfo = reader.readTag()) !== null) {
    const { fieldNo, wireType } = tagInfo;
    switch (fieldNo) {
      case 1:
        if (wireType !== WireType.VARINT) {
          throw new Error(`decodeServiceFrame: field 1 (stream_id) expected wireType 0, got ${wireType}`);
        }
        stream_id = reader.readUint64();
        break;
      case 2:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeServiceFrame: field 2 (request) expected wireType 2, got ${wireType}`);
        }
        request = decodeApplicationRequest(reader.readLengthDelimited());
        kind = { case: "request", value: request };
        break;
      case 3:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeServiceFrame: field 3 (response) expected wireType 2, got ${wireType}`);
        }
        response = decodeApplicationResponse(reader.readLengthDelimited());
        kind = { case: "response", value: response };
        break;
      case 4:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeServiceFrame: field 4 (body_chunk) expected wireType 2, got ${wireType}`);
        }
        body_chunk = decodeBodyChunk(reader.readLengthDelimited());
        kind = { case: "body_chunk", value: body_chunk };
        break;
      case 5:
        if (wireType !== WireType.LENGTH_DELIMITED) {
          throw new Error(`decodeServiceFrame: field 5 (reset) expected wireType 2, got ${wireType}`);
        }
        reset = decodeReset(reader.readLengthDelimited());
        kind = { case: "reset", value: reset };
        break;
      default:
        reader.skipType(wireType);
        break;
    }
  }

  return new ServiceFrame({
    stream_id,
    kind,
    request,
    response,
    body_chunk,
    reset,
  });
}
