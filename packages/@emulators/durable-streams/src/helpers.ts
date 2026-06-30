import type { Context } from "@emulators/core";
import type { DurableStreamEntity, DurableStreamMessage, DurableStreamProducer } from "./entities.js";
import type { DurableStreamsStore } from "./store.js";

type ResponseBody = ConstructorParameters<typeof Response>[0];

export const ZERO_OFFSET = "0000000000000000_0000000000000000";
export const STREAM_OFFSET_HEADER = "Stream-Next-Offset";
export const STREAM_CURSOR_HEADER = "Stream-Cursor";
export const STREAM_UP_TO_DATE_HEADER = "Stream-Up-To-Date";
export const STREAM_CLOSED_HEADER = "Stream-Closed";
export const STREAM_SEQ_HEADER = "Stream-Seq";
export const STREAM_TTL_HEADER = "Stream-TTL";
export const STREAM_EXPIRES_AT_HEADER = "Stream-Expires-At";
export const PRODUCER_ID_HEADER = "Producer-Id";
export const PRODUCER_EPOCH_HEADER = "Producer-Epoch";
export const PRODUCER_SEQ_HEADER = "Producer-Seq";
export const PRODUCER_EXPECTED_SEQ_HEADER = "Producer-Expected-Seq";
export const PRODUCER_RECEIVED_SEQ_HEADER = "Producer-Received-Seq";
export const STREAM_SSE_DATA_ENCODING_HEADER = "Stream-SSE-Data-Encoding";

export const OFFSET_QUERY_PARAM = "offset";
export const LIVE_QUERY_PARAM = "live";
export const CURSOR_QUERY_PARAM = "cursor";

const EXPOSED_HEADERS = [
  STREAM_OFFSET_HEADER,
  STREAM_CURSOR_HEADER,
  STREAM_UP_TO_DATE_HEADER,
  STREAM_CLOSED_HEADER,
  STREAM_TTL_HEADER,
  STREAM_EXPIRES_AT_HEADER,
  PRODUCER_EPOCH_HEADER,
  PRODUCER_SEQ_HEADER,
  PRODUCER_EXPECTED_SEQ_HEADER,
  PRODUCER_RECEIVED_SEQ_HEADER,
  "ETag",
  "Content-Type",
  "Content-Encoding",
  "Vary",
];

const FRAME_OVERHEAD = 5;

export interface ProducerValidationAccepted {
  status: "accepted";
  producer?: DurableStreamProducer;
  epoch: number;
  lastSeq: number;
}

export interface ProducerValidationDuplicate {
  status: "duplicate";
  lastSeq: number;
}

export interface ProducerValidationStaleEpoch {
  status: "stale_epoch";
  currentEpoch: number;
}

export interface ProducerValidationInvalidEpochSeq {
  status: "invalid_epoch_seq";
}

export interface ProducerValidationSequenceGap {
  status: "sequence_gap";
  expectedSeq: number;
  receivedSeq: number;
}

export type ProducerValidationResult =
  | ProducerValidationAccepted
  | ProducerValidationDuplicate
  | ProducerValidationStaleEpoch
  | ProducerValidationInvalidEpochSeq
  | ProducerValidationSequenceGap;

export function protocolHeaders(headers: Record<string, string> = {}): Record<string, string> {
  return {
    "Access-Control-Expose-Headers": EXPOSED_HEADERS.join(", "),
    ...headers,
  };
}

export function textResponse(
  c: Context,
  status: number,
  message: string,
  headers: Record<string, string> = {},
): Response {
  return c.text(message, status, protocolHeaders(headers));
}

export function bodyResponse(
  c: Context,
  status: number,
  body: ResponseBody | null,
  headers: Record<string, string> = {},
): Response {
  return c.body(body, status, protocolHeaders(headers));
}

export function normalizeStreamPath(pathname: string): string {
  if (!pathname || pathname === "/") return "/";
  try {
    return decodeURI(pathname);
  } catch {
    return pathname;
  }
}

export function mediaType(contentType: string | undefined): string {
  return (contentType ?? "").split(";")[0]!.trim().toLowerCase();
}

export function isJsonContentType(contentType: string | undefined): boolean {
  return mediaType(contentType) === "application/json";
}

export function isSseTextCompatible(contentType: string | undefined): boolean {
  const type = mediaType(contentType);
  return type.startsWith("text/") || type === "application/json";
}

export function validateOffset(offset: string): boolean {
  return /^(-1|now|\d+_\d+)$/.test(offset);
}

export function parseIntegerHeader(value: string | undefined): number | null {
  if (value === undefined || !/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

export function readMessages(ds: DurableStreamsStore, streamPath: string): DurableStreamMessage[] {
  return ds.messages.findBy("stream_path", streamPath).sort((a, b) => a.offset.localeCompare(b.offset));
}

export function messagesAfterOffset(
  messages: DurableStreamMessage[],
  offset: string | undefined,
): DurableStreamMessage[] {
  if (!offset || offset === "-1") return messages;
  if (offset === "now") return [];
  return messages.filter((message) => message.offset > offset);
}

export function decodeMessageBody(message: DurableStreamMessage): Uint8Array {
  return Buffer.from(message.body_base64, "base64");
}

export function encodeMessageBody(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

export function processJsonAppend(data: Uint8Array, isInitialCreate = false): Uint8Array {
  const text = new TextDecoder().decode(data);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Invalid JSON");
  }

  if (Array.isArray(parsed)) {
    if (parsed.length === 0) {
      if (isInitialCreate) return new Uint8Array(0);
      throw new Error("Empty arrays are not allowed");
    }
    return new TextEncoder().encode(`${parsed.map((item) => JSON.stringify(item)).join(",")},`);
  }

  return new TextEncoder().encode(`${JSON.stringify(parsed)},`);
}

export function formatJsonMessages(messages: DurableStreamMessage[]): Uint8Array {
  if (messages.length === 0) {
    return new TextEncoder().encode("[]");
  }

  const chunks = messages.map((message) => new TextDecoder().decode(decodeMessageBody(message)).trimEnd()).join("");
  const withoutTrailingComma = chunks.endsWith(",") ? chunks.slice(0, -1) : chunks;
  return new TextEncoder().encode(`[${withoutTrailingComma}]`);
}

export function formatMessages(contentType: string, messages: DurableStreamMessage[]): Uint8Array {
  if (isJsonContentType(contentType)) {
    return formatJsonMessages(messages);
  }

  const totalLength = messages.reduce((sum, message) => sum + message.content_length, 0);
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const message of messages) {
    const body = decodeMessageBody(message);
    out.set(body, offset);
    offset += body.length;
  }
  return out;
}

export function nextOffset(currentOffset: string, dataLength: number): string {
  const [readSeqRaw, byteOffsetRaw] = currentOffset.split("_");
  const readSeq = Number(readSeqRaw ?? 0);
  const byteOffset = Number(byteOffsetRaw ?? 0);
  const newByteOffset = byteOffset + FRAME_OVERHEAD + dataLength;
  return `${String(readSeq).padStart(16, "0")}_${String(newByteOffset).padStart(16, "0")}`;
}

export function appendMessage(
  ds: DurableStreamsStore,
  stream: DurableStreamEntity,
  data: Uint8Array,
  isInitialCreate = false,
): DurableStreamMessage | null {
  let processedData = data;
  if (isJsonContentType(stream.content_type)) {
    processedData = processJsonAppend(data, isInitialCreate);
    if (processedData.length === 0) return null;
  }

  const offset = nextOffset(stream.current_offset, processedData.length);
  const chunkIndex = readMessages(ds, stream.path).length;
  const message = ds.messages.insert({
    stream_path: stream.path,
    offset,
    chunk_index: chunkIndex,
    body_base64: encodeMessageBody(processedData),
    content_length: processedData.length,
    timestamp: Date.now(),
  });
  ds.streams.update(stream.id, {
    current_offset: offset,
    last_accessed_at: Date.now(),
  });
  stream.current_offset = offset;
  stream.last_accessed_at = Date.now();
  return message;
}

export function touchStream(ds: DurableStreamsStore, stream: DurableStreamEntity): void {
  const lastAccessedAt = Date.now();
  ds.streams.update(stream.id, { last_accessed_at: lastAccessedAt });
  stream.last_accessed_at = lastAccessedAt;
}

export function deleteStreamState(ds: DurableStreamsStore, stream: DurableStreamEntity): void {
  for (const message of ds.messages.findBy("stream_path", stream.path)) {
    ds.messages.delete(message.id);
  }
  for (const producer of ds.producers.findBy("stream_path", stream.path)) {
    ds.producers.delete(producer.id);
  }
  ds.streams.delete(stream.id);
}

export function validateProducer(
  ds: DurableStreamsStore,
  streamPath: string,
  producerId: string,
  producerEpoch: number,
  producerSeq: number,
): ProducerValidationResult {
  const existing = ds.producers
    .findBy("stream_path", streamPath)
    .find((producer) => producer.producer_id === producerId);

  if (!existing) {
    if (producerSeq !== 0) return { status: "invalid_epoch_seq" };
    return { status: "accepted", epoch: producerEpoch, lastSeq: producerSeq };
  }

  if (producerEpoch < existing.epoch) {
    return { status: "stale_epoch", currentEpoch: existing.epoch };
  }

  if (producerEpoch > existing.epoch) {
    if (producerSeq !== 0) return { status: "invalid_epoch_seq" };
    return { status: "accepted", producer: existing, epoch: producerEpoch, lastSeq: producerSeq };
  }

  if (producerSeq <= existing.last_seq) {
    return { status: "duplicate", lastSeq: existing.last_seq };
  }

  if (producerSeq > existing.last_seq + 1) {
    return { status: "sequence_gap", expectedSeq: existing.last_seq + 1, receivedSeq: producerSeq };
  }

  return { status: "accepted", producer: existing, epoch: producerEpoch, lastSeq: producerSeq };
}

export function commitProducer(
  ds: DurableStreamsStore,
  streamPath: string,
  producerId: string,
  accepted: ProducerValidationAccepted,
): void {
  if (accepted.producer) {
    ds.producers.update(accepted.producer.id, { epoch: accepted.epoch, last_seq: accepted.lastSeq });
    return;
  }

  ds.producers.insert({
    stream_path: streamPath,
    producer_id: producerId,
    epoch: accepted.epoch,
    last_seq: accepted.lastSeq,
  });
}

export function seedStream(
  ds: DurableStreamsStore,
  path: string,
  contentType: string,
  initialData?: string,
  closed = false,
): DurableStreamEntity {
  const existing = ds.streams.findOneBy("path", path);
  if (existing) return existing;

  const now = Date.now();
  const stream = ds.streams.insert({
    path,
    content_type: contentType,
    current_offset: ZERO_OFFSET,
    closed: false,
    last_accessed_at: now,
    soft_deleted: false,
    ref_count: 0,
  });

  if (initialData !== undefined && initialData.length > 0) {
    appendMessage(ds, stream, new TextEncoder().encode(initialData), true);
  }

  if (closed) {
    ds.streams.update(stream.id, { closed: true });
    stream.closed = true;
  }

  return stream;
}

export function encodeSseData(payload: string): string {
  return `${payload
    .split(/\r\n|\r|\n/)
    .map((line) => `data:${line}`)
    .join("\n")}\n\n`;
}

export function generateCursor(cursor: string | undefined): string {
  return cursor && cursor.length > 0 ? cursor : String(Math.floor(Date.now() / 1000));
}
