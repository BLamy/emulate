import type { Context, RouteContext } from "@emulators/core";
import type { DurableStreamEntity } from "../entities.js";
import { getDurableStreamsStore } from "../store.js";
import {
  CURSOR_QUERY_PARAM,
  LIVE_QUERY_PARAM,
  OFFSET_QUERY_PARAM,
  PRODUCER_EPOCH_HEADER,
  PRODUCER_EXPECTED_SEQ_HEADER,
  PRODUCER_ID_HEADER,
  PRODUCER_RECEIVED_SEQ_HEADER,
  PRODUCER_SEQ_HEADER,
  STREAM_CLOSED_HEADER,
  STREAM_CURSOR_HEADER,
  STREAM_EXPIRES_AT_HEADER,
  STREAM_OFFSET_HEADER,
  STREAM_SEQ_HEADER,
  STREAM_SSE_DATA_ENCODING_HEADER,
  STREAM_TTL_HEADER,
  STREAM_UP_TO_DATE_HEADER,
  ZERO_OFFSET,
  appendMessage,
  bodyResponse,
  commitProducer,
  decodeMessageBody,
  deleteStreamState,
  encodeSseData,
  formatMessages,
  generateCursor,
  isJsonContentType,
  isSseTextCompatible,
  mediaType,
  messagesAfterOffset,
  normalizeStreamPath,
  parseIntegerHeader,
  protocolHeaders,
  readMessages,
  textResponse,
  touchStream,
  validateOffset,
  validateProducer,
  type ProducerValidationResult,
} from "../helpers.js";

const STREAM_FORKED_FROM_HEADER = "Stream-Forked-From";
const STREAM_FORK_OFFSET_HEADER = "Stream-Fork-Offset";
const STREAM_FORK_SUB_OFFSET_HEADER = "Stream-Fork-Sub-Offset";

const STREAM_METHODS = ["PUT", "HEAD", "GET", "POST", "DELETE"] as const;

export function streamRoutes(ctx: RouteContext): void {
  const { app, store } = ctx;
  const ds = () => getDurableStreamsStore(store);

  for (const method of STREAM_METHODS) {
    app.on(method, "/:path{.*}", async (c) => {
      const path = normalizeStreamPath(new URL(c.req.url).pathname);
      switch (method) {
        case "PUT":
          return createStream(c, path);
        case "HEAD":
          return headStream(c, path);
        case "GET":
          return readStream(c, path);
        case "POST":
          return appendStream(c, path);
        case "DELETE":
          return deleteStream(c, path);
      }
    });
  }

  function activeStream(path: string): DurableStreamEntity | undefined {
    const stream = ds().streams.findOneBy("path", path);
    if (!stream) return undefined;

    const now = Date.now();
    const expiresAt = stream.expires_at ? new Date(stream.expires_at).getTime() : null;
    const ttlExpiresAt = stream.ttl_seconds !== undefined ? stream.last_accessed_at + stream.ttl_seconds * 1000 : null;
    const expired =
      (expiresAt !== null && (!Number.isFinite(expiresAt) || now >= expiresAt)) ||
      (ttlExpiresAt !== null && now >= ttlExpiresAt);

    if (!expired) return stream;

    if (stream.ref_count > 0) {
      ds().streams.update(stream.id, { soft_deleted: true });
      stream.soft_deleted = true;
      return stream;
    }

    deleteStreamState(ds(), stream);
    return undefined;
  }

  async function createStream(c: Context, path: string): Promise<Response> {
    if (path === "/") {
      return textResponse(c, 400, "Stream path is required");
    }

    const forkedFrom = c.req.header(STREAM_FORKED_FROM_HEADER);
    const forkOffset = c.req.header(STREAM_FORK_OFFSET_HEADER);
    const forkSubOffsetRaw = c.req.header(STREAM_FORK_SUB_OFFSET_HEADER);
    const existing = activeStream(path);

    const ttlRaw = c.req.header(STREAM_TTL_HEADER);
    const expiresAt = c.req.header(STREAM_EXPIRES_AT_HEADER);
    const closed = c.req.header(STREAM_CLOSED_HEADER) === "true";

    if (ttlRaw && expiresAt) {
      return textResponse(c, 400, "Cannot specify both Stream-TTL and Stream-Expires-At");
    }

    let ttlSeconds: number | undefined;
    if (ttlRaw !== undefined) {
      const parsed = parseIntegerHeader(ttlRaw);
      if (parsed === null) return textResponse(c, 400, "Invalid Stream-TTL value");
      ttlSeconds = parsed;
    }

    if (expiresAt !== undefined && isNaN(new Date(expiresAt).getTime())) {
      return textResponse(c, 400, "Invalid Stream-Expires-At timestamp");
    }

    if (forkOffset !== undefined && !/^\d+_\d+$/.test(forkOffset)) {
      return textResponse(c, 400, "Invalid Stream-Fork-Offset format");
    }

    let forkSubOffset: number | undefined;
    if (forkSubOffsetRaw !== undefined) {
      if (!forkedFrom) return textResponse(c, 400, "Stream-Fork-Sub-Offset requires Stream-Forked-From");
      const parsed = parseIntegerHeader(forkSubOffsetRaw);
      if (parsed === null) return textResponse(c, 400, "Invalid Stream-Fork-Sub-Offset format");
      forkSubOffset = parsed;
    }

    let contentType = c.req.header("Content-Type");
    if (!contentType || !/^[\w-]+\/[\w.+-]+/.test(contentType)) {
      contentType = forkedFrom ? undefined : "application/octet-stream";
    }

    if (existing) {
      if (existing.soft_deleted) {
        return textResponse(c, 409, "Stream has active forks");
      }

      const typeMatches =
        mediaType(contentType) === mediaType(existing.content_type) ||
        (contentType === undefined && forkedFrom !== undefined && mediaType(existing.content_type).length > 0);
      const ttlMatches = ttlSeconds === existing.ttl_seconds;
      const expiresMatches = expiresAt === existing.expires_at;
      const closedMatches = closed === existing.closed;
      const forkMatches = (forkedFrom ?? undefined) === existing.forked_from;
      const forkOffsetMatches = forkOffset === undefined || forkOffset === existing.fork_offset;
      const forkSubOffsetMatches = (forkSubOffset ?? 0) === (existing.fork_sub_offset ?? 0);

      if (
        typeMatches &&
        ttlMatches &&
        expiresMatches &&
        closedMatches &&
        forkMatches &&
        forkOffsetMatches &&
        forkSubOffsetMatches
      ) {
        return bodyResponse(c, 200, null, streamMetadataHeaders(existing));
      }

      return textResponse(c, 409, "Stream already exists with different configuration");
    }

    let inheritedMessages: ReturnType<typeof readMessages> = [];
    let resolvedContentType = contentType ?? "application/octet-stream";
    let resolvedForkOffset = forkOffset;

    if (forkedFrom) {
      const source = activeStream(forkedFrom);
      if (!source) return textResponse(c, 404, "Source stream not found");
      if (source.soft_deleted) return textResponse(c, 409, "Source stream is gone");

      resolvedContentType = contentType ?? source.content_type;
      if (contentType && mediaType(contentType) !== mediaType(source.content_type)) {
        return textResponse(c, 409, "Content type mismatch with source stream");
      }

      resolvedForkOffset = forkOffset ?? source.current_offset;
      if (source.current_offset < resolvedForkOffset) {
        return textResponse(c, 400, "Fork offset beyond source stream length");
      }
      if (forkSubOffset && forkSubOffset > 0) {
        return textResponse(c, 400, "Stream-Fork-Sub-Offset is not supported by this emulator");
      }

      inheritedMessages = readMessages(ds(), source.path).filter((message) => message.offset <= resolvedForkOffset!);
      ds().streams.update(source.id, { ref_count: source.ref_count + 1 });
    }

    const stream = ds().streams.insert({
      path,
      content_type: resolvedContentType,
      current_offset: inheritedMessages[inheritedMessages.length - 1]?.offset ?? resolvedForkOffset ?? ZERO_OFFSET,
      closed: false,
      ttl_seconds: ttlSeconds,
      expires_at: expiresAt,
      last_accessed_at: Date.now(),
      forked_from: forkedFrom,
      fork_offset: resolvedForkOffset,
      fork_sub_offset: forkSubOffset,
      soft_deleted: false,
      ref_count: 0,
    });

    for (const inherited of inheritedMessages) {
      ds().messages.insert({
        stream_path: stream.path,
        offset: inherited.offset,
        chunk_index: inherited.chunk_index,
        body_base64: inherited.body_base64,
        content_length: inherited.content_length,
        timestamp: inherited.timestamp,
      });
    }

    const body = new Uint8Array(await c.req.arrayBuffer());
    try {
      if (body.length > 0) appendMessage(ds(), stream, body, true);
    } catch (err) {
      deleteStreamState(ds(), stream);
      return textResponse(c, 400, err instanceof Error ? err.message : "Invalid stream body");
    }

    if (closed) {
      ds().streams.update(stream.id, { closed: true });
      stream.closed = true;
    }

    return bodyResponse(c, 201, null, streamMetadataHeaders(stream));
  }

  function headStream(c: Context, path: string): Response {
    const stream = activeStream(path);
    if (!stream) return textResponse(c, 404, "Stream not found");
    if (stream.soft_deleted) return textResponse(c, 410, "Stream is gone");

    return bodyResponse(c, 200, null, streamMetadataHeaders(stream));
  }

  async function readStream(c: Context, path: string): Promise<Response> {
    const stream = activeStream(path);
    if (!stream) return textResponse(c, 404, "Stream not found");
    if (stream.soft_deleted) return textResponse(c, 410, "Stream is gone");

    const url = new URL(c.req.url);
    const offsetValues = url.searchParams.getAll(OFFSET_QUERY_PARAM);
    if (offsetValues.length > 1) return textResponse(c, 400, "Multiple offset parameters not allowed");

    const offset = offsetValues[0];
    if (offset !== undefined && (offset === "" || !validateOffset(offset))) {
      return textResponse(c, 400, "Invalid offset format");
    }

    const live = url.searchParams.get(LIVE_QUERY_PARAM);
    if ((live === "long-poll" || live === "sse") && !offset) {
      return textResponse(c, 400, `${live === "sse" ? "SSE" : "Long-poll"} requires offset parameter`);
    }

    const effectiveOffset = offset === "now" ? stream.current_offset : offset;
    const allMessages = readMessages(ds(), stream.path);
    const messages = messagesAfterOffset(allMessages, effectiveOffset);
    const responseOffset = messages[messages.length - 1]?.offset ?? stream.current_offset;
    const upToDate = true;

    touchStream(ds(), stream);

    if (live === "sse") {
      return sseResponse(c, stream, messages, responseOffset, url.searchParams.get(CURSOR_QUERY_PARAM) ?? undefined);
    }

    if (live === "long-poll" && messages.length === 0 && effectiveOffset === stream.current_offset) {
      const headers: Record<string, string> = {
        [STREAM_OFFSET_HEADER]: stream.current_offset,
        [STREAM_UP_TO_DATE_HEADER]: "true",
        [STREAM_CURSOR_HEADER]: generateCursor(url.searchParams.get(CURSOR_QUERY_PARAM) ?? undefined),
      };
      if (stream.closed) headers[STREAM_CLOSED_HEADER] = "true";
      return bodyResponse(c, 204, null, headers);
    }

    const headers = streamReadHeaders(stream, responseOffset, upToDate, offset ?? "-1");
    if (offset === "now") {
      const emptyBody = isJsonContentType(stream.content_type) ? new TextEncoder().encode("[]") : new Uint8Array(0);
      return bodyResponse(c, 200, emptyBody, headers);
    }

    const ifNoneMatch = c.req.header("If-None-Match");
    if (ifNoneMatch && ifNoneMatch === headers.ETag) {
      return bodyResponse(c, 304, null, { ETag: headers.ETag });
    }

    return bodyResponse(c, 200, formatMessages(stream.content_type, messages), headers);
  }

  async function appendStream(c: Context, path: string): Promise<Response> {
    const stream = activeStream(path);
    if (!stream) return textResponse(c, 404, "Stream not found");
    if (stream.soft_deleted) return textResponse(c, 410, "Stream is gone");

    const closeStream = c.req.header(STREAM_CLOSED_HEADER) === "true";
    const contentType = c.req.header("Content-Type");
    const streamSeq = c.req.header(STREAM_SEQ_HEADER);
    const producerValidation = validateProducerHeaders(c);
    if (producerValidation instanceof Response) return producerValidation;

    const body = new Uint8Array(await c.req.arrayBuffer());

    if (body.length === 0 && closeStream) {
      return closeOnly(c, stream, producerValidation);
    }

    if (body.length === 0) {
      return textResponse(c, 400, "Empty body");
    }

    if (!contentType) {
      return textResponse(c, 400, "Content-Type header is required");
    }

    if (mediaType(contentType) !== mediaType(stream.content_type)) {
      return textResponse(c, 409, "Content-type mismatch");
    }

    if (stream.closed) {
      return textResponse(c, 409, "Stream is closed", {
        [STREAM_OFFSET_HEADER]: stream.current_offset,
        [STREAM_CLOSED_HEADER]: "true",
      });
    }

    if (producerValidation) {
      const handled = producerFailureResponse(c, producerValidation, stream);
      if (handled) return handled;
    }

    if (streamSeq !== undefined && stream.last_seq !== undefined && streamSeq <= stream.last_seq) {
      return textResponse(c, 409, "Sequence conflict");
    }

    let message;
    try {
      message = appendMessage(ds(), stream, body);
    } catch (err) {
      return textResponse(c, 400, err instanceof Error ? err.message : "Invalid stream body");
    }

    const updates: Partial<DurableStreamEntity> = {};
    if (streamSeq !== undefined) updates.last_seq = streamSeq;
    if (closeStream) {
      updates.closed = true;
      stream.closed = true;
      if (producerValidation) {
        updates.closed_by_producer_id = producerValidation.producerId;
        updates.closed_by_epoch = producerValidation.producerEpoch;
        updates.closed_by_seq = producerValidation.producerSeq;
      }
    }
    if (Object.keys(updates).length > 0) {
      ds().streams.update(stream.id, updates);
    }

    if (producerValidation && producerValidation.result.status === "accepted") {
      commitProducer(ds(), stream.path, producerValidation.producerId, producerValidation.result);
    }

    const headers: Record<string, string> = {
      [STREAM_OFFSET_HEADER]: message?.offset ?? stream.current_offset,
    };
    if (closeStream) headers[STREAM_CLOSED_HEADER] = "true";
    if (producerValidation) {
      headers[PRODUCER_EPOCH_HEADER] = String(producerValidation.producerEpoch);
      headers[PRODUCER_SEQ_HEADER] = String(producerValidation.producerSeq);
    }

    return bodyResponse(c, producerValidation ? 200 : 204, null, headers);
  }

  function closeOnly(
    c: Context,
    stream: DurableStreamEntity,
    producerValidation: ParsedProducerHeaders | null,
  ): Response {
    if (producerValidation) {
      if (
        stream.closed &&
        stream.closed_by_producer_id === producerValidation.producerId &&
        stream.closed_by_epoch === producerValidation.producerEpoch &&
        stream.closed_by_seq === producerValidation.producerSeq
      ) {
        return bodyResponse(c, 204, null, {
          [STREAM_OFFSET_HEADER]: stream.current_offset,
          [STREAM_CLOSED_HEADER]: "true",
          [PRODUCER_EPOCH_HEADER]: String(producerValidation.producerEpoch),
          [PRODUCER_SEQ_HEADER]: String(producerValidation.producerSeq),
        });
      }

      if (stream.closed) {
        return textResponse(c, 409, "Stream is closed", {
          [STREAM_OFFSET_HEADER]: stream.current_offset,
          [STREAM_CLOSED_HEADER]: "true",
        });
      }

      const handled = producerFailureResponse(c, producerValidation, stream);
      if (handled) return handled;

      if (producerValidation.result.status === "accepted") {
        commitProducer(ds(), stream.path, producerValidation.producerId, producerValidation.result);
      }
    } else if (stream.closed) {
      return bodyResponse(c, 204, null, {
        [STREAM_OFFSET_HEADER]: stream.current_offset,
        [STREAM_CLOSED_HEADER]: "true",
      });
    }

    const updates: Partial<DurableStreamEntity> = { closed: true };
    if (producerValidation) {
      updates.closed_by_producer_id = producerValidation.producerId;
      updates.closed_by_epoch = producerValidation.producerEpoch;
      updates.closed_by_seq = producerValidation.producerSeq;
    }
    ds().streams.update(stream.id, updates);
    stream.closed = true;

    const headers: Record<string, string> = {
      [STREAM_OFFSET_HEADER]: stream.current_offset,
      [STREAM_CLOSED_HEADER]: "true",
    };
    if (producerValidation) {
      headers[PRODUCER_EPOCH_HEADER] = String(producerValidation.producerEpoch);
      headers[PRODUCER_SEQ_HEADER] = String(producerValidation.producerSeq);
    }

    return bodyResponse(c, 204, null, headers);
  }

  function deleteStream(c: Context, path: string): Response {
    const stream = activeStream(path);
    if (!stream) return textResponse(c, 404, "Stream not found");
    if (stream.soft_deleted) return textResponse(c, 410, "Stream is gone");

    if (stream.forked_from) {
      const source = ds().streams.findOneBy("path", stream.forked_from);
      if (source) {
        ds().streams.update(source.id, { ref_count: Math.max(0, source.ref_count - 1) });
      }
    }

    deleteStreamState(ds(), stream);
    return bodyResponse(c, 204, null);
  }

  function streamMetadataHeaders(stream: DurableStreamEntity): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": stream.content_type,
      [STREAM_OFFSET_HEADER]: stream.current_offset,
      "Cache-Control": "no-store",
    };
    if (stream.closed) headers[STREAM_CLOSED_HEADER] = "true";
    if (stream.ttl_seconds !== undefined) headers[STREAM_TTL_HEADER] = String(stream.ttl_seconds);
    if (stream.expires_at) headers[STREAM_EXPIRES_AT_HEADER] = stream.expires_at;
    return headers;
  }

  function streamReadHeaders(
    stream: DurableStreamEntity,
    responseOffset: string,
    upToDate: boolean,
    startOffset: string,
  ): Record<string, string> {
    const clientAtTail = responseOffset === stream.current_offset;
    const closedSuffix = stream.closed && clientAtTail && upToDate ? ":c" : "";
    const etag = `"${Buffer.from(stream.path).toString("base64")}:${startOffset}:${responseOffset}${closedSuffix}"`;
    const headers: Record<string, string> = {
      "Content-Type": stream.content_type,
      [STREAM_OFFSET_HEADER]: responseOffset,
      ETag: etag,
      "Cache-Control": "no-store",
    };
    if (upToDate) headers[STREAM_UP_TO_DATE_HEADER] = "true";
    if (stream.closed && clientAtTail && upToDate) headers[STREAM_CLOSED_HEADER] = "true";
    return headers;
  }

  function sseResponse(
    c: Context,
    stream: DurableStreamEntity,
    messages: ReturnType<typeof readMessages>,
    responseOffset: string,
    cursor: string | undefined,
  ): Response {
    const useBase64 = !isSseTextCompatible(stream.content_type);
    const lines: string[] = [];

    for (const message of messages) {
      let dataPayload: string;
      if (useBase64) {
        dataPayload = Buffer.from(decodeMessageBody(message)).toString("base64");
      } else if (isJsonContentType(stream.content_type)) {
        dataPayload = new TextDecoder().decode(formatMessages(stream.content_type, [message]));
      } else {
        dataPayload = new TextDecoder().decode(decodeMessageBody(message));
      }
      lines.push(`event: data\n${encodeSseData(dataPayload)}`);
    }

    const controlData: Record<string, string | boolean> = {
      streamNextOffset: responseOffset,
    };
    if (stream.closed && responseOffset === stream.current_offset) {
      controlData.streamClosed = true;
    } else {
      controlData.streamCursor = generateCursor(cursor);
      controlData.upToDate = true;
    }
    lines.push(`event: control\n${encodeSseData(JSON.stringify(controlData))}`);

    const headers: Record<string, string> = {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
    };
    if (useBase64) headers[STREAM_SSE_DATA_ENCODING_HEADER] = "base64";

    return bodyResponse(c, 200, lines.join(""), headers);
  }

  function validateProducerHeaders(c: Context): ParsedProducerHeaders | Response | null {
    const producerId = c.req.header(PRODUCER_ID_HEADER);
    const producerEpochRaw = c.req.header(PRODUCER_EPOCH_HEADER);
    const producerSeqRaw = c.req.header(PRODUCER_SEQ_HEADER);
    const hasAny = producerId !== undefined || producerEpochRaw !== undefined || producerSeqRaw !== undefined;
    const hasAll = producerId !== undefined && producerEpochRaw !== undefined && producerSeqRaw !== undefined;

    if (!hasAny) return null;
    if (!hasAll) {
      return textResponse(c, 400, "All producer headers must be provided together");
    }
    if (producerId === "") return textResponse(c, 400, "Invalid Producer-Id");

    const producerEpoch = parseIntegerHeader(producerEpochRaw);
    if (producerEpoch === null) return textResponse(c, 400, "Invalid Producer-Epoch");

    const producerSeq = parseIntegerHeader(producerSeqRaw);
    if (producerSeq === null) return textResponse(c, 400, "Invalid Producer-Seq");

    return {
      producerId,
      producerEpoch,
      producerSeq,
      result: validateProducer(
        ds(),
        normalizeStreamPath(new URL(c.req.url).pathname),
        producerId,
        producerEpoch,
        producerSeq,
      ),
    };
  }

  function producerFailureResponse(
    c: Context,
    parsed: ParsedProducerHeaders,
    stream: DurableStreamEntity,
  ): Response | null {
    const { result } = parsed;
    switch (result.status) {
      case "accepted":
        return null;
      case "duplicate":
        return bodyResponse(c, 204, null, {
          [PRODUCER_EPOCH_HEADER]: String(parsed.producerEpoch),
          [PRODUCER_SEQ_HEADER]: String(result.lastSeq),
          ...(stream.closed ? { [STREAM_CLOSED_HEADER]: "true" } : {}),
        });
      case "stale_epoch":
        return textResponse(c, 403, "Stale producer epoch", {
          [PRODUCER_EPOCH_HEADER]: String(result.currentEpoch),
        });
      case "invalid_epoch_seq":
        return textResponse(c, 400, "New epoch must start with sequence 0");
      case "sequence_gap":
        return textResponse(c, 409, "Producer sequence gap", {
          [PRODUCER_EXPECTED_SEQ_HEADER]: String(result.expectedSeq),
          [PRODUCER_RECEIVED_SEQ_HEADER]: String(result.receivedSeq),
        });
    }
  }
}

interface ParsedProducerHeaders {
  producerId: string;
  producerEpoch: number;
  producerSeq: number;
  result: ProducerValidationResult;
}
