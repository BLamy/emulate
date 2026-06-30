import type { Entity } from "@emulators/core";

export interface DurableStreamEntity extends Entity {
  path: string;
  content_type: string;
  current_offset: string;
  closed: boolean;
  last_seq?: string;
  ttl_seconds?: number;
  expires_at?: string;
  last_accessed_at: number;
  forked_from?: string;
  fork_offset?: string;
  fork_sub_offset?: number;
  soft_deleted: boolean;
  ref_count: number;
  closed_by_producer_id?: string;
  closed_by_epoch?: number;
  closed_by_seq?: number;
}

export interface DurableStreamMessage extends Entity {
  stream_path: string;
  offset: string;
  chunk_index: number;
  body_base64: string;
  content_length: number;
  timestamp: number;
}

export interface DurableStreamProducer extends Entity {
  stream_path: string;
  producer_id: string;
  epoch: number;
  last_seq: number;
}
