import { Store, type Collection } from "@emulators/core";
import type { DurableStreamEntity, DurableStreamMessage, DurableStreamProducer } from "./entities.js";

export interface DurableStreamsStore {
  streams: Collection<DurableStreamEntity>;
  messages: Collection<DurableStreamMessage>;
  producers: Collection<DurableStreamProducer>;
}

export function getDurableStreamsStore(store: Store): DurableStreamsStore {
  return {
    streams: store.collection<DurableStreamEntity>("durable_streams.streams", ["path"]),
    messages: store.collection<DurableStreamMessage>("durable_streams.messages", ["stream_path", "offset"]),
    producers: store.collection<DurableStreamProducer>("durable_streams.producers", ["stream_path", "producer_id"]),
  };
}
