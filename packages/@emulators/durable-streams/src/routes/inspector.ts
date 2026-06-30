import type { InspectorTab, RouteContext } from "@emulators/core";
import { escapeHtml, renderInspectorPage } from "@emulators/core";
import { getDurableStreamsStore } from "../store.js";
import { readMessages } from "../helpers.js";

const SERVICE_LABEL = "Durable Streams";

const TABS: InspectorTab[] = [{ id: "streams", label: "Streams", href: "/_inspector?tab=streams" }];

export function inspectorRoutes(ctx: RouteContext): void {
  const { app, store } = ctx;
  const ds = () => getDurableStreamsStore(store);

  app.get("/_inspector", (c) => {
    const streams = ds()
      .streams.all()
      .sort((a, b) => a.path.localeCompare(b.path));
    const rows = streams
      .map((stream) => {
        const messages = readMessages(ds(), stream.path);
        return `<tr>
          <td>${escapeHtml(stream.path)}</td>
          <td>${escapeHtml(stream.content_type)}</td>
          <td>${messages.length}</td>
          <td>${escapeHtml(stream.current_offset)}</td>
          <td>${stream.closed ? "Yes" : "No"}</td>
        </tr>`;
      })
      .join("\n");

    const contentHtml = `
      <div class="inspector-section">
        <h2>Streams (${streams.length})</h2>
        <table class="inspector-table">
          <thead><tr><th>Path</th><th>Content Type</th><th>Messages</th><th>Offset</th><th>Closed</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="5"><div class="inspector-empty">No streams</div></td></tr>`}</tbody>
        </table>
      </div>`;

    return c.html(renderInspectorPage("Inspector", TABS, "streams", contentHtml, SERVICE_LABEL));
  });
}
