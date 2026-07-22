import { describe, expect, it } from "vitest";
import { renderCardPage } from "../ui.js";

describe("renderCardPage", () => {
  it("uses readable text for the emulator footer", () => {
    const html = renderCardPage("Authorize", "Choose an account", "");

    expect(html).toMatch(/\.powered-by\{[^}]*color:#1a8c00/);
  });

  it("renders the card title as the page heading", () => {
    const html = renderCardPage("Authorize Linear App", "Choose an account", "");

    expect(html).toContain('<h1 class="card-title">Authorize Linear App</h1>');
  });
});
