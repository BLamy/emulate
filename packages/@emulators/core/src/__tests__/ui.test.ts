import { describe, expect, it } from "vitest";
import { renderCardPage } from "../ui.js";

describe("renderCardPage", () => {
  it("uses readable text for the emulator footer", () => {
    const html = renderCardPage("Authorize", "Choose an account", "");

    expect(html).toMatch(/\.powered-by\{[^}]*color:#1a8c00/);
  });
});
