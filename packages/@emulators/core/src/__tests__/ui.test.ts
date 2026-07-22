import { describe, expect, it } from "vitest";
import { renderCardPage, renderUserButton } from "../ui.js";

describe("renderCardPage", () => {
  it("uses readable text for the emulator footer", () => {
    const html = renderCardPage("Authorize", "Choose an account", "");

    expect(html).toMatch(/\.powered-by\{[^}]*color:#1a8c00/);
  });

  it("renders the card title as the page heading", () => {
    const html = renderCardPage("Authorize Linear App", "Choose an account", "");

    expect(html).toContain('<h1 class="card-title">Authorize Linear App</h1>');
  });

  it("uses readable text for account email addresses", () => {
    const button = renderUserButton({
      letter: "A",
      login: "admin",
      email: "admin@example.com",
      formAction: "/authorize",
      hiddenFields: {},
    });
    const html = renderCardPage("Authorize", "Choose an account", button);

    expect(html).toMatch(/\.user-email\{[^}]*color:#1a8c00/);
    expect(html).toContain('<div class="user-email">admin@example.com</div>');
  });

  it("wraps card content in the main landmark", () => {
    const html = renderCardPage("Authorize", "Choose an account", "");

    expect(html).toContain('<main class="content">');
    expect(html).toContain("</main>");
  });
});
