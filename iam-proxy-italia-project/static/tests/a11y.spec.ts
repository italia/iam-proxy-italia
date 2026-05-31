import AxeBuilder from "@axe-core/playwright";
import { test, expect } from "@playwright/test";

const PAGES_TO_SCAN = ["/disco.html", "/it-wallet.html"];

for (const pagePath of PAGES_TO_SCAN) {
  test(`axe scan ${pagePath}`, async ({ page }) => {
    await page.goto(pagePath, { waitUntil: "networkidle" });

    // Open dynamic controls to include runtime UI in the accessibility scan.
    if (pagePath === "/it-wallet.html") {
      const searchToggle = page.locator("#wallet-search-toggle");
      if ((await searchToggle.count()) && (await searchToggle.isVisible())) {
        await searchToggle.click();
      }
    }

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();

    expect(results.violations, () =>
      results.violations
        .map((violation) => `${violation.id}: ${violation.help}`)
        .join("\n")
    ).toEqual([]);
  });
}
