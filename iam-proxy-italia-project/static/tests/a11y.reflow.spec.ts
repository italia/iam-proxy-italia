import { expect, test } from "@playwright/test";

const PAGES = ["/disco.html", "/it-wallet.html"] as const;

type Scenario = {
  name: string;
  width: number;
  height: number;
};

// 400% zoom equivalence for desktop widths:
// 1280px -> 320px CSS viewport, 1024px -> 256px CSS viewport.
const SCENARIOS: Scenario[] = [
  { name: "1280@400%", width: 320, height: 720 },
  { name: "1024@400%", width: 256, height: 720 },
];

for (const pagePath of PAGES) {
  for (const scenario of SCENARIOS) {
    test(`reflow ${scenario.name} ${pagePath}`, async ({ page }) => {
      await page.setViewportSize({
        width: scenario.width,
        height: scenario.height,
      });

      await page.goto(pagePath, { waitUntil: "networkidle" });

      const horizontalOverflow = await page.evaluate(() => {
        const root = document.documentElement;
        const body = document.body;

        const rootOverflow = root.scrollWidth - root.clientWidth;
        const bodyOverflow = body ? body.scrollWidth - body.clientWidth : 0;

        return Math.max(rootOverflow, bodyOverflow);
      });

      expect(
        horizontalOverflow,
        `Unexpected horizontal overflow for ${pagePath} at ${scenario.name}`
      ).toBeLessThanOrEqual(1);

      // Basic "loss of functionality" guard:
      // at least one actionable control remains visible in the viewport flow.
      const controls = page.locator("a[href], button, input, select, textarea");
      await expect(controls.first()).toBeVisible();

      // Clipping guard on main landmarks.
      const main = page.locator("main").first();
      await expect(main).toBeVisible();
      const clipped = await main.evaluate((el) => {
        const rect = el.getBoundingClientRect();
        return rect.width <= 0 || rect.height <= 0;
      });
      expect(clipped, `Main landmark appears clipped on ${pagePath}`).toBeFalsy();
    });
  }
}
