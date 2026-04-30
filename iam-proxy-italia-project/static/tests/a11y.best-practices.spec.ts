import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

type ViolationSummary = {
  id: string;
  impact: string | null | undefined;
  help: string;
  targets: string[];
};

function summarizeViolations(results: { violations: Array<{ id: string; impact?: string | null; help: string; nodes: Array<{ target: string[] }> }> }): ViolationSummary[] {
  return results.violations.map((violation) => ({
    id: violation.id,
    impact: violation.impact,
    help: violation.help,
    targets: violation.nodes.flatMap((node) => node.target).slice(0, 5),
  }));
}

test("best-practice checks on disco dynamic sections", async ({ page }) => {
  await page.goto("/disco.html", { waitUntil: "networkidle" });

  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");

  const learnMoreToggle = page.locator(".eid-learn-more-toggle").first();
  if (await learnMoreToggle.count()) {
    await learnMoreToggle.focus();
    await page.keyboard.press("Enter");
  }

  const results = await new AxeBuilder({ page })
    .withTags(["best-practice"])
    .analyze();

  const summary = summarizeViolations(results);
  expect(summary, JSON.stringify(summary, null, 2)).toEqual([]);
});

test("spid menu stays closed during Tab-only navigation", async ({ page }) => {
  await page.goto("/disco.html", { waitUntil: "networkidle" });

  const spidTrigger = page.locator("[spid-idp-button]").first();
  await expect(spidTrigger).toBeVisible();
  const spidMenu = page.locator("#spid-idp-button-xlarge-post");

  // Use real keyboard navigation to reach the trigger.
  for (let i = 0; i < 30; i += 1) {
    await page.keyboard.press("Tab");
    const isFocused = await spidTrigger.evaluate((el) => document.activeElement === el);
    if (isFocused) break;
  }

  await expect(spidTrigger).toBeFocused();
  await expect(spidTrigger).not.toHaveClass(/spid-idp-button-open/);
  await expect(spidMenu).toBeHidden();
});

test("spid menu opens only with Enter or Space", async ({ page }) => {
  await page.goto("/disco.html", { waitUntil: "networkidle" });

  const spidTrigger = page.locator("[spid-idp-button]").first();
  await expect(spidTrigger).toBeVisible();
  const spidMenu = page.locator("#spid-idp-button-xlarge-post");
  await expect(spidMenu).toBeHidden();

  // Navigate with real Tab keystrokes until SPID trigger gets focus.
  for (let i = 0; i < 30; i += 1) {
    await page.keyboard.press("Tab");
    const isFocused = await spidTrigger.evaluate((el) => document.activeElement === el);
    if (isFocused) break;
  }
  await expect(spidTrigger).toBeFocused();
  await expect(spidTrigger).not.toHaveClass(/spid-idp-button-open/);
  await expect(spidMenu).toBeHidden();

  // Explicit activation via Enter opens the menu.
  await page.keyboard.press("Enter");
  await expect(spidTrigger).toHaveClass(/spid-idp-button-open/);
  await expect(spidMenu).toBeVisible();
  await page.mouse.click(5, 5);
  await expect(spidTrigger).not.toHaveClass(/spid-idp-button-open/);
  await expect(spidMenu).toBeHidden();

  // Explicit activation via Space opens the menu as well.
  await spidTrigger.focus();
  await page.keyboard.press("Space");
  await expect(spidTrigger).toHaveClass(/spid-idp-button-open/);
  await expect(spidMenu).toBeVisible();

  // Escape closes the open SPID menu.
  await page.keyboard.press("Escape");
  await expect(spidTrigger).not.toHaveClass(/spid-idp-button-open/);
  await expect(spidMenu).toBeHidden();
});

test("cie menu opens with Enter/Space and closes with Escape", async ({ page }) => {
  await page.goto("/disco.html", { waitUntil: "networkidle" });

  const cieTrigger = page.locator(".eid-card-btn-cie").first();
  await expect(cieTrigger).toBeVisible();
  const cieMenu = page.locator(".cie-dropdown-menu").first();

  await cieTrigger.focus();
  await expect(cieMenu).not.toHaveClass(/is-open/);

  await page.keyboard.press("Enter");
  await expect(cieMenu).toHaveClass(/is-open/);

  await page.keyboard.press("Escape");
  await expect(cieMenu).not.toHaveClass(/is-open/);

  await cieTrigger.focus();
  await page.keyboard.press("Space");
  await expect(cieMenu).toHaveClass(/is-open/);

  await page.keyboard.press("Escape");
  await expect(cieMenu).not.toHaveClass(/is-open/);
});

test("best-practice checks on it-wallet interactive controls", async ({ page }) => {
  await page.goto("/it-wallet.html", { waitUntil: "networkidle" });

  const searchToggle = page.locator("#wallet-search-toggle");
  if ((await searchToggle.count()) && (await searchToggle.isVisible())) {
    await searchToggle.focus();
    await page.keyboard.press("Enter");
  }

  const sortTrigger = page.locator("#wallet-sort-trigger");
  if ((await sortTrigger.count()) && (await sortTrigger.isVisible())) {
    await sortTrigger.focus();
    await page.keyboard.press("Enter");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Escape");
  }

  const searchInput = page.locator("#wallet-search");
  if ((await searchInput.count()) && (await searchInput.isVisible())) {
    await searchInput.fill("it");
    await page.keyboard.press("Tab");
    await page.keyboard.press("Enter");
  }

  const results = await new AxeBuilder({ page })
    .withTags(["best-practice"])
    .analyze();

  const summary = summarizeViolations(results);
  expect(summary, JSON.stringify(summary, null, 2)).toEqual([]);
});
