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

test("@best-practice best-practice checks on disco dynamic sections", async ({ page }) => {
  await page.goto("/disco.html", { waitUntil: "networkidle" });

  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");

  const findHowLink = page.locator(".eid-find-how-link").first();
  if (await findHowLink.count()) {
    await expect(findHowLink).toHaveAttribute("target", "_blank");
    await expect(findHowLink).toHaveAttribute("aria-label", /si apre in una nuova finestra|opens in a new window/i);
  }

  await expect(page.locator("#eid-cards-container")).not.toHaveAttribute("aria-live", /.+/);
  await expect(page.locator("#eid-selection-title")).toHaveCount(1);
  await expect(page.locator("main #eid-selection-title")).toHaveCount(1);

  const learnMoreToggle = page.locator(".eid-learn-more-toggle").first();
  if (await learnMoreToggle.count()) {
    await expect(learnMoreToggle).toHaveAttribute("aria-controls", /.+/);
    await expect(learnMoreToggle).toHaveAttribute("aria-expanded", "false");
    const labelledBy = await learnMoreToggle.getAttribute("aria-labelledby");
    expect(labelledBy).toBeTruthy();
    const labelledByIds = labelledBy!.split(/\s+/);
    expect(labelledByIds.length).toBeGreaterThanOrEqual(2);
    const cardTitle = page.locator(`#${labelledByIds[1]}`);
    await expect(cardTitle).toHaveClass(/it-card-title/);
    await expect(learnMoreToggle).not.toHaveAttribute("aria-label");
    const controlsId = await learnMoreToggle.getAttribute("aria-controls");
    const panel = page.locator(`#${controlsId}`);
    await expect(panel).toHaveAttribute("role", "region");
    await expect(panel).toHaveAttribute("hidden", "");
    const panelLabelledBy = await panel.getAttribute("aria-labelledby");
    expect(panelLabelledBy).toContain(labelledByIds[1]);
    await learnMoreToggle.focus();
    await page.keyboard.press("Enter");
    await expect(learnMoreToggle).toHaveAttribute("aria-expanded", "true");
    await expect(panel).not.toHaveAttribute("hidden", "");
  }

  const results = await new AxeBuilder({ page })
    .withTags(["best-practice"])
    .analyze();

  const summary = summarizeViolations(results);
  expect(summary, JSON.stringify(summary, null, 2)).toEqual([]);
});

test("@keyboard spid menu stays closed during Tab-only navigation", async ({ page }) => {
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

test("@keyboard spid menu opens only with Enter or Space", async ({ page }) => {
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

test("@keyboard spid menu closes with Escape when focus is inside IdP entries", async ({ page }) => {
  await page.goto("/disco.html", { waitUntil: "networkidle" });

  const spidTrigger = page.locator("[spid-idp-button]").first();
  const spidMenu = page.locator("#spid-idp-button-xlarge-post");
  const firstIdpLink = spidMenu.locator("a[href]").first();

  for (let i = 0; i < 30; i += 1) {
    await page.keyboard.press("Tab");
    const isFocused = await spidTrigger.evaluate((el) => document.activeElement === el);
    if (isFocused) break;
  }
  await expect(spidTrigger).toBeFocused();

  await page.keyboard.press("Enter");
  await expect(spidTrigger).toHaveClass(/spid-idp-button-open/);
  await expect(spidMenu).toBeVisible();

  await page.keyboard.press("Tab");
  await expect(firstIdpLink).toBeFocused();

  await page.keyboard.press("Escape");
  await expect(spidTrigger).not.toHaveClass(/spid-idp-button-open/);
  await expect(spidMenu).toBeHidden();
});

test("@keyboard cie menu opens with Enter/Space and closes with Escape", async ({ page }) => {
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

test("@focus it-wallet initial load does not move focus to heading or search", async ({ page }) => {
  await page.goto("/it-wallet.html", { waitUntil: "networkidle" });
  await page.waitForFunction(() => document.getElementById("wallet-grid")?.children.length > 0);
  await expect(page.locator("#page-title")).not.toBeFocused();
  await expect(page.locator("#wallet-search")).not.toBeFocused();

  const firstCard = page.locator(".it-wallet-card").first();
  const labelledBy = await firstCard.getAttribute("aria-labelledby");
  expect(labelledBy).toBeTruthy();
  await expect(page.locator(`#${labelledBy}`)).toHaveClass(/it-wallet-card-title/);
});

test("@status it-wallet search announces result count", async ({ page }) => {
  await page.goto("/it-wallet.html", { waitUntil: "networkidle" });
  await page.waitForFunction(() => document.getElementById("wallet-grid")?.children.length > 0);

  await expect(page.locator("#wallet-search-form")).toHaveAttribute("role", "search");
  await expect(page.locator("#wallet-controls")).toHaveAttribute("aria-label", /Strumenti elenco wallet/i);
  await expect(page.locator("#wallet-search-form")).toHaveAttribute("aria-labelledby", "wallet-search-legend");
  await expect(page.locator("#wallet-search-legend")).toHaveCount(1);
  await expect(page.locator("label[for='wallet-search']")).toHaveCount(1);
  await expect(page.locator("#wallet-search")).not.toHaveAttribute("aria-label", /.+/);
  await expect(page.locator("#search-btn")).toHaveAttribute("type", "submit");
  await expect(page.locator("#wallet-search-form #search-btn")).toHaveCount(1);
  await expect(page.locator("#search-btn")).toBeEnabled();

  const searchInput = page.locator("#wallet-search");
  if (!(await searchInput.count()) || !(await searchInput.isVisible())) {
    test.skip(true, "Search controls not visible on this viewport");
  }

  await searchInput.fill("io");
  await page.locator("#search-btn").click();
  await expect(page.locator("#wallet-results-status")).not.toHaveText("");
  await expect(page.locator("#wallet-results-status")).toHaveText(/\d|nessun|no results/i);
});

test("@keyboard it-wallet empty search shows inline error", async ({ page }) => {
  await page.goto("/it-wallet.html", { waitUntil: "networkidle" });
  await page.waitForFunction(() => document.getElementById("wallet-grid")?.children.length > 0);

  const searchInput = page.locator("#wallet-search");
  const searchBtn = page.locator("#search-btn");
  if (!(await searchInput.count()) || !(await searchInput.isVisible())) {
    test.skip(true, "Search controls not visible on this viewport");
  }

  await expect(searchBtn).toBeEnabled();
  await searchBtn.click();
  await expect(page.locator("#wallet-search-error")).toBeVisible();
  await expect(page.locator("#wallet-search")).toHaveAttribute("aria-invalid", "true");
  await expect(page.locator("#wallet-search")).toHaveAttribute("aria-describedby", "wallet-search-error");
});

test("@focus it-wallet sort restores focus on trigger", async ({ page }) => {
  await page.goto("/it-wallet.html", { waitUntil: "networkidle" });
  await page.waitForFunction(() => document.getElementById("wallet-grid")?.children.length > 0);

  const sortTrigger = page.locator("#wallet-sort-trigger");
  if (!(await sortTrigger.count()) || !(await sortTrigger.isVisible())) {
    test.skip(true, "Sort controls not visible on this viewport");
  }

  await sortTrigger.click();
  await page.locator("#wallet-sort-item-az").click();
  await expect(sortTrigger).toBeFocused();
});

test("@keyboard it-wallet sort menu Escape restores focus from menu item", async ({ page }) => {
  await page.goto("/it-wallet.html", { waitUntil: "networkidle" });
  await page.waitForFunction(() => document.getElementById("wallet-grid")?.children.length > 0);

  const sortTrigger = page.locator("#wallet-sort-trigger");
  const sortMenu = page.locator("#wallet-sort-menu");
  const firstSortItem = page.locator("#wallet-sort-item-default");
  if (!(await sortTrigger.count()) || !(await sortTrigger.isVisible())) {
    test.skip(true, "Sort controls not visible on this viewport");
  }

  await sortTrigger.focus();
  await page.keyboard.press("Enter");
  await expect(sortMenu).toBeVisible();
  await firstSortItem.focus();
  await expect(firstSortItem).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(sortMenu).toBeHidden();
  await expect(sortTrigger).toBeFocused();
});

test("@keyboard it-wallet sort menu arrow key navigation", async ({ page }) => {
  await page.goto("/it-wallet.html", { waitUntil: "networkidle" });
  await page.waitForFunction(() => document.getElementById("wallet-grid")?.children.length > 0);

  const sortTrigger = page.locator("#wallet-sort-trigger");
  const defaultItem = page.locator("#wallet-sort-item-default");
  const azItem = page.locator("#wallet-sort-item-az");
  if (!(await sortTrigger.count()) || !(await sortTrigger.isVisible())) {
    test.skip(true, "Sort controls not visible on this viewport");
  }

  await sortTrigger.focus();
  await page.keyboard.press("Enter");
  await expect(defaultItem).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(azItem).toBeFocused();
  await page.keyboard.press("ArrowUp");
  await expect(defaultItem).toBeFocused();
});

test("@status it-wallet mobile search panel announces on open", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/it-wallet.html", { waitUntil: "networkidle" });
  await page.waitForFunction(() => document.getElementById("wallet-grid")?.children.length > 0);

  const searchToggle = page.locator("#wallet-search-toggle");
  if (!(await searchToggle.count()) || !(await searchToggle.isVisible())) {
    test.skip(true, "Mobile search toggle not visible");
  }

  await expect(page.locator("#wallet-controls")).toHaveAttribute("hidden", "");
  await searchToggle.click();
  await expect(page.locator("#wallet-controls")).not.toHaveAttribute("hidden", "");
  await expect(searchToggle).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator("#wallet-search")).toBeFocused();
  await expect(page.locator("#wallet-results-status")).toContainText(/visualizzati|displayed/i);
});

test("@best-practice best-practice checks on it-wallet interactive controls", async ({ page }) => {
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
    await expect(sortTrigger).toBeFocused();
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
