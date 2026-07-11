import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Scans the full page in both themes with every
 * collapsible / progressively-revealed region exposed. This lab has no
 * native <details>; it hides walkthrough steps with a `.is-hidden`
 * (display:none) class and reveals them one at a time. We expose all of
 * them (plus any <details>, just in case) before scanning so hidden
 * content is audited too, and neutralize transitions so nothing is
 * scanned mid-animation.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Expand any native disclosure widgets.
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Freeze transitions/animations and force full opacity so panels are
    // scanned in their settled state, not mid-transition.
    const style = document.createElement('style');
    style.textContent =
      '*,*::before,*::after{animation:none !important;transition:none !important}' +
      '.is-hidden{display:grid !important}' +
      '[hidden]{display:revert !important}';
    document.head.appendChild(style);
    // Reveal progressively-shown walkthrough steps and any hidden panels.
    for (const el of document.querySelectorAll('.is-hidden')) {
      el.classList.remove('is-hidden');
    }
    for (const el of document.querySelectorAll('[hidden]')) {
      el.removeAttribute('hidden');
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealAll(page);
  await scan(page);
});
