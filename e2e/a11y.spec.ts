import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

async function checkGradientContrast(page: Page, selector: string) {
  const ratio = await page.evaluate((sel) => {
    function getLuminance(r: number, g: number, b: number) {
      const a = [r, g, b].map(v => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      });
      return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722;
    }
    const el = document.querySelector(sel);
    if (!el) return 0;
    const style = window.getComputedStyle(el);
    const colorMatch = style.color.match(/\d+/g);
    if (!colorMatch) return 0;
    const [cr, cg, cb] = colorMatch.map(Number);
    const textLum = getLuminance(cr, cg, cb);

    let bgStr = getComputedStyle(document.body).backgroundColor;
    if (bgStr === 'rgba(0, 0, 0, 0)' || bgStr === 'transparent') {
      bgStr = getComputedStyle(document.documentElement).backgroundColor;
    }
    const bgMatch = bgStr.match(/\d+/g);
    if (!bgMatch) return 0;
    const [br, bg, bb] = bgMatch.map(Number);
    const bgLum = getLuminance(br, bg, bb);

    const L1 = Math.max(textLum, bgLum);
    const L2 = Math.min(textLum, bgLum);
    return (L1 + 0.05) / (L2 + 0.05);
  }, selector);
  expect(ratio).toBeGreaterThanOrEqual(4.5);
}

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
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  await expect(page.locator('h1')).toBeVisible();
  await checkGradientContrast(page, '.scripture-footer');
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  await expect(page.locator('h1')).toBeVisible();
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await checkGradientContrast(page, '.scripture-footer');
  await revealAll(page);
  await scan(page);
});
