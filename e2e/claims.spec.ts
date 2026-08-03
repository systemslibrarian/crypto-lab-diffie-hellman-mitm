import { test as base, expect, type Page } from '@playwright/test';

/**
 * Functional gate: the claims this page makes, asserted against the rendered
 * DOM rather than against the engine the DOM is drawn from.
 *
 * The rules this file plays by:
 *   - Verdicts are checked against a value the PAGE computed, not a string
 *     baked in here. "Both sides derived the same shared secret" is only
 *     believed when Alice's rendered secret and Bob's rendered secret are read
 *     out of two different <dd>s and compared.
 *   - Where the same number is rendered twice through different code (the wire
 *     diagram vs the key cards, Part 3's shares vs Part 4's signed transcript,
 *     the cost table vs the chart's screen-reader description), the two are
 *     asserted equal. Those have been the highest-yield checks in this fleet.
 *   - Key material is spot-checked against an independent BigInt oracle below,
 *     so "8" has to be g^a mod p and not just a plausible-looking digit.
 *   - Handlers repaint in place, so a bare toBeVisible() would re-read the
 *     PREVIOUS result. Every interaction stamps a sentinel into the panel
 *     first and waits for it to be destroyed.
 */

// Fail any test that produced an uncaught page exception.
const test = base.extend<{ pageErrors: void }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', (e) => errors.push(`${e.name}: ${e.message}`));
      await use();
      expect(errors, 'uncaught page exceptions').toEqual([]);
    },
    { auto: true },
  ],
});

// ---------------------------------------------------------------- oracle ----

/** Independent square-and-multiply, so the page's arithmetic is checked
 *  against something other than itself. */
function modPow(base_: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = ((base_ % m) + m) % m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    e >>= 1n;
    b = (b * b) % m;
  }
  return result;
}

// --------------------------------------------------------------- helpers ----

/** Mark the current contents of a panel so we can prove they were replaced.
 *  Every handler here repaints with `innerHTML = …`, which destroys the mark. */
async function stamp(page: Page, selector: string): Promise<void> {
  await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) throw new Error(`stamp: no ${sel}`);
    const mark = document.createElement('span');
    mark.setAttribute('data-e2e-sentinel', '');
    el.appendChild(mark);
  }, selector);
}

/** Wait until the stamped contents are gone AND the new contents have settled
 *  into their final shape (async panels paint a "computing…" interim first). */
async function settled(page: Page, selector: string, needle: RegExp): Promise<void> {
  await page.waitForFunction(
    ({ sel, src }: { sel: string; src: string }) => {
      const el = document.querySelector(sel);
      if (!el) return false;
      if (el.querySelector('[data-e2e-sentinel]')) return false;
      return new RegExp(src).test(el.textContent ?? '');
    },
    { sel: selector, src: needle.source },
  );
}

interface KvEntry {
  text: string;
  /** The untruncated value: long numbers render as "3231…0559 (617 digits)"
   *  with the full digits parked on the copy button. */
  full: string;
}

/** Read every <dl class="kv"> inside a scope as dt -> value, in document order. */
async function readKv(page: Page, scope: string): Promise<Record<string, KvEntry>> {
  return page.evaluate((sel) => {
    const out: Record<string, { text: string; full: string }> = {};
    for (const dl of Array.from(document.querySelectorAll(`${sel} dl.kv`))) {
      let key = '';
      for (const child of Array.from(dl.children)) {
        if (child.tagName === 'DT') key = (child.textContent ?? '').trim();
        else if (child.tagName === 'DD' && key) {
          const chip = child.querySelector('.copy-chip');
          const text = (child.textContent ?? '').trim();
          out[key] = { text, full: chip?.getAttribute('data-copy') ?? text };
        }
      }
    }
    return out;
  }, scope);
}

/** dd values of one wire party, in render order: [sends, receives, key]. */
async function partyValues(page: Page, party: string): Promise<string[]> {
  return page.locator(`#m-out .party--${party} dd`).allTextContents();
}

function leadingBigInt(s: string): bigint {
  const m = s.replace(/[\s,]/g, '').match(/^\d+/);
  expect(m, `expected a number at the start of ${JSON.stringify(s)}`).not.toBeNull();
  return BigInt(m![0]);
}

/** The cost table Part 2 renders: preset label -> { bits, steps, status }. */
async function costTable(page: Page): Promise<Record<string, { bits: number; cost: string; status: string }>> {
  const rows = await page.locator('#p-out .cost-table tbody tr').all();
  const out: Record<string, { bits: number; cost: string; status: string }> = {};
  for (const row of rows) {
    const cells = await row.locator('td').allTextContents();
    out[cells[0]!.trim()] = {
      bits: Number(cells[1]!.replace('-bit', '')),
      cost: cells[2]!.trim(),
      status: cells[3]!.trim(),
    };
  }
  return out;
}

const PRESETS = [
  { id: 'tiny', label: 'Tiny', p: 23n, g: 5n, bits: 5, breakable: true },
  { id: 'small', label: 'Small', p: 2357n, g: 2n, bits: 12, breakable: true },
  { id: 'medium', label: 'Medium', p: 1000003n, g: 2n, bits: 20, breakable: true },
  { id: 'real', label: 'Realistic', p: null, g: 2n, bits: 2048, breakable: false },
] as const;

/** Put Part 3 into a known state and reveal the whole walkthrough. */
async function runMitm(
  page: Page,
  vals: { a: string; b: string; m1: string; m2: string },
): Promise<void> {
  await page.locator('#m-a').fill(vals.a);
  await page.locator('#m-b').fill(vals.b);
  await page.locator('#m-m1').fill(vals.m1);
  await page.locator('#m-m2').fill(vals.m2);
  await stamp(page, '#m-out');
  await page.locator('#m-run').click();
  await settled(page, '#m-out', /Step|Alice/);
  await page.locator('#m-all').click();
  await expect(page.locator('#m-steplabel')).toHaveText('Step 6 of 6');
}

// ------------------------------------------------------- 1. honest exchange --

test('honest exchange: the two rendered shared secrets are the same number, and it is g^ab mod p', async ({
  page,
}) => {
  await page.goto('.');

  for (const preset of PRESETS) {
    await stamp(page, '#p-out');
    await page.locator('#p-preset').selectOption(preset.id);
    await settled(page, '#p-out', /On the wire/);

    const kv = await readKv(page, '#p-out');
    const p = BigInt(kv['p (modulus)']!.full);
    const g = BigInt(kv['g (generator)']!.full);
    const A = BigInt(kv['A = gᵃ mod p']!.full);
    const B = BigInt(kv['B = gᵇ mod p']!.full);
    const fromAlice = BigInt(kv['Alice: Bᵃ mod p']!.full);
    const fromBob = BigInt(kv['Bob: Aᵇ mod p']!.full);
    const a = BigInt(await page.locator('#p-a').inputValue());
    const b = BigInt(await page.locator('#p-b').inputValue());

    // The headline verdict, checked against what the page itself rendered on
    // both sides rather than against a string we chose.
    expect(fromAlice, `${preset.id}: Alice's secret must equal Bob's`).toBe(fromBob);
    await expect(page.locator('#p-out .status')).toHaveClass(/status--ok/);
    await expect(page.locator('#p-out .status')).toContainText('same shared secret');

    // …and that shared number is the real one, not a plausible placeholder.
    expect(p.toString(2).length).toBe(preset.bits);
    expect(A).toBe(modPow(g, a, p));
    expect(B).toBe(modPow(g, b, p));
    expect(fromAlice).toBe(modPow(B, a, p));
    expect(fromBob).toBe(modPow(A, b, p));
    // Never transmitted: the secret must not be either public value.
    expect(fromAlice).not.toBe(A);
    expect(fromAlice).not.toBe(B);
  }

  // The production-size group really did render 617 digits of key material.
  const real = await readKv(page, '#p-out');
  expect(real['Alice: Bᵃ mod p']!.full.length).toBeGreaterThan(600);
});

test('the hero worked example and Part 2 default run render the same p=23 numbers', async ({ page }) => {
  await page.goto('.');

  const hero = (await page.locator('.hero-steps').innerText()).replace(/\s+/g, ' ');
  const heroA = leadingBigInt(hero.match(/A = 5⁶ mod 23 = (\d+)/)![1]!);
  const heroB = leadingBigInt(hero.match(/B = 5¹⁵ mod 23 = (\d+)/)![1]!);
  const heroShared = leadingBigInt(hero.match(/Bᵃ = Aᵇ mod 23 = (\d+)/)![1]!);

  const kv = await readKv(page, '#p-out');
  expect(await page.locator('#p-a').inputValue()).toBe('6');
  expect(await page.locator('#p-b').inputValue()).toBe('15');
  expect(BigInt(kv['A = gᵃ mod p']!.full)).toBe(heroA);
  expect(BigInt(kv['B = gᵇ mod p']!.full)).toBe(heroB);
  expect(BigInt(kv['Alice: Bᵃ mod p']!.full)).toBe(heroShared);
  expect(BigInt(kv['Bob: Aᵇ mod p']!.full)).toBe(heroShared);
  // and the hero's arithmetic is real
  expect(heroShared).toBe(modPow(5n, 6n * 15n, 23n));
});

// ---------------------------------------------------- 2. the passive attack --

test('the discrete-log break recovers the exponent that was typed, and its step count decomposes into the cost table it prints', async ({
  page,
}) => {
  await page.goto('.');

  const exponents: Record<string, string> = { tiny: '9', small: '1234', medium: '424242' };

  for (const preset of PRESETS.filter((p) => p.breakable)) {
    await stamp(page, '#p-out');
    await page.locator('#p-preset').selectOption(preset.id);
    await settled(page, '#p-out', /On the wire/);

    await page.locator('#p-a').fill(exponents[preset.id]!);
    await stamp(page, '#p-out');
    await page.locator('#p-run').click();
    await settled(page, '#p-out', /On the wire/);
    const A = BigInt((await readKv(page, '#p-out'))['A = gᵃ mod p']!.full);

    await stamp(page, '#p-out');
    await page.locator('#p-break').click();
    await settled(page, '#p-out', /baby-step giant-step/);

    const verdict = await page.locator('#p-out .status').innerText();
    // The attack claims a specific exponent — it must be the one we typed, and
    // it must genuinely open the exchange the page rendered a moment ago.
    const recovered = BigInt(verdict.match(/a = (\d+)/)![1]!);
    expect(recovered.toString()).toBe(exponents[preset.id]);
    expect(modPow(preset.g, recovered, preset.p!)).toBe(A);
    await expect(page.locator('#p-out .status')).toHaveClass(/status--alarm/);

    // Counter consistency: the reported work is baby steps + giant steps, where
    // the baby-step table is exactly the ~√p figure this same panel tabulates,
    // and the giant-step walk is strictly shorter than that table.
    const steps = Number(verdict.match(/in ([\d,]+) group operations/)![1]!.replace(/,/g, ''));
    const table = await costTable(page);
    const babySteps = Number(table[preset.label]!.cost.match(/~(\d+) steps/)![1]!);
    expect(table[preset.label]!.bits).toBe(preset.bits);
    expect(table[preset.label]!.status).toBe('breakable here');
    expect(steps, `${preset.id}: total work >= the √p baby-step table`).toBeGreaterThanOrEqual(babySteps);
    expect(steps, `${preset.id}: giant-step walk must be shorter than the table`).toBeLessThan(2 * babySteps);
  }
});

test('the 2048-bit group refuses the break, and every surface quotes the same work factor', async ({
  page,
}) => {
  await page.goto('.');

  // Print the cost table first (it only renders after a break attempt).
  await stamp(page, '#p-out');
  await page.locator('#p-break').click();
  await settled(page, '#p-out', /baby-step giant-step/);
  const table = await costTable(page);
  expect(table['Realistic']!.status).toBe('infeasible');
  const tableExp = table['Realistic']!.cost.match(/2\^(\d+)/)![1]!;

  await stamp(page, '#p-out');
  await page.locator('#p-preset').selectOption('real');
  await settled(page, '#p-out', /On the wire/);

  // Failure path: the attack is refused, and the refusal names the reason.
  const breakBtn = page.locator('#p-break');
  await expect(breakBtn).toBeDisabled();
  const title = (await breakBtn.getAttribute('title'))!;
  expect(title).toMatch(/Disabled: at 2048 bits/);
  const titleExp = title.match(/2\^(\d+)/)![1]!;

  // Three independently-formatted surfaces, one number.
  const chartLabel = (await page.locator('.chart-figure svg').getAttribute('aria-label'))!;
  const chartExp = chartLabel.match(/2048-bit, about 2 to the (\d+)/)![1]!;
  expect(titleExp).toBe(tableExp);
  expect(chartExp).toBe(tableExp);

  // …and the exchange itself still completes at production size.
  await expect(page.locator('#p-out .status')).toContainText('same shared secret');
});

test('the chart description a screen reader hears quotes the same work factors as the bars it describes', async ({
  page,
}) => {
  await page.goto('.');
  await stamp(page, '#p-out');
  await page.locator('#p-break').click();
  await settled(page, '#p-out', /baby-step giant-step/);

  const chartLabel = (await page.locator('.chart-figure svg').getAttribute('aria-label'))!;
  const bars = await page.locator('.chart-figure .chart-value').allTextContents();
  const rowLabels = await page.locator('.chart-figure .chart-label').allTextContents();
  expect(bars).toHaveLength(4);

  const spoken = [...chartLabel.matchAll(/(\d+)-bit, about 2 to the ([\d.]+) steps/g)].map((m) => ({
    bits: m[1]!,
    exp: m[2]!,
  }));
  expect(spoken).toHaveLength(4);

  const table = await costTable(page);
  for (const [i, bar] of bars.entries()) {
    // The bar's own label and the spoken description must be the same figure.
    const barExp = bar.match(/2\^([\d.]+)/)![1]!;
    expect(barExp, `bar ${i}`).toBe(spoken[i]!.exp);
    expect(rowLabels[i]).toContain(`${spoken[i]!.bits}-bit`);

    // …and that log2 figure must agree with the linear step count the cost
    // table prints for the same preset (1 dp of rounding => ~3.5% at worst).
    const preset = PRESETS[i]!;
    const cost = table[preset.label]!.cost;
    const linear = cost.match(/~(\d+) steps$/);
    if (linear) {
      const ratio = Math.pow(2, Number(barExp)) / Number(linear[1]!);
      expect(ratio, `${preset.label}: 2^${barExp} vs ${linear[1]} steps`).toBeGreaterThan(0.95);
      expect(ratio).toBeLessThan(1.05);
    } else {
      expect(cost).toContain(`2^${barExp}`);
    }
  }
});

// ----------------------------------------------------- 3. the active attack --

test('MITM: Alice shares her key with Mallory, Bob shares a different one, and no key is shared between Alice and Bob', async ({
  page,
}) => {
  await page.goto('.');
  await runMitm(page, { a: '1751', b: '998', m1: '333', m2: '777' });

  const [aliceSends, aliceReceives, aliceKey] = await partyValues(page, 'alice');
  const [malloryWithAlice, malloryWithBob] = await partyValues(page, 'mallory');
  const [bobSends, bobReceives, bobKey] = await partyValues(page, 'bob');

  const A = leadingBigInt(aliceSends!);
  const B = leadingBigInt(bobSends!);
  const M1 = leadingBigInt(aliceReceives!);
  const M2 = leadingBigInt(bobReceives!);
  const kAlice = leadingBigInt(aliceKey!);
  const kBob = leadingBigInt(bobKey!);
  const kMalloryAlice = leadingBigInt(malloryWithAlice!);
  const kMalloryBob = leadingBigInt(malloryWithBob!);

  // The claim, checked against page-computed values on both sides of each
  // equality. aliceKey is M1^a; malloryKeyWithAlice is A^m1 — different
  // computations that must land on the same number.
  expect(kAlice, "Alice's key must equal Mallory's Alice-side key").toBe(kMalloryAlice);
  expect(kBob, "Bob's key must equal Mallory's Bob-side key").toBe(kMalloryBob);
  expect(kAlice, 'Alice and Bob must NOT share a key').not.toBe(kBob);

  // Alice and Bob each received Mallory's value, not the peer's.
  expect(M1).not.toBe(B);
  expect(M2).not.toBe(A);
  expect(aliceReceives).toContain("Mallory's, not Bob's");
  expect(bobReceives).toContain("Mallory's, not Alice's");

  // Independent arithmetic: every one of those four numbers is real.
  const p = 2357n;
  const g = 2n;
  expect(A).toBe(modPow(g, 1751n, p));
  expect(B).toBe(modPow(g, 998n, p));
  expect(M1).toBe(modPow(g, 333n, p));
  expect(M2).toBe(modPow(g, 777n, p));
  expect(kAlice).toBe(modPow(M1, 1751n, p));
  expect(kBob).toBe(modPow(M2, 998n, p));

  // Cross-render: the key cards are drawn from the same run as the wire panel.
  const cards = await page.locator('#m-out .key-card .key-value').allTextContents();
  expect(leadingBigInt(cards[0]!)).toBe(kAlice);
  expect(leadingBigInt(cards[1]!)).toBe(kBob);
  await expect(page.locator('#m-out .key-card--alarm')).toHaveCount(2);
  await expect(page.locator('#m-out > .status')).toHaveClass(/status--alarm/);
  await expect(page.locator('#m-out > .status')).toContainText("Alice's key ≠ Bob's key");
});

test('the relay really encrypts: Mallory reads the plaintext, swaps it, and Bob cannot open Alice’s own ciphertext', async ({
  page,
}) => {
  await page.goto('.');
  await runMitm(page, { a: '1751', b: '998', m1: '333', m2: '777' });

  await page.locator('#i-msg').fill('Pay Bob $100');
  await page.locator('#i-edit').fill('Pay Mallory $9000');
  await stamp(page, '#i-out');
  await page.locator('#i-send').click();
  await settled(page, '#i-out', /believes Alice said/);

  const relay = await page.locator('#i-out').innerText();
  expect(relay).toContain('Pay Bob $100'); // Mallory decrypted it
  expect(relay).toContain('a rewritten message');
  expect(relay).toContain('Pay Mallory $9000'); // Bob accepted the rewrite

  const cards = await page.locator('#i-out .key-card .key-value').allTextContents();
  expect(cards[0]).toContain('Pay Mallory $9000');

  // FAILURE PATH: Bob's direct read of Alice's real ciphertext must fail, and
  // the page must name the cause (no shared key / GCM tag check).
  expect(cards[1]).toContain('fails — no shared key');
  await expect(page.locator('#i-out .key-card').nth(1)).toHaveClass(/key-card--alarm/);
  await expect(page.locator('#i-out')).toContainText('AES-GCM tag check just failed');
  await expect(page.locator('#i-out > .status')).toHaveClass(/status--alarm/);

  // Two ciphertexts under two different keys => two different IV/ct lines.
  const sealed = await page.locator('#i-out .relay-steps .mono-scroll').allTextContents();
  expect(sealed).toHaveLength(2);
  expect(sealed[0]).not.toBe(sealed[1]);
  expect(sealed[0]).toMatch(/^iv=[0-9a-f]{8}… · ct=[0-9a-f]{24}…$/);

  // The control must survive the run.
  await expect(page.locator('#i-send')).toBeEnabled();
});

test('when the chosen exponents make the two keys collide, BOTH panels say so and neither claims a split', async ({
  page,
}) => {
  await page.goto('.');
  // Same exponent on both sides of Mallory => one key, not two. The demo's own
  // degenerate case, and it must be reported rather than papered over.
  await runMitm(page, { a: '100', b: '100', m1: '50', m2: '50' });

  const [, , aliceKey] = await partyValues(page, 'alice');
  const [, , bobKey] = await partyValues(page, 'bob');
  expect(leadingBigInt(aliceKey!)).toBe(leadingBigInt(bobKey!));
  await expect(page.locator('#m-out > .status')).toHaveClass(/status--info/);
  await expect(page.locator('#m-out > .status')).toContainText('happened to collide');
  await expect(page.locator('#m-out .key-card--alarm')).toHaveCount(0);

  await stamp(page, '#i-out');
  await page.locator('#i-send').click();
  await settled(page, '#i-out', /believes Alice said/);

  // The relay must reach the SAME conclusion as the panel above it.
  const cards = await page.locator('#i-out .key-card .key-value').allTextContents();
  expect(cards[1]).toContain('Pay Bob $100'); // Bob CAN read Alice's bytes now
  expect(cards[1]).not.toContain('fails');
  await expect(page.locator('#i-out')).toContainText('the split never happened');
  await expect(page.locator('#i-out')).not.toContainText('AES-GCM tag check just failed');
});

// ------------------------------------------------------------ 4. the fix ----

test('signed handshake (honest): the signature verifies, Bob proceeds, and the signed shares are the ones Part 3 puts on the wire', async ({
  page,
}) => {
  await page.goto('.');

  // Part 3's defaults use the same group and exponents Part 4 signs over, so
  // the two sections must agree on A and B.
  const [aliceSends] = await partyValues(page, 'alice');
  const [bobSends] = await partyValues(page, 'bob');

  await stamp(page, '#f-out');
  await page.locator('#f-clean').click();
  await settled(page, '#f-out', /Bob proceeds/);

  const kv = await readKv(page, '#f-out');
  const signed = kv['Transcript Alice signed']!.text;
  const verified = kv['Transcript Bob verifies']!.text;
  expect(kv["Bob's verify()"]!.text).toBe('true');
  expect(kv['Bob proceeds?']!.text).toBe('yes');
  await expect(page.locator('#f-out .status')).toHaveClass(/status--ok/);
  await expect(page.locator('#f-out .status')).toContainText('Bob accepts');

  // The verifier reconstructed exactly the transcript the signer signed.
  const signedSelf = signed.match(/self=A?=?(\d+)/)![1]!;
  const verifiedSelf = verified.match(/self=A?=?(\d+)/)![1]!;
  const signedPeer = signed.match(/peer=B=(\d+)/)![1]!;
  const verifiedPeer = verified.match(/peer=B=(\d+)/)![1]!;
  expect(verifiedSelf).toBe(signedSelf);
  expect(verifiedPeer).toBe(signedPeer);
  expect(verified).not.toContain('swapped by Mallory');

  // Cross-section: the same shares Part 3 renders on the wire.
  expect(signedSelf).toBe(leadingBigInt(aliceSends!).toString());
  expect(signedPeer).toBe(leadingBigInt(bobSends!).toString());
  expect(BigInt(signedSelf)).toBe(modPow(2n, 1751n, 2357n));
});

test('signed handshake (tampered): verification fails closed, the cause is named, and the substituted share is exactly the value Part 3 shows Mallory sending', async ({
  page,
}) => {
  await page.goto('.');

  const [, aliceReceives] = await partyValues(page, 'alice');
  const malloryShare = leadingBigInt(aliceReceives!); // M1 = g^333

  await stamp(page, '#f-out');
  await page.locator('#f-tamper').click();
  await settled(page, '#f-out', /Bob proceeds/);

  const kv = await readKv(page, '#f-out');
  // FAILURE PATH: reached, and named.
  expect(kv["Bob's verify()"]!.text).toBe('false');
  expect(kv['Bob proceeds?']!.text).toBe('no — aborted');
  await expect(page.locator('#f-out .status')).toContainText('man-in-the-middle is detected');
  await expect(page.locator('#f-out .status')).toContainText('aborts');
  // A detected attack is a system-integrity WIN, so it must not be styled alarm.
  await expect(page.locator('#f-out .status')).toHaveClass(/status--ok/);

  const signed = kv['Transcript Alice signed']!.text;
  const verified = kv['Transcript Bob verifies']!.text;
  const signedSelf = signed.match(/self=A?=?(\d+)/)![1]!;
  const verifiedSelf = verified.match(/self=A?=?(\d+)/)![1]!;
  const signedPeer = signed.match(/peer=B=(\d+)/)![1]!;
  const verifiedPeer = verified.match(/peer=B=(\d+)/)![1]!;

  // The transcripts differ in exactly one field — the signer's own share.
  expect(verifiedSelf).not.toBe(signedSelf);
  expect(verifiedPeer).toBe(signedPeer);
  expect(verified).toContain('swapped by Mallory');
  // …and the swapped-in value is Mallory's M₁ from Part 3, not an arbitrary one.
  expect(BigInt(verifiedSelf)).toBe(malloryShare);
  expect(BigInt(verifiedSelf)).toBe(modPow(2n, 333n, 2357n));

  // Honest run right after must not inherit the failure.
  await stamp(page, '#f-out');
  await page.locator('#f-clean').click();
  await settled(page, '#f-out', /Bob proceeds/);
  expect((await readKv(page, '#f-out'))["Bob's verify()"]!.text).toBe('true');
});

// ------------------------------------------------------------ regressions ---

test('REGRESSION: re-running the attack retires the relay that was encrypted under the old keys', async ({
  page,
}) => {
  await page.goto('.');

  // 1. A run whose two keys collide, relayed. The relay's verdict is a claim
  //    about THOSE keys: "the split never happened".
  await runMitm(page, { a: '100', b: '100', m1: '50', m2: '50' });
  await stamp(page, '#i-out');
  await page.locator('#i-send').click();
  await settled(page, '#i-out', /believes Alice said/);
  await expect(page.locator('#i-out')).toContainText('the split never happened');

  // 2. Change m₂ and re-run. Alice's and Bob's keys now differ.
  await runMitm(page, { a: '100', b: '100', m1: '50', m2: '777' });
  const [, , aliceKey] = await partyValues(page, 'alice');
  const [, , bobKey] = await partyValues(page, 'bob');
  expect(leadingBigInt(aliceKey!)).not.toBe(leadingBigInt(bobKey!));
  await expect(page.locator('#m-out > .status')).toContainText('Attack succeeded');

  // 3. The relay below must not still be asserting the opposite about the same
  //    run. (It used to: "K(Alice·Mallory) = K(Bob·Mallory), so the split never
  //    happened" sat directly under "Attack succeeded: Alice's key ≠ Bob's key",
  //    with Bob shown reading Alice's bytes he no longer has the key for.)
  await expect(page.locator('#i-out')).not.toContainText('the split never happened');
  await expect(page.locator('#i-out')).not.toContainText('believes Alice said');
  await expect(page.locator('#i-out')).toContainText('Send through Mallory');
  await expect(page.locator('#i-out .key-card')).toHaveCount(0);

  // 4. Same guarantee when the group parameters change underneath it.
  await stamp(page, '#i-out');
  await page.locator('#i-send').click();
  await settled(page, '#i-out', /believes Alice said/);
  await stamp(page, '#i-out');
  await page.locator('#m-preset').selectOption('tiny');
  await settled(page, '#i-out', /Send through Mallory/);
  await expect(page.locator('#i-out .key-card')).toHaveCount(0);
});

test('REGRESSION: a verdict does not outlive the exponent it names', async ({ page }) => {
  await page.goto('.');

  // Part 2: the break prints "Recovered Alice's secret: a = 6".
  await stamp(page, '#p-out');
  await page.locator('#p-break').click();
  await settled(page, '#p-out', /baby-step giant-step/);
  await expect(page.locator('#p-out .status')).toContainText("Recovered Alice's secret: a = 6");

  // Retype the very exponent that verdict names.
  await page.locator('#p-a').fill('7');
  await expect(page.locator('#p-out')).toHaveAttribute('data-stale', 'true');
  const note = page.locator('#p-out [data-stale-note]');
  await expect(note).toBeVisible();
  await expect(note).toContainText('Run exchange'); // names the control that fixes it

  // Recomputing clears the flag, and the panel now describes a = 7.
  await stamp(page, '#p-out');
  await page.locator('#p-run').click();
  await settled(page, '#p-out', /On the wire/);
  await expect(page.locator('#p-out')).not.toHaveAttribute('data-stale', 'true');
  await expect(page.locator('#p-out [data-stale-note]')).toHaveCount(0);
  expect(BigInt((await readKv(page, '#p-out'))['A = gᵃ mod p']!.full)).toBe(modPow(5n, 7n, 23n));

  // Part 3: the wire diagram and the relay both name the exponents too.
  await runMitm(page, { a: '1751', b: '998', m1: '333', m2: '777' });
  await stamp(page, '#i-out');
  await page.locator('#i-send').click();
  await settled(page, '#i-out', /believes Alice said/);

  await page.locator('#m-m1').fill('334');
  await expect(page.locator('#m-out')).toHaveAttribute('data-stale', 'true');
  await expect(page.locator('#i-out')).toHaveAttribute('data-stale', 'true');
  await expect(page.locator('#m-out [data-stale-note]')).toContainText('Run the attack');
  await expect(page.locator('#i-out [data-stale-note]')).toContainText('Send through Mallory');

  // Editing the message invalidates the relay transcript alone.
  await runMitm(page, { a: '1751', b: '998', m1: '334', m2: '777' });
  await stamp(page, '#i-out');
  await page.locator('#i-send').click();
  await settled(page, '#i-out', /believes Alice said/);
  await expect(page.locator('#m-out')).not.toHaveAttribute('data-stale', 'true');
  await page.locator('#i-msg').fill('Pay Bob $1');
  await expect(page.locator('#i-out')).toHaveAttribute('data-stale', 'true');
  await expect(page.locator('#m-out')).not.toHaveAttribute('data-stale', 'true');
});

test('REGRESSION: the hidden attribute actually hides — author display rules do not beat it', async ({
  page,
}) => {
  await page.goto('.');

  // Nothing shipping the attribute may be painted.
  const leaks = await page.evaluate(() =>
    Array.from(document.querySelectorAll('[hidden]'))
      .filter((el) => getComputedStyle(el).display !== 'none')
      .map((el) => `${el.tagName.toLowerCase()}.${(el as HTMLElement).className}`),
  );
  expect(leaks, 'elements marked hidden that still render').toEqual([]);

  // And `el.hidden = true` must not be a silent no-op on this page's layout
  // classes. Every one of these carries an author `display`, which beats the
  // UA sheet's `[hidden]{display:none}` at any specificity; without an
  // !important override in style.css all 18 of them rendered anyway.
  const stillPainted = await page.evaluate(() => {
    const classes = [
      'wire', 'party', 'steps', 'kv', 'controls', 'field', 'stepper', 'key-grid',
      'threat-strip', 'toy-banner', 'compare', 'hero-steps', 'section-nav',
      'reuse-grid', 'related', 'glossary', 'ref-list', 'panel-card', 'lab-section',
    ];
    const out: string[] = [];
    for (const cls of classes) {
      const probe = document.createElement('div');
      probe.className = cls;
      probe.hidden = true;
      document.body.appendChild(probe);
      if (getComputedStyle(probe).display !== 'none') out.push(cls);
      probe.remove();
    }
    const steps = document.querySelector('.steps');
    if (steps) {
      const li = document.createElement('li');
      li.hidden = true;
      steps.appendChild(li);
      if (getComputedStyle(li).display !== 'none') out.push('steps>li');
      li.remove();
    }
    return out;
  });
  expect(stillPainted, 'classes whose author display beats [hidden]').toEqual([]);
});

// ------------------------------------------------------- input & liveness ---

test('out-of-range and non-numeric exponents are clamped into [1, p-2] and the exchange still agrees with the clamped value', async ({
  page,
}) => {
  await page.goto('.');

  const cases: { typed: string; expect: string }[] = [
    { typed: '0', expect: '1' }, // below the range
    { typed: '-5', expect: '1' },
    { typed: '99999', expect: '21' }, // above p-2 for p = 23
    { typed: 'not-a-number', expect: '21' }, // unparseable -> keeps the last good value
  ];

  for (const c of cases) {
    await page.locator('#p-a').fill(c.typed);
    await stamp(page, '#p-out');
    await page.locator('#p-run').click();
    await settled(page, '#p-out', /On the wire/);

    // The control is corrected in place…
    expect(await page.locator('#p-a').inputValue(), `typed ${c.typed}`).toBe(c.expect);
    // …and the rendered public value is g^(clamped) mod p, not g^(typed).
    const kv = await readKv(page, '#p-out');
    expect(BigInt(kv['A = gᵃ mod p']!.full)).toBe(modPow(5n, BigInt(c.expect), 23n));
    expect(BigInt(kv['Alice: Bᵃ mod p']!.full)).toBe(BigInt(kv['Bob: Aᵇ mod p']!.full));
    await expect(page.locator('#p-out .status')).toHaveClass(/status--ok/);
  }
});

test('every control stays live across a full session', async ({ page }) => {
  await page.goto('.');

  // Walkthrough bounds: only the ends are disabled, and only at the ends.
  await runMitm(page, { a: '1751', b: '998', m1: '333', m2: '777' });
  await expect(page.locator('#m-next')).toBeDisabled(); // at step 6
  await expect(page.locator('#m-prev')).toBeEnabled();
  await page.locator('#m-prev').click();
  await expect(page.locator('#m-next')).toBeEnabled();
  await stamp(page, '#m-out');
  await page.locator('#m-run').click();
  await settled(page, '#m-out', /Alice/);
  await expect(page.locator('#m-steplabel')).toHaveText('Step 1 of 6');
  await expect(page.locator('#m-prev')).toBeDisabled();
  await expect(page.locator('#m-next')).toBeEnabled();

  // The relay button comes back after a completed run…
  await page.locator('#m-all').click();
  await stamp(page, '#i-out');
  await page.locator('#i-send').click();
  await settled(page, '#i-out', /believes Alice said/);
  await expect(page.locator('#i-send')).toBeEnabled();

  // The break button is disabled ONLY on the infeasible group, and recovers.
  await stamp(page, '#p-out');
  await page.locator('#p-preset').selectOption('real');
  await settled(page, '#p-out', /On the wire/);
  await expect(page.locator('#p-break')).toBeDisabled();
  await stamp(page, '#p-out');
  await page.locator('#p-preset').selectOption('medium');
  await settled(page, '#p-out', /On the wire/);
  await expect(page.locator('#p-break')).toBeEnabled();
  await expect(page.locator('#p-run')).toBeEnabled();

  // Both signed-handshake buttons remain usable in either order.
  for (const id of ['#f-tamper', '#f-clean', '#f-tamper']) {
    await stamp(page, '#f-out');
    await page.locator(id).click();
    await settled(page, '#f-out', /Bob proceeds/);
    await expect(page.locator(id)).toBeEnabled();
  }
});
