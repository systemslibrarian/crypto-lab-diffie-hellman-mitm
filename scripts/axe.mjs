// axe-core accessibility audit against the live preview build.
// WCAG 2.1 A/AA across three viewport widths and both themes.
import { chromium } from 'playwright';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve('axe-core'), 'utf8');

const URL = 'http://localhost:4173/crypto-lab-diffie-hellman-mitm/';

async function audit(label, viewport, theme) {
	console.log(`\n=== axe: ${label} (${theme}) ===`);
	const browser = await chromium.launch();
	const ctx = await browser.newContext({ viewport });
	// Seed the theme before boot so the anti-flash script paints it first.
	await ctx.addInitScript((t) => {
		try { localStorage.setItem('theme', t); } catch {}
	}, theme);
	const page = await ctx.newPage();
	await page.goto(URL, { waitUntil: 'networkidle' });
	// Wait for the passive playground to render its first exchange.
	await page.waitForFunction(
		() => /shared secret/.test(document.querySelector('#p-out')?.textContent ?? ''),
	);
	await page.addScriptTag({ content: axeSource });
	const result = await page.evaluate(async () => {
		// @ts-ignore — axe injected above
		return await window.axe.run(document, {
			runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
		});
	});
	const v = result.violations;
	if (v.length === 0) {
		console.log('ok  : no WCAG 2.1 A/AA violations');
	} else {
		console.error(`FAIL: ${v.length} violation(s)`);
		for (const violation of v) {
			console.error(`  - [${violation.impact}] ${violation.id}: ${violation.help}`);
			for (const node of violation.nodes.slice(0, 3)) {
				console.error(`      target: ${node.target.join(' ')}`);
			}
		}
		process.exitCode = 1;
	}
	console.log(`     passes: ${result.passes.length}, incomplete: ${result.incomplete.length}`);
	await browser.close();
}

for (const theme of ['dark', 'light']) {
	await audit('desktop 1280', { width: 1280, height: 800 }, theme);
	await audit('mobile 390', { width: 390, height: 844 }, theme);
	await audit('narrow 360', { width: 360, height: 740 }, theme);
}

if (process.exitCode) console.error('\nAXE: FAIL');
else console.log('\nAXE: PASS');
