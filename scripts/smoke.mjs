// Headless smoke test — desktop + mobile viewports, real interactions.
// Run after `npm run preview` is serving on http://localhost:4623 -- this
// lab's port, and what OWN_PORT below already uses. The comment said 4700,
// which belongs to crypto-lab-pqxdh-wire.
import { chromium, devices } from 'playwright';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/* Own the server this suite tests.
 *
 * This file used to point at a fixed localhost port and assume a preview was
 * already serving it, without checking whose server answered. A port held by
 * another project -- or by a sibling lab previewed on the same workstation --
 * answers the goto, and every assertion after it describes someone else's
 * page. Port 4623 is this lab's own in the fleet registry
 * (crypto-lab/tools/playwright-ports.json); it was 4700, which the registry assigns to
 * crypto-lab-pqxdh-wire.
 * --strictPort refuses to move, so a collision now fails loudly here instead
 * of testing the wrong app quietly.
 *
 * Set SMOKE_URL to point this at an already-running server; CI does.
 */
const OWN_PORT = 4623;
const URL = process.env.SMOKE_URL ?? `http://localhost:${OWN_PORT}/crypto-lab-diffie-hellman-mitm/`;
let ownServer = null;

async function reachable(u) {
	try {
		return (await fetch(u, { redirect: 'follow' })).ok;
	} catch {
		return false;
	}
}

async function startOwnServer() {
	if (!existsSync(join(REPO_ROOT, 'dist', 'index.html'))) {
		const built = spawnSync('npm', ['run', 'build'], { cwd: REPO_ROOT, encoding: 'utf8' });
		if (built.status !== 0) {
			console.error('FAIL: could not build before starting the preview server');
			console.error((built.stdout ?? '') + (built.stderr ?? ''));
			process.exit(1);
		}
	}
	const child = spawn('npm', ['run', 'preview', '--', '--port', String(OWN_PORT), '--strictPort'], {
		cwd: REPO_ROOT,
		stdio: ['ignore', 'pipe', 'pipe'],
	});
	let log = '';
	child.stdout.on('data', (d) => (log += d));
	child.stderr.on('data', (d) => (log += d));
	for (let i = 0; i < 60; i++) {
		if (await reachable(URL)) return child;
		if (child.exitCode !== null) break;
		await new Promise((r) => setTimeout(r, 500));
	}
	console.error(`FAIL: preview did not come up on port ${OWN_PORT} within 30s.`);
	console.error('      --strictPort does not move, so this is a port collision or a build fault:');
	console.error(log.trim() || '      (the server printed nothing)');
	try {
		if (child.exitCode === null) process.kill(child.pid);
	} catch {}
	process.exit(1);
}

/* By pid, and only the child this process started -- never by pattern. */
function stopOwnServer() {
	if (ownServer?.exitCode === null) {
		try {
			process.kill(ownServer.pid);
		} catch {}
	}
}

if (!process.env.SMOKE_URL) ownServer = await startOwnServer();



function assert(cond, msg) {
	if (!cond) {
		console.error('FAIL:', msg);
		process.exitCode = 1;
	} else {
		console.log('ok  :', msg);
	}
}

async function run(label, deviceOpts) {
	console.log(`\n=== ${label} ===`);
	const browser = await chromium.launch();
	const ctx = await browser.newContext(deviceOpts ?? {});
	const page = await ctx.newPage();

	const errors = [];
	page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
	page.on('console', (m) => {
		if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
	});

	await page.goto(URL, { waitUntil: 'networkidle' });

	// Standardization surface.
	assert((await page.locator('h1').count()) === 1, 'exactly one h1');
	assert((await page.locator('h1.cl-hero-title').first().textContent())?.includes('Diffie–Hellman'), 'hero title present');
	assert((await page.locator('.cl-topbar').count()) === 1, 'exactly one shared header');
	assert((await page.locator('a.cl-skip-link[href="#app"]').count()) === 1, 'skip link targets #app');
	const footer = page.locator('footer.scripture-footer');
	assert(
		(await footer.textContent())?.includes('1 Corinthians 10:31'),
		'scripture footer present',
	);

	// Part 2 — DH exchange + working discrete-log break.
	await page.locator('#p-run').click();
	assert((await page.locator('#p-out').textContent())?.includes('shared secret'), 'passive exchange renders');
	await page.locator('#p-break').click();
	assert(
		(await page.locator('#p-out').textContent())?.includes("Recovered Alice's secret"),
		'discrete-log break recovers a',
	);
	assert((await page.locator('.chart-figure svg').count()) >= 1, 'difficulty chart present');
	// 2048-bit: exchange still computes, break is disabled.
	await page.locator('#p-preset').selectOption('real');
	assert(await page.locator('#p-break').isDisabled(), 'break disabled on 2048-bit');
	assert((await page.locator('#p-out').textContent())?.includes('same shared secret'), '2048-bit exchange agrees');

	// Part 3 — MITM step-through.
	await page.locator('#m-run').click();
	assert((await page.locator('#m-steplabel').textContent())?.includes('Step 1 of 6'), 'walkthrough starts at step 1');
	assert(await page.locator('#m-prev').isDisabled(), 'prev disabled at step 1');
	await page.locator('#m-all').click();
	assert((await page.locator('#mitm').textContent())?.includes('Attack succeeded'), 'MITM splits keys (alarm)');
	assert((await page.locator('#mitm .key-card--alarm').count()) === 2, 'two alarm key cards');
	// stepping back hides the punchline
	await page.locator('#m-prev').click();
	assert((await page.locator('#mitm .key-card').count()) === 0, 'stepping back hides key cards');

	// Part 3 payoff — Mallory reads and rewrites a real AES-GCM message.
	await page.locator('#m-all').click(); // ensure keys are shown
	await page.locator('#i-send').click();
	await page.waitForFunction(() => /believes Alice said/.test(document.querySelector('#i-out')?.textContent ?? ''));
	assert((await page.locator('#i-out').textContent())?.includes('Pay Bob $100'), 'Mallory decrypts Alice’s real message');
	assert((await page.locator('#i-out').textContent())?.includes('Pay Mallory $9000'), 'Bob receives Mallory’s rewrite');
	assert((await page.locator('#i-out').textContent())?.includes('no shared key'), 'Bob can’t read Alice’s original directly');

	// Part 4 — authenticated DH (real ECDSA), honest then tampered.
	await page.locator('#f-clean').click();
	await page.waitForFunction(() => /verifies/.test(document.querySelector('#f-out')?.textContent ?? ''));
	assert((await page.locator('#f-out').textContent())?.includes('Bob accepts'), 'signed honest accepted');
	await page.locator('#f-tamper').click();
	await page.waitForFunction(() => /detected/.test(document.querySelector('#f-out')?.textContent ?? ''));
	assert(
		(await page.locator('#f-out').textContent())?.includes('man-in-the-middle is detected'),
		'tamper detected, fail closed',
	);

	// Part 6 — references & glossary.
	assert((await page.locator('#refs .ref-list li').count()) >= 6, 'references listed');
	assert((await page.locator('#refs .glossary dt').count()) >= 8, 'glossary populated');

	// No horizontal overflow.
	const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
	assert(!overflow, 'no horizontal overflow');

	assert(errors.length === 0, `no console/page errors${errors.length ? ' -> ' + errors.join(' | ') : ''}`);

	await browser.close();
}

await run('desktop 1280', { viewport: { width: 1280, height: 900 } });
await run('iPhone 12', devices['iPhone 12']);
await run('narrow 360', { viewport: { width: 360, height: 740 } });

stopOwnServer();

if (process.exitCode) console.error('\nSMOKE: FAIL');
else console.log('\nSMOKE: PASS');
