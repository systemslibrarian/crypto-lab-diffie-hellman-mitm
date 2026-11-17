// axe-core accessibility audit against the live preview build.
// WCAG 2.1 A/AA across three viewport widths and both themes.
import { chromium } from 'playwright';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
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
 * Set AXE_URL to point this at an already-running server; CI does.
 */
const OWN_PORT = 4623;
const URL = process.env.AXE_URL ?? `http://localhost:${OWN_PORT}/crypto-lab-diffie-hellman-mitm/`;
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

if (!process.env.AXE_URL) ownServer = await startOwnServer();


const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve('axe-core'), 'utf8');


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

stopOwnServer();

if (process.exitCode) console.error('\nAXE: FAIL');
else console.log('\nAXE: PASS');
