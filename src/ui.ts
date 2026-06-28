// ui.ts — Diffie–Hellman & the man in the middle.
//
// One scrollable lesson in five parts, mirroring the prompt's required flow:
//   1. Quick explanation (small numbers)
//   2. Passive eavesdropper — run DH, then actually break it on toy primes
//   3. Active man-in-the-middle (the main event)
//   4. What breaks — unauthenticated vs signed DH, with real ECDSA
//   5. Key takeaways
//
// All interactive controls are keyboard-operable; every status pairs an icon,
// text, and colour. Colour tracks system integrity: a successful MITM is an
// ALARM, never a green "success".

import {
	PRESETS,
	presetById,
	diffieHellman,
	babyStepGiantStep,
	discreteLogCost,
	modPow,
	mitm,
	generateIdentity,
	authenticatedDeliver,
} from './engine.ts';
import type { DhPreset } from './engine.ts';

// ---------- tiny DOM helpers -------------------------------------------------

function el<K extends keyof HTMLElementTagNameMap>(
	tag: K,
	className?: string,
	html?: string,
): HTMLElementTagNameMap[K] {
	const node = document.createElement(tag);
	if (className) node.className = className;
	if (html !== undefined) node.innerHTML = html;
	return node;
}

function escapeHtml(s: string): string {
	return s
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

// Long values (a 2048-bit modulus is ~617 digits) are truncated for display
// with a copy button that yields the full value.
function copyChip(value: string, label = 'Copy'): string {
	return `<button type="button" class="copy-chip" data-copy="${escapeHtml(value)}" aria-label="Copy ${escapeHtml(label)} to clipboard">📋 ${escapeHtml(label)}</button>`;
}

function shortValue(n: bigint): string {
	const s = n.toString();
	if (s.length <= 28) return `<span class="mono-scroll">${s}</span>`;
	const head = s.slice(0, 12);
	const tail = s.slice(-8);
	return `<span class="mono-scroll" title="${s.length} digits">${head}…${tail}</span> <span class="muted">(${s.length} digits)</span>${copyChip(s, 'value')}`;
}

function wireCopyButtons(root: HTMLElement): void {
	root.addEventListener('click', async (e) => {
		const target = (e.target as HTMLElement | null)?.closest<HTMLButtonElement>('.copy-chip');
		if (!target) return;
		try {
			await navigator.clipboard.writeText(target.dataset.copy ?? '');
			const original = target.innerHTML;
			target.innerHTML = '✓ Copied';
			target.classList.add('copy-chip--ok');
			setTimeout(() => {
				target.innerHTML = original;
				target.classList.remove('copy-chip--ok');
			}, 1400);
		} catch {
			target.innerHTML = '✗ Failed';
		}
	});
}

function presetOptions(selected: string): string {
	return PRESETS.map(
		(p) => `<option value="${p.id}"${p.id === selected ? ' selected' : ''}>${escapeHtml(p.label)}</option>`,
	).join('');
}

function threatStrip(protects: string[], doesNot: string[]): string {
	const yes = protects.map((t) => `<span class="threat-chip threat-chip--yes">✓ ${escapeHtml(t)}</span>`).join('');
	const no = doesNot.map((t) => `<span class="threat-chip threat-chip--no">✗ ${escapeHtml(t)}</span>`).join('');
	return `<div class="threat-strip" role="note" aria-label="Threat model for this section">${yes}${no}</div>`;
}

function toyBanner(detail: string): string {
	return `<div class="toy-banner" role="note"><span class="toy-banner-tag">Toy params</span><span>${detail}</span></div>`;
}

// Clamp a typed exponent into [1, p-2]; fall back if unparseable.
function parseExponent(raw: string, p: bigint, fallback: bigint): bigint {
	try {
		const n = BigInt(raw.trim());
		if (n < 1n) return 1n;
		if (n > p - 2n) return p - 2n;
		return n;
	} catch {
		return fallback;
	}
}

function defaultExponents(preset: DhPreset): { a: bigint; b: bigint } {
	if (preset.id === 'tiny') return { a: 6n, b: 15n };
	if (preset.id === 'small') return { a: 1751n, b: 998n };
	if (preset.id === 'medium') return { a: 524287n, b: 314159n };
	return { a: 123456789n, b: 987654321n };
}

// ---------- 1. hero / quick explanation -------------------------------------

function renderHero(): HTMLElement {
	const section = el('header', 'hero-panel');
	section.setAttribute('role', 'banner');
	const demo = diffieHellman(23n, 5n, 6n, 15n);
	section.innerHTML = `
		<p class="eyebrow">Crypto Lab · Key Exchange</p>
		<h1>Diffie–Hellman &amp; the Man in the Middle</h1>
		<p class="hero-text">
			Diffie–Hellman lets two strangers agree on a shared secret over a channel
			everyone can read. A <b>passive</b> eavesdropper who sees every message still
			can't compute that secret — that's the discrete-logarithm problem doing its job.
			But an <b>active</b> attacker who can <em>change</em> messages breaks it completely.
			This page lets you run the exchange, break it on toy numbers, watch a
			man-in-the-middle split it in two, and then fix it with a real signature.
		</p>
		<div class="hero-steps">
			<div class="hero-step">
				<b>1 · Public setup</b>
				<div class="mono-inline">p = 23, g = 5<br>(everyone knows these)</div>
			</div>
			<div class="hero-step">
				<b>2 · Secrets &amp; publics</b>
				<div class="mono-inline">Alice a=6 → A = 5⁶ mod 23 = ${demo.A}<br>Bob b=15 → B = 5¹⁵ mod 23 = ${demo.B}</div>
			</div>
			<div class="hero-step">
				<b>3 · Shared secret</b>
				<div class="mono-inline">Bᵃ = Aᵇ mod 23 = ${demo.sharedFromAlice}<br>same number, never sent</div>
			</div>
		</div>
		<p class="hero-text">
			The trick: <code>(gᵇ)ᵃ = (gᵃ)ᵇ = g<sup>ab</sup></code>. Alice and Bob each raise the
			other's public value to their own secret and land on <code>g<sup>ab</sup></code>.
			Eve sees <code>g</code>, <code>gᵃ</code> and <code>gᵇ</code> but recovering
			<code>a</code> or <code>b</code> means solving a discrete logarithm — easy here,
			hopeless at real sizes.
		</p>
	`;
	return section;
}

// ---------- 2. passive eavesdropper -----------------------------------------

function renderPassive(): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'passive';
	let preset = presetById('tiny');
	let { a, b } = defaultExponents(preset);

	section.innerHTML = `
		<p class="section-kicker">Part 2 · Passive attacker</p>
		<h2>Eve is watching — and it doesn't help her</h2>
		<p class="section-intro">
			Eve sees everything on the wire: <code>p</code>, <code>g</code>, Alice's
			<code>A</code> and Bob's <code>B</code>. To get the shared secret she'd need a
			private exponent — a discrete log. On these toy primes you can run that attack
			yourself and watch it succeed; then switch to a 2048-bit modulus and watch it
			become hopeless.
		</p>
		${threatStrip(['Passive eavesdropping (at real sizes)'], ['Active tampering — see Part 3'])}
		<div class="controls">
			<div class="field field--wide">
				<label for="p-preset">Group parameters</label>
				<select id="p-preset">${presetOptions(preset.id)}</select>
			</div>
			<div class="field">
				<label for="p-a">Alice secret a</label>
				<input id="p-a" inputmode="numeric" value="${a}">
			</div>
			<div class="field">
				<label for="p-b">Bob secret b</label>
				<input id="p-b" inputmode="numeric" value="${b}">
			</div>
			<button class="btn" id="p-run" type="button">Run exchange</button>
			<button class="btn btn--danger" id="p-break" type="button">Break it · recover a</button>
		</div>
		<div id="p-toy">${toyBanner(escapeHtml(preset.note))}</div>
		<div id="p-out" class="panel-card" style="margin-top:18px" aria-live="polite"></div>
	`;

	const selPreset = section.querySelector<HTMLSelectElement>('#p-preset')!;
	const inA = section.querySelector<HTMLInputElement>('#p-a')!;
	const inB = section.querySelector<HTMLInputElement>('#p-b')!;
	const out = section.querySelector<HTMLDivElement>('#p-out')!;
	const toy = section.querySelector<HTMLDivElement>('#p-toy')!;
	const breakBtn = section.querySelector<HTMLButtonElement>('#p-break')!;

	function syncPresetUI(): void {
		toy.innerHTML = toyBanner(escapeHtml(preset.note));
		breakBtn.disabled = !preset.breakable;
		breakBtn.title = preset.breakable
			? 'Recover Alice’s secret by discrete log'
			: 'Disabled: at 2048 bits this would need ~2¹⁰²³ steps';
	}

	function runExchange(): void {
		a = parseExponent(inA.value, preset.p, a);
		b = parseExponent(inB.value, preset.p, b);
		inA.value = a.toString();
		inB.value = b.toString();
		const r = diffieHellman(preset.p, preset.g, a, b);
		out.innerHTML = `
			<h3>On the wire (everything Eve sees)</h3>
			<dl class="kv">
				<dt>p (modulus)</dt><dd>${shortValue(r.p)}</dd>
				<dt>g (generator)</dt><dd>${r.g}</dd>
				<dt>A = gᵃ mod p</dt><dd>${shortValue(r.A)}</dd>
				<dt>B = gᵇ mod p</dt><dd>${shortValue(r.B)}</dd>
			</dl>
			<h3 style="margin-top:18px">Computed privately (never transmitted)</h3>
			<dl class="kv">
				<dt>Alice: Bᵃ mod p</dt><dd>${shortValue(r.sharedFromAlice)}</dd>
				<dt>Bob: Aᵇ mod p</dt><dd>${shortValue(r.sharedFromBob)}</dd>
			</dl>
			<p class="status ${r.agree ? 'status--ok' : 'status--alarm'}">
				${r.agree ? 'Both sides derived the same shared secret.' : 'Mismatch — parameters invalid.'}
			</p>
			<p class="muted" style="margin-top:6px">Eve has p, g, A and B — and no efficient way to turn them into that secret. Press “Break it” to see why “efficient” is doing the work in that sentence.</p>
		`;
	}

	function breakIt(): void {
		a = parseExponent(inA.value, preset.p, a);
		const A = modPow(preset.g, a, preset.p);
		const t0 = performance.now();
		const res = babyStepGiantStep(preset.g, A, preset.p, preset.p - 1n);
		const ms = (performance.now() - t0).toFixed(1);
		const recovered = res.x !== null && modPow(preset.g, res.x, preset.p) === A;
		const costRows = PRESETS.map((pr) => {
			const c = discreteLogCost(pr.p);
			const work = c.feasibleHere
				? `~${c.sqrtSteps.toString()} steps`
				: `~2^${Math.round(c.approxLog2Steps)} steps`;
			return `<tr class="${pr.id === preset.id ? 'is-current' : ''}"><td>${escapeHtml(pr.label.split(' — ')[0]!)}</td><td>${c.bits}-bit</td><td>${work}</td><td>${c.feasibleHere ? 'breakable here' : 'infeasible'}</td></tr>`;
		}).join('');

		out.innerHTML = `
			<h3>Discrete-log attack — baby-step giant-step</h3>
			${
				recovered && res.x !== null
					? `<p class="status status--alarm">Recovered Alice's secret: a = ${res.x.toString()} — in ${res.steps.toLocaleString()} group operations (${ms} ms).</p>
					   <p class="muted" style="margin-top:6px">The same algorithm found <code>a</code> with no inside knowledge: it solved <code>gᵃ ≡ A (mod p)</code> directly. Eve now computes the “shared” secret too.</p>`
					: `<p class="status status--info">This modulus is too large to break here: the attack would need about 2<sup>${Math.round(discreteLogCost(preset.p).approxLog2Steps)}</sup> steps, so it is left disabled. That gap — trivial vs astronomically infeasible — is the entire security of Diffie–Hellman.</p>`
			}
			<div class="table-scroll">
				<table class="cost-table">
					<thead><tr><th>Preset</th><th>Size</th><th>Break cost ≈ √p</th><th>Status</th></tr></thead>
					<tbody>${costRows}</tbody>
				</table>
			</div>
			<p class="muted" style="margin-top:10px">Cost scales with the square root of the modulus, so every extra bit roughly doubles the work. A 2048-bit group puts it past the reach of every computer that will ever exist — while the exchange itself stays a few multiplications.</p>
		`;
	}

	selPreset.addEventListener('change', () => {
		preset = presetById(selPreset.value);
		const d = defaultExponents(preset);
		a = d.a;
		b = d.b;
		inA.value = a.toString();
		inB.value = b.toString();
		syncPresetUI();
		runExchange();
	});
	section.querySelector<HTMLButtonElement>('#p-run')!.addEventListener('click', runExchange);
	breakBtn.addEventListener('click', breakIt);

	syncPresetUI();
	runExchange();
	return section;
}

// ---------- 3. active man-in-the-middle --------------------------------------

function renderMitm(): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'mitm';
	let preset = presetById('small');
	let { a, b } = defaultExponents(preset);
	let m1 = 333n;
	let m2 = 777n;

	section.innerHTML = `
		<p class="section-kicker">Part 3 · Active attacker (the main event)</p>
		<h2>Mallory in the middle</h2>
		<p class="section-intro">
			Plain Diffie–Hellman never checks <em>who</em> sent a public value. Mallory uses
			that: she cuts the wire and runs <b>two</b> separate exchanges — one with Alice
			(pretending to be Bob), one with Bob (pretending to be Alice). Both halves succeed.
			Alice and Bob each think they share one key; really they share two different keys,
			both with Mallory, who relays and reads everything between them.
		</p>
		${threatStrip([], ['Active man-in-the-middle — this is exactly what unauthenticated DH cannot stop'])}
		<div class="controls">
			<div class="field field--wide">
				<label for="m-preset">Group parameters</label>
				<select id="m-preset">${presetOptions(preset.id)}</select>
			</div>
			<div class="field"><label for="m-a">Alice a</label><input id="m-a" inputmode="numeric" value="${a}"></div>
			<div class="field"><label for="m-b">Bob b</label><input id="m-b" inputmode="numeric" value="${b}"></div>
			<div class="field"><label for="m-m1">Mallory ↔ Alice (m₁)</label><input id="m-m1" inputmode="numeric" value="${m1}"></div>
			<div class="field"><label for="m-m2">Mallory ↔ Bob (m₂)</label><input id="m-m2" inputmode="numeric" value="${m2}"></div>
			<button class="btn btn--danger" id="m-run" type="button">Run the attack</button>
		</div>
		<div id="m-toy">${toyBanner('Mallory needs no secret-breaking and no big computation — just the ability to alter messages. That is what makes the active attack so much stronger than eavesdropping.')}</div>
		<div id="m-out" aria-live="polite"></div>
	`;

	const selPreset = section.querySelector<HTMLSelectElement>('#m-preset')!;
	const inA = section.querySelector<HTMLInputElement>('#m-a')!;
	const inB = section.querySelector<HTMLInputElement>('#m-b')!;
	const inM1 = section.querySelector<HTMLInputElement>('#m-m1')!;
	const inM2 = section.querySelector<HTMLInputElement>('#m-m2')!;
	const out = section.querySelector<HTMLDivElement>('#m-out')!;

	function run(): void {
		a = parseExponent(inA.value, preset.p, a);
		b = parseExponent(inB.value, preset.p, b);
		m1 = parseExponent(inM1.value, preset.p, m1);
		m2 = parseExponent(inM2.value, preset.p, m2);
		inA.value = a.toString();
		inB.value = b.toString();
		inM1.value = m1.toString();
		inM2.value = m2.toString();

		const r = mitm(preset.p, preset.g, a, b, m1, m2);
		const split = !r.aliceAndBobShareKey;

		out.innerHTML = `
			<div class="wire">
				<div class="party party--alice">
					<h4>👩 Alice</h4>
					<span class="role">thinks she's talking to Bob</span>
					<dl class="kv">
						<dt>sends A</dt><dd>${shortValue(r.A)}</dd>
						<dt>receives</dt><dd>${shortValue(r.M1)} <span class="muted">(Mallory's, not Bob's)</span></dd>
						<dt>her key M₁ᵃ</dt><dd>${shortValue(r.aliceKey)}</dd>
					</dl>
				</div>
				<div class="wire-gap wire-gap--cut"><span class="arrow">⇢✂</span>cut</div>
				<div class="party party--mallory">
					<h4>🦹 Mallory</h4>
					<span class="role">relays both sides, reads everything</span>
					<dl class="kv">
						<dt>Aᵐ¹ (= Alice's)</dt><dd>${shortValue(r.malloryKeyWithAlice)}</dd>
						<dt>Bᵐ² (= Bob's)</dt><dd>${shortValue(r.malloryKeyWithBob)}</dd>
					</dl>
				</div>
				<div class="wire-gap wire-gap--cut"><span class="arrow">✂⇠</span>cut</div>
				<div class="party party--bob">
					<h4>🧑 Bob</h4>
					<span class="role">thinks he's talking to Alice</span>
					<dl class="kv">
						<dt>sends B</dt><dd>${shortValue(r.B)}</dd>
						<dt>receives</dt><dd>${shortValue(r.M2)} <span class="muted">(Mallory's, not Alice's)</span></dd>
						<dt>his key M₂ᵇ</dt><dd>${shortValue(r.bobKey)}</dd>
					</dl>
				</div>
			</div>

			<ol class="steps">
				<li><span class="n">1</span><span>Alice sends <code>A = gᵃ</code> toward Bob. Mallory intercepts it — Bob never sees it.</span></li>
				<li class="is-cut"><span class="n">2</span><span>Mallory sends Alice her own <code>M₁ = g<sup>m₁</sup></code>, pretending it's Bob's value.</span></li>
				<li><span class="n">3</span><span>Bob sends <code>B = gᵇ</code> toward Alice. Mallory intercepts that too.</span></li>
				<li class="is-cut"><span class="n">4</span><span>Mallory sends Bob her own <code>M₂ = g<sup>m₂</sup></code>, pretending it's Alice's value.</span></li>
				<li><span class="n">5</span><span>Alice computes <code>M₁ᵃ</code>; Mallory computes <code>A<sup>m₁</sup></code> — the same number. They share a key.</span></li>
				<li><span class="n">6</span><span>Bob computes <code>M₂ᵇ</code>; Mallory computes <code>B<sup>m₂</sup></code> — the same number. They share a different key.</span></li>
			</ol>

			<div class="key-grid">
				<div class="key-card ${split ? 'key-card--alarm' : 'key-card--ok'}">
					<div class="key-label">👩 Alice's "shared" key</div>
					<div class="key-value">${shortValue(r.aliceKey)}</div>
				</div>
				<div class="key-card ${split ? 'key-card--alarm' : 'key-card--ok'}">
					<div class="key-label">🧑 Bob's "shared" key</div>
					<div class="key-value">${shortValue(r.bobKey)}</div>
				</div>
			</div>

			<p class="status ${split ? 'status--alarm' : 'status--info'}">
				${
					split
						? `Attack succeeded: Alice's key ≠ Bob's key. There is no Alice–Bob secret — only an Alice–Mallory key and a Bob–Mallory key. Mallory decrypts, reads, optionally edits, and re-encrypts every message. Neither side can tell.`
						: `With these exponents the two keys happened to collide; change m₁ or m₂ to see them split.`
				}
			</p>
			<p class="muted" style="margin-top:6px">Notice what Mallory did <em>not</em> need: she never solved a discrete log or broke any math. She only needed to sit on the wire and swap two values. Authentication — not bigger numbers — is what stops her (Part 4).</p>
		`;
	}

	selPreset.addEventListener('change', () => {
		preset = presetById(selPreset.value);
		const d = defaultExponents(preset);
		a = d.a;
		b = d.b;
		inA.value = a.toString();
		inB.value = b.toString();
		run();
	});
	section.querySelector<HTMLButtonElement>('#m-run')!.addEventListener('click', run);

	run();
	return section;
}

// ---------- 4. what breaks: unauthenticated vs signed DH ---------------------

function renderCompare(): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'fix';
	section.innerHTML = `
		<p class="section-kicker">Part 4 · What breaks, and the fix</p>
		<h2>Sign the handshake</h2>
		<p class="section-intro">
			The man-in-the-middle works only because nobody checks who sent a public value.
			Bind each DH value to an identity with a signature and Mallory's substitution stops
			verifying. Below is a <b>real</b> P-256 ECDSA signature via WebCrypto — Alice signs
			her DH value, Bob checks it. Run it clean, then run it with Mallory tampering.
		</p>
		<div class="compare">
			<div class="compare-col compare-col--broken">
				<h3>Unauthenticated DH</h3>
				<p class="status status--alarm">Mallory wins</p>
				<ul>
					<li>Public values arrive with no proof of origin.</li>
					<li>Mallory swaps them; both verifications are vacuous because there are none.</li>
					<li>Alice and Bob finish with keys shared with the attacker.</li>
				</ul>
			</div>
			<div class="compare-col compare-col--safe">
				<h3>Authenticated DH (signed)</h3>
				<p class="status status--ok">Mallory is caught</p>
				<ul>
					<li>Alice signs her DH value with a long-term identity key.</li>
					<li>Bob verifies against Alice's authentic public key before using it.</li>
					<li>A swapped value no longer matches the signature → abort, fail closed.</li>
				</ul>
			</div>
		</div>

		<div class="controls">
			<button class="btn" id="f-clean" type="button">Run signed exchange (honest)</button>
			<button class="btn btn--danger" id="f-tamper" type="button">Run signed exchange (Mallory tampers)</button>
		</div>
		<div id="f-out" class="panel-card" style="margin-top:18px" aria-live="polite">
			<p class="muted">Press a button to generate a fresh ECDSA identity for Alice and run a real signed delivery.</p>
		</div>

		<h3 style="margin-top:24px">How real protocols authenticate DH</h3>
		<dl class="kv">
			<dt>TLS 1.3</dt><dd class="muted" style="font-family:var(--sans)">The server signs the handshake transcript (which includes its ephemeral key share) with its certificate key; the client verifies against the cert chain. SIGMA-style "sign-and-MAC".</dd>
			<dt>Signal (X3DH)</dt><dd class="muted" style="font-family:var(--sans)">Identity keys sign the signed-prekey; the long-term identity binds every ephemeral DH so a swapped prekey is detected.</dd>
			<dt>SSH</dt><dd class="muted" style="font-family:var(--sans)">The server signs the exchange hash with its host key; the famous "host key fingerprint" prompt is you authenticating that key out of band.</dd>
		</dl>
		<div class="related">
			<a href="https://systemslibrarian.github.io/crypto-lab-key-exchange/" target="_blank" rel="noopener">Key Exchange Evolution →</a>
			<a href="https://systemslibrarian.github.io/crypto-lab-x3dh-wire/" target="_blank" rel="noopener">X3DH Wire →</a>
			<a href="https://systemslibrarian.github.io/crypto-lab-noise-pipe/" target="_blank" rel="noopener">Noise Pipe →</a>
			<a href="https://systemslibrarian.github.io/crypto-lab-tls-handshake/" target="_blank" rel="noopener">TLS Handshake →</a>
			<a href="https://systemslibrarian.github.io/crypto-lab-opaque-gate/" target="_blank" rel="noopener">OPAQUE Gate →</a>
		</div>
	`;

	const out = section.querySelector<HTMLDivElement>('#f-out')!;

	async function runSigned(tamper: boolean): Promise<void> {
		out.innerHTML = `<p class="muted">Generating ECDSA identity and signing…</p>`;
		const p = 2357n;
		const g = 2n;
		const aliceValue = modPow(g, 1751n, p); // Alice's real A = g^a
		const malloryValue = modPow(g, 333n, p); // what Mallory would substitute
		const delivered = tamper ? malloryValue : aliceValue;

		const alice = await generateIdentity('Alice');
		const res = await authenticatedDeliver(alice, aliceValue, delivered);

		out.innerHTML = `
			<h3>${tamper ? '🦹 Mallory tampers with the signed value' : '✅ Honest signed delivery'}</h3>
			<dl class="kv">
				<dt>Value Alice signed</dt><dd>${shortValue(res.signedValue)}</dd>
				<dt>Value Bob received</dt><dd>${shortValue(res.deliveredValue)}${res.tampered ? ' <span class="muted">(swapped by Mallory)</span>' : ''}</dd>
				<dt>Signature scheme</dt><dd style="font-family:var(--sans)">ECDSA · P-256 · SHA-256 (WebCrypto)</dd>
				<dt>Bob's verify()</dt><dd>${res.verified ? 'true' : 'false'}</dd>
				<dt>Bob proceeds?</dt><dd>${res.accepted ? 'yes' : 'no — aborted'}</dd>
			</dl>
			<p class="status ${res.accepted ? 'status--ok' : res.mitmDetected ? 'status--ok' : 'status--alarm'}">
				${
					res.mitmDetected
						? 'Signature check failed on the swapped value — the man-in-the-middle is detected and the handshake aborts. The same swap that broke Part 3 is now caught.'
						: res.accepted
							? 'Signature verifies — Bob accepts Alice’s authentic value and the exchange continues safely.'
							: 'Unexpected state.'
				}
			</p>
			<p class="muted" style="margin-top:6px">${tamper ? 'Mallory can still copy Alice’s real value, but then she doesn’t control the key. To control it she must change the value — and she can’t forge Alice’s signature over the new one.' : 'Now try the tamper button: the signature is over Alice’s value, so any substitution fails to verify.'}</p>
		`;
	}

	section.querySelector<HTMLButtonElement>('#f-clean')!.addEventListener('click', () => void runSigned(false));
	section.querySelector<HTMLButtonElement>('#f-tamper')!.addEventListener('click', () => void runSigned(true));
	return section;
}

// ---------- 5. key takeaways -------------------------------------------------

function renderTakeaways(): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'takeaways';
	section.innerHTML = `
		<p class="section-kicker">Part 5 · Key takeaways</p>
		<h2>When Diffie–Hellman is safe — and when it isn't</h2>
		<ul class="takeaways">
			<li><b>Passive ≠ active.</b> DH defeats an eavesdropper by resting on the discrete-log problem. It does <em>nothing</em> against an attacker who can modify messages.</li>
			<li><b>The math wasn't broken.</b> The man-in-the-middle never solved a discrete log. He exploited a missing check: "is this public value really from the person I think?"</li>
			<li><b>Unauthenticated DH gives two keys, not one.</b> After the attack Alice and Bob each share a key with Mallory and none with each other — and the protocol gives them no way to notice.</li>
			<li><b>Authentication is the fix, not bigger numbers.</b> Signatures, certificates, or a password-authenticated exchange (PAKE) bind each DH value to an identity, so a swap fails to verify.</li>
			<li><b>This is why real protocols sign the handshake.</b> TLS 1.3, the Signal protocol, SSH, and WireGuard all layer authentication on top of (EC)DH for exactly this reason.</li>
			<li><b>Never roll your own.</b> Use vetted libraries and standard, authenticated key-exchange protocols. The toy primes here exist only so the attack fits in a browser tab.</li>
		</ul>
		${threatStrip(['Passive eavesdropper (real sizes)', 'Active MITM — once authenticated'], ['Active MITM — while unauthenticated'])}
	`;
	return section;
}

// ---------- mount ------------------------------------------------------------

export function mountApp(root: HTMLElement): void {
	const shell = el('div', 'page-shell');
	shell.append(
		renderHero(),
		renderPassive(),
		renderMitm(),
		renderCompare(),
		renderTakeaways(),
	);
	root.append(shell);
	wireCopyButtons(root);
}
