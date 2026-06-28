// Deterministic unit tests for src/engine.ts.
//
// Run under Node's built-in test runner with --experimental-strip-types so the
// .ts engine imports directly. The crypto math is deterministic; the ECDSA
// authentication path is tested for behaviour (verify passes clean, fails on
// tamper), not for specific signature bytes.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
	modPow,
	mod,
	isqrt,
	isProbablePrime,
	diffieHellman,
	babyStepGiantStep,
	discreteLogCost,
	mitm,
	generateIdentity,
	authenticatedDeliver,
	PRESETS,
	presetById,
} from '../src/engine.ts';

test('modPow: known values and identities', () => {
	assert.equal(modPow(5n, 0n, 23n), 1n);
	assert.equal(modPow(5n, 6n, 23n), 8n);
	assert.equal(modPow(5n, 15n, 23n), 19n);
	assert.equal(modPow(2n, 10n, 1024n), 0n);
	assert.equal(modPow(123n, 1n, 7n), 123n % 7n);
});

test('mod: always non-negative', () => {
	assert.equal(mod(-1n, 23n), 22n);
	assert.equal(mod(-25n, 23n), 21n);
});

test('isqrt: floor of square root', () => {
	assert.equal(isqrt(0n), 0n);
	assert.equal(isqrt(1n), 1n);
	assert.equal(isqrt(15n), 3n);
	assert.equal(isqrt(16n), 4n);
	assert.equal(isqrt(2356n), 48n); // 48^2 = 2304, 49^2 = 2401
});

test('isProbablePrime: small primes and composites', () => {
	for (const p of [2n, 3n, 5n, 23n, 2357n, 1000003n]) {
		assert.equal(isProbablePrime(p), true, `${p} should be prime`);
	}
	for (const c of [1n, 4n, 9n, 21n, 2356n, 1000004n]) {
		assert.equal(isProbablePrime(c), false, `${c} should be composite`);
	}
});

test('diffieHellman: classic textbook example agrees', () => {
	// p = 23, g = 5, a = 6, b = 15 — the canonical worked example.
	const r = diffieHellman(23n, 5n, 6n, 15n);
	assert.equal(r.A, 8n);
	assert.equal(r.B, 19n);
	assert.equal(r.sharedFromAlice, 2n);
	assert.equal(r.sharedFromBob, 2n);
	assert.equal(r.agree, true);
});

test('diffieHellman: many instances all agree', () => {
	for (let a = 1n; a < 22n; a++) {
		for (let b = 1n; b < 22n; b++) {
			const r = diffieHellman(23n, 5n, a, b);
			assert.equal(r.agree, true, `a=${a} b=${b}`);
		}
	}
});

test('diffieHellman: agrees at 2048-bit production size', () => {
	const { p, g } = presetById('real');
	const r = diffieHellman(p, g, 123456789n, 987654321n);
	assert.equal(r.agree, true);
	assert.equal(r.sharedFromAlice, r.sharedFromBob);
	assert.notEqual(r.sharedFromAlice, 1n); // sanity: a real shared value
});

test('babyStepGiantStep: recovers the exponent on a primitive root', () => {
	// 5 is a primitive root mod 23, so x is unique in [0, 22) and equals a.
	for (const a of [1n, 6n, 9n, 15n, 21n]) {
		const A = modPow(5n, a, 23n);
		const res = babyStepGiantStep(5n, A, 23n, 22n);
		assert.notEqual(res.x, null);
		assert.equal(res.x, a, `should recover a=${a}`);
		assert.equal(modPow(5n, res.x, 23n), A);
	}
});

test('babyStepGiantStep: recovers on a 20-bit prime and reports work', () => {
	const a = 524287n;
	const A = modPow(2n, a, 1000003n);
	const res = babyStepGiantStep(2n, A, 1000003n, 1000002n);
	assert.notEqual(res.x, null);
	assert.equal(modPow(2n, res.x, 1000003n), A); // reproduces Alice's public value
	assert.ok(res.steps > 0 && res.steps < 5000, `~sqrt(p) steps, got ${res.steps}`);
	assert.equal(res.cappedAt, null);
});

test('babyStepGiantStep: refuses 2048-bit, reporting the cap not a hang', () => {
	const { p, g } = presetById('real');
	const A = modPow(g, 42n, p);
	const res = babyStepGiantStep(g, A, p, p - 1n);
	assert.equal(res.x, null);
	assert.notEqual(res.cappedAt, null); // bailed out, did not attempt 2^1023 steps
});

test('discreteLogCost: tiny is feasible, 2048-bit is not', () => {
	assert.equal(discreteLogCost(23n).feasibleHere, true);
	const real = discreteLogCost(presetById('real').p);
	assert.equal(real.feasibleHere, false);
	assert.equal(real.bits, 2048);
	assert.ok(real.approxLog2Steps > 1000); // ~2^1023 work
});

test('mitm: Alice and Bob end with DIFFERENT keys, each shared with Mallory', () => {
	const r = mitm(2357n, 2n, 1751n, 998n, 333n, 777n);
	// Each side genuinely agrees with Mallory...
	assert.equal(r.aliceSideAgrees, true);
	assert.equal(r.bobSideAgrees, true);
	assert.equal(r.aliceKey, r.malloryKeyWithAlice);
	assert.equal(r.bobKey, r.malloryKeyWithBob);
	// ...but Alice and Bob do NOT share a key. That is the whole attack.
	assert.equal(r.aliceAndBobShareKey, false);
	assert.notEqual(r.aliceKey, r.bobKey);
});

test('mitm: the substituted values are Mallory’s, not the real ones', () => {
	const r = mitm(23n, 5n, 6n, 15n, 4n, 7n);
	assert.equal(r.M1, modPow(5n, 4n, 23n)); // what Alice receives
	assert.equal(r.M2, modPow(5n, 7n, 23n)); // what Bob receives
	assert.notEqual(r.M1, r.B); // Alice never sees Bob's real value
	assert.notEqual(r.M2, r.A); // Bob never sees Alice's real value
});

test('authenticatedDeliver: clean exchange verifies and is accepted', async () => {
	const alice = await generateIdentity('Alice');
	const A = modPow(5n, 6n, 23n);
	const res = await authenticatedDeliver(alice, A, A); // no tampering
	assert.equal(res.tampered, false);
	assert.equal(res.verified, true);
	assert.equal(res.accepted, true);
	assert.equal(res.mitmDetected, false);
});

test('authenticatedDeliver: a tampered value fails closed (MITM detected)', async () => {
	const alice = await generateIdentity('Alice');
	const A = modPow(2n, 1751n, 2357n);
	const malloryValue = modPow(2n, 333n, 2357n); // Mallory's substitute
	const res = await authenticatedDeliver(alice, A, malloryValue);
	assert.equal(res.tampered, true);
	assert.equal(res.verified, false); // signature was over A, not Mallory's value
	assert.equal(res.accepted, false); // INVARIANT: never proceed unverified
	assert.equal(res.mitmDetected, true);
});

test('PRESETS: every breakable preset uses a real prime; real group is 2048-bit', () => {
	for (const preset of PRESETS) {
		assert.equal(isProbablePrime(preset.p), true, `${preset.id} p must be prime`);
		assert.equal(preset.breakable, discreteLogCost(preset.p).feasibleHere, preset.id);
	}
	assert.equal(discreteLogCost(presetById('real').p).bits, 2048);
});
