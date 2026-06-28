// engine.ts — Diffie–Hellman & the man in the middle.
//
// Everything that is the teaching subject is hand-rolled and inspectable:
//   1. Diffie–Hellman over Z_p* — real modular exponentiation in BigInt.
//   2. A *working* passive attack — baby-step giant-step discrete log that
//      actually recovers Alice's secret exponent on toy primes, and reports
//      how many group operations it took so the cost curve is concrete.
//   3. The active man-in-the-middle — Mallory runs two independent DH
//      exchanges (one with Alice, one with Bob) and ends up holding two
//      different keys while Alice and Bob each believe they share one.
//   4. The fix — authenticated DH using REAL WebCrypto ECDSA (P-256)
//      signatures over the ephemeral public values. When Mallory substitutes
//      a value the signature no longer verifies and the exchange fails closed.
//
// Toy primes are intentional: they are the only reason the discrete-log break
// can run in your browser. Real DH uses 2048–4096-bit safe primes (see
// MODP_2048). None of this is for production — use a vetted library.

// ---------- modular arithmetic (BigInt) --------------------------------------

export function mod(a: bigint, m: bigint): bigint {
	return ((a % m) + m) % m;
}

// Square-and-multiply modular exponentiation. The single primitive every part
// of this demo is built on; small enough to read top to bottom.
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
	if (m === 1n) return 0n;
	let result = 1n;
	let b = mod(base, m);
	let e = exp;
	while (e > 0n) {
		if (e & 1n) result = (result * b) % m;
		e >>= 1n;
		b = (b * b) % m;
	}
	return result;
}

// Integer square root (BigInt) — used to size the baby-step giant-step table.
export function isqrt(n: bigint): bigint {
	if (n < 0n) throw new Error('isqrt of negative');
	if (n < 2n) return n;
	let x = n;
	let y = (x + 1n) >> 1n;
	while (y < x) {
		x = y;
		y = (x + n / x) >> 1n;
	}
	return x;
}

// Deterministic-enough Miller–Rabin for the small/medium primes a user can
// type here. Used only to validate input ("is p actually prime?"), never as a
// security primitive.
export function isProbablePrime(n: bigint): boolean {
	if (n < 2n) return false;
	for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
		if (n === p) return true;
		if (n % p === 0n) return false;
	}
	let d = n - 1n;
	let r = 0n;
	while ((d & 1n) === 0n) {
		d >>= 1n;
		r += 1n;
	}
	for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
		if (a >= n) continue;
		let x = modPow(a, d, n);
		if (x === 1n || x === n - 1n) continue;
		let composite = true;
		for (let i = 0n; i < r - 1n; i++) {
			x = (x * x) % n;
			if (x === n - 1n) {
				composite = false;
				break;
			}
		}
		if (composite) return false;
	}
	return true;
}

// ---------- Diffie–Hellman ---------------------------------------------------

export interface DhResult {
	p: bigint;
	g: bigint;
	a: bigint; // Alice's private exponent
	b: bigint; // Bob's private exponent
	A: bigint; // Alice's public value: g^a mod p
	B: bigint; // Bob's public value:   g^b mod p
	sharedFromAlice: bigint; // B^a mod p
	sharedFromBob: bigint; // A^b mod p
	agree: boolean;
}

export function diffieHellman(p: bigint, g: bigint, a: bigint, b: bigint): DhResult {
	const A = modPow(g, a, p);
	const B = modPow(g, b, p);
	const sharedFromAlice = modPow(B, a, p);
	const sharedFromBob = modPow(A, b, p);
	return {
		p,
		g,
		a,
		b,
		A,
		B,
		sharedFromAlice,
		sharedFromBob,
		agree: sharedFromAlice === sharedFromBob,
	};
}

// ---------- passive attack: discrete log -------------------------------------

export interface DlogResult {
	// The recovered exponent x with g^x ≡ h (mod p), or null if the search was
	// capped before finding one (i.e. the parameters are too big to break here).
	x: bigint | null;
	steps: number; // group operations actually performed
	cappedAt: number | null; // non-null if we stopped early to stay responsive
}

// Hard ceiling so a careless "Break it" on a large prime can never hang the
// tab. ~3M steps is well under a second and far past any toy prime here.
export const DLOG_STEP_CAP = 3_000_000;

// Baby-step giant-step: solve g^x ≡ h (mod p) for x in [0, order).
// Time and memory are ~sqrt(order) — the square-root speedup that still leaves
// real DH (order ~2^2047) completely out of reach. This is a genuine attack;
// it returns the real exponent, not a lookup of a value we already knew.
export function babyStepGiantStep(
	g: bigint,
	h: bigint,
	p: bigint,
	order: bigint,
): DlogResult {
	const m = isqrt(order) + 1n;
	// Refuse to even build the table if it would blow the cap — report the cost.
	if (m > BigInt(DLOG_STEP_CAP)) {
		return { x: null, steps: 0, cappedAt: DLOG_STEP_CAP };
	}
	let steps = 0;
	// Baby steps: table of g^j -> j for j in [0, m).
	const table = new Map<string, bigint>();
	let e = 1n;
	for (let j = 0n; j < m; j++) {
		const key = e.toString();
		if (!table.has(key)) table.set(key, j);
		e = (e * g) % p;
		steps++;
	}
	// Giant steps: factor = g^(-m). Walk h * factor^i and look it up.
	const factor = modPow(g, mod(-m, order === 0n ? p - 1n : order), p);
	let gamma = mod(h, p);
	for (let i = 0n; i < m; i++) {
		const hit = table.get(gamma.toString());
		if (hit !== undefined) {
			const x = mod(i * m + hit, order);
			return { x, steps, cappedAt: null };
		}
		gamma = (gamma * factor) % p;
		steps++;
		if (steps > DLOG_STEP_CAP) {
			return { x: null, steps, cappedAt: DLOG_STEP_CAP };
		}
	}
	return { x: null, steps, cappedAt: null };
}

// Honest cost estimate for parameters too large to actually break, so the UI
// can contrast "467 → instant" with "2048-bit → heat death of the universe".
export interface DlogCost {
	bits: number; // size of the modulus in bits
	sqrtSteps: bigint; // ~sqrt(order): the BSGS work factor
	approxLog2Steps: number; // log2 of that, for human-scale comparison
	feasibleHere: boolean; // can we run it under the step cap?
}

export function discreteLogCost(p: bigint): DlogCost {
	const order = p - 1n;
	const sqrtSteps = isqrt(order) + 1n;
	const bits = p.toString(2).length;
	const approxLog2Steps = bits > 1 ? (bits - 1) / 2 : 0;
	return {
		bits,
		sqrtSteps,
		approxLog2Steps,
		feasibleHere: sqrtSteps <= BigInt(DLOG_STEP_CAP),
	};
}

// ---------- active attack: man in the middle ---------------------------------

// Mallory sits on the wire and runs two SEPARATE Diffie–Hellman exchanges:
// one facing Alice (exponent m1), one facing Bob (exponent m2). Alice and Bob
// never see each other's real public value — they see Mallory's. Each computes
// a key that matches Mallory's, and the two keys differ. There is no point at
// which Alice and Bob share a secret; Mallory relays (and can read/alter)
// everything between them.
export interface MitmResult {
	p: bigint;
	g: bigint;
	a: bigint; // Alice's private exponent
	b: bigint; // Bob's private exponent
	m1: bigint; // Mallory's exponent facing Alice
	m2: bigint; // Mallory's exponent facing Bob
	A: bigint; // Alice's true public value (intercepted, never reaches Bob)
	B: bigint; // Bob's true public value (intercepted, never reaches Alice)
	M1: bigint; // g^m1 — what Mallory sends to Alice posing as Bob
	M2: bigint; // g^m2 — what Mallory sends to Bob posing as Alice
	aliceKey: bigint; // M1^a — what Alice thinks is the Alice–Bob key
	bobKey: bigint; // M2^b — what Bob thinks is the Alice–Bob key
	malloryKeyWithAlice: bigint; // A^m1 — equals aliceKey
	malloryKeyWithBob: bigint; // B^m2 — equals bobKey
	aliceSideAgrees: boolean; // aliceKey === malloryKeyWithAlice
	bobSideAgrees: boolean; // bobKey === malloryKeyWithBob
	aliceAndBobShareKey: boolean; // the lie the protocol cannot detect: false
}

export function mitm(
	p: bigint,
	g: bigint,
	a: bigint,
	b: bigint,
	m1: bigint,
	m2: bigint,
): MitmResult {
	const A = modPow(g, a, p);
	const B = modPow(g, b, p);
	const M1 = modPow(g, m1, p);
	const M2 = modPow(g, m2, p);
	const aliceKey = modPow(M1, a, p);
	const bobKey = modPow(M2, b, p);
	const malloryKeyWithAlice = modPow(A, m1, p);
	const malloryKeyWithBob = modPow(B, m2, p);
	return {
		p,
		g,
		a,
		b,
		m1,
		m2,
		A,
		B,
		M1,
		M2,
		aliceKey,
		bobKey,
		malloryKeyWithAlice,
		malloryKeyWithBob,
		aliceSideAgrees: aliceKey === malloryKeyWithAlice,
		bobSideAgrees: bobKey === malloryKeyWithBob,
		aliceAndBobShareKey: aliceKey === bobKey,
	};
}

// ---------- the fix: authenticated DH (real ECDSA over WebCrypto) ------------

// Real P-256 ECDSA via SubtleCrypto — not a stand-in. The signature does NOT
// cover a bare DH value; it covers the *handshake transcript*: the signer's
// identity plus BOTH ephemeral shares. This is what SIGMA / TLS 1.3 / SSH do,
// and it matters: signing only your own g^a (with the peer's share unbound)
// is open to identity-misbinding / unknown-key-share attacks, where a
// signature made in one session is replayed into another. Binding the peer's
// share into the signed transcript closes that. (Real SIGMA additionally MACs
// the transcript under the derived key; we keep the signature and call out the
// MAC in the UI rather than implement a full AKE.)

export interface IdentityKey {
	name: string;
	publicKey: CryptoKey; // the authentic verifying key (think: in a certificate)
	privateKey: CryptoKey; // the secret signing key
}

export async function generateIdentity(name: string): Promise<IdentityKey> {
	const pair = await crypto.subtle.generateKey(
		{ name: 'ECDSA', namedCurve: 'P-256' },
		false,
		['sign', 'verify'],
	);
	return { name, publicKey: pair.publicKey, privateKey: pair.privateKey };
}

// Canonical, unambiguous transcript encoding. Domain-separated and fully
// delimited so two different (signer, self, peer) triples can never collide on
// the same byte string.
export function transcriptBytes(signer: string, self: bigint, peer: bigint): Uint8Array {
	const msg = `DH-MITM/v1\nsigner=${signer}\nself=0x${self.toString(16)}\npeer=0x${peer.toString(16)}`;
	return new TextEncoder().encode(msg);
}

export interface AuthExchangeResult {
	tampered: boolean; // was a MITM substitution attempted?
	signerSelf: bigint; // the signer's own share, as bound into the signature
	signerPeer: bigint; // the peer share the signer bound in (the genuine one)
	deliveredSelf: bigint; // the signer's share as it reached the verifier
	verified: boolean; // did the verifier's signature check pass?
	mitmDetected: boolean; // tampered && !verified — the fail-closed win
	accepted: boolean; // does the verifier proceed? (only if verified)
}

// Alice signs the transcript (her identity + her share A + Bob's share B) and
// Bob verifies it against Alice's authentic public key BEFORE using her share.
// Bob reconstructs the transcript from what HE received. If Mallory swapped
// Alice's A for M2 in flight, Bob verifies over a transcript with `self=M2`,
// which Alice never signed — so the check fails and Bob aborts.
// Invariant: `accepted` can only be true when `verified` is true.
export async function authenticatedDeliver(
	alice: IdentityKey,
	aliceShare: bigint, // A = g^a — Alice's genuine share
	bobShare: bigint, // B = g^b — bound into the signed transcript
	deliveredAliceShare: bigint, // what reaches Bob (A normally, M2 under MITM)
): Promise<AuthExchangeResult> {
	const signature = await crypto.subtle.sign(
		{ name: 'ECDSA', hash: 'SHA-256' },
		alice.privateKey,
		transcriptBytes(alice.name, aliceShare, bobShare),
	);
	const tampered = deliveredAliceShare !== aliceShare;
	const verified = await crypto.subtle.verify(
		{ name: 'ECDSA', hash: 'SHA-256' },
		alice.publicKey,
		signature,
		transcriptBytes(alice.name, deliveredAliceShare, bobShare),
	);
	return {
		tampered,
		signerSelf: aliceShare,
		signerPeer: bobShare,
		deliveredSelf: deliveredAliceShare,
		verified,
		mitmDetected: tampered && !verified,
		// Fail closed: never proceed on an unverified transcript, no matter what.
		accepted: verified,
	};
}

// ---------- preset parameters ------------------------------------------------

export interface DhPreset {
	id: string;
	label: string;
	p: bigint;
	g: bigint;
	note: string;
	breakable: boolean; // can the discrete-log attack run under the cap?
}

// 2048-bit MODP group (RFC 3526, group 14) — a real-world DH modulus. Included
// so the demo can compute a real exchange at production size while showing that
// the same brute-force break is hopeless here. [extension] point: add group 15
// (3072-bit) or a 4096-bit modulus by appending to PRESETS.
const MODP_2048 = BigInt(
	'0x' +
		'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' +
		'020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' +
		'4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
		'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' +
		'98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' +
		'9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
		'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
		'3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',
);

export const PRESETS: DhPreset[] = [
	{
		id: 'tiny',
		label: 'Tiny — p = 23, g = 5',
		p: 23n,
		g: 5n,
		note: 'The classic textbook example. Small enough to follow every multiplication by hand.',
		breakable: true,
	},
	{
		id: 'small',
		label: 'Small — p = 2357, g = 2',
		p: 2357n,
		g: 2n,
		note: 'Handbook of Applied Cryptography §8.4. Still trivially breakable, but the numbers look "real".',
		breakable: true,
	},
	{
		id: 'medium',
		label: 'Medium — p = 1000003, g = 2',
		p: 1000003n,
		g: 2n,
		note: 'A 20-bit prime. The discrete-log break now visibly takes ~1000 steps instead of a handful.',
		breakable: true,
	},
	{
		id: 'real',
		label: 'Realistic — 2048-bit (RFC 3526 group 14)',
		p: MODP_2048,
		g: 2n,
		note: 'A real production DH modulus. The exchange still computes instantly; the brute-force break needs ~2^1023 steps and is left disabled.',
		breakable: false,
	},
];

export function presetById(id: string): DhPreset {
	const found = PRESETS.find((preset) => preset.id === id);
	if (!found) throw new Error(`unknown preset: ${id}`);
	return found;
}
