# crypto-lab-diffie-hellman-mitm

## What It Is

An interactive lesson on the **Diffie–Hellman key exchange** and the **man-in-the-middle attack** that breaks it when it is left unauthenticated. Diffie–Hellman solves a single problem: two parties who have never met agree on a shared secret over a channel anyone can read, using the hardness of the **discrete-logarithm problem** in the multiplicative group Z_p\*. Its security model is precise and narrow — it defeats a *passive* eavesdropper, but it provides **no authentication**, so an *active* attacker who can modify messages can run two separate exchanges and sit in the middle. Every number in the demo is real, hand-rolled BigInt modular arithmetic (no faked math), and the discrete-log break and the ECDSA-signed fix both actually run in your browser. The toy primes exist only so the attack is fast enough to watch; this is a teaching tool, not a library.

## When to Use It

- **Teaching why "secure key exchange" needs authentication** — the demo shows the math is fine and the *protocol* is what fails, which is the point students most often miss.
- **Explaining the passive-vs-active attacker distinction** — run the discrete-log break (passive, defeated at real sizes) right next to the MITM (active, defeated only by signatures) to make the contrast concrete.
- **Briefing engineers before they touch a handshake** — make it visceral that raw, unauthenticated (EC)DH must be wrapped in signatures, certificates, or a PAKE.
- **Showing the cost curve of discrete log** — the break runs in milliseconds on a 16-bit prime and is left disabled on a real 2048-bit group with a √p cost estimate, illustrating why bigger parameters stop the eavesdropper but never the man in the middle.
- **Do NOT use it as a crypto library** — the primes are deliberately tiny and breakable, and rolling your own key exchange is exactly the mistake the lesson warns against. In production use a vetted implementation of an authenticated protocol (TLS 1.3, the Signal protocol, SSH, Noise).

## Live Demo

**[systemslibrarian.github.io/crypto-lab-diffie-hellman-mitm](https://systemslibrarian.github.io/crypto-lab-diffie-hellman-mitm/)**

The page is one scrollable lesson in five parts. You can run a Diffie–Hellman exchange on four parameter sets (`p = 23` up to a real 2048-bit RFC 3526 group), press **Break it** to recover Alice's secret exponent with a baby-step giant-step discrete-log attack, switch on **Mallory** to watch an active man-in-the-middle give Alice and Bob two different keys, and run a **real WebCrypto ECDSA** signed exchange that catches the tamper and fails closed. Controls: parameter preset, the private exponents `a` and `b`, Mallory's two exponents `m₁`/`m₂`, and honest-vs-tampered signed-delivery buttons.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-diffie-hellman-mitm
cd crypto-lab-diffie-hellman-mitm
npm install
npm run dev
```

No environment variables, no API keys, no backend — everything runs client-side in the browser. `npm run build` type-checks and produces the static `dist/`; `npm test` runs the engine unit tests; `npm run verify` does both.

## Part of the Crypto-Lab Suite

> One of 60+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*
