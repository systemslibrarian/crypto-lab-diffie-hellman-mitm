import './style.css';
import './extra.css';
import { diffieHellman, babyStepGiantStep, mitm, modPow } from './engine.ts';
import { mountApp } from './ui.ts';

// Dev-only self-test. Keeps the deployed build quiet but shouts in the console
// on a regression while developing.
if (import.meta.env.DEV) {
	console.group('crypto-lab-diffie-hellman-mitm: engine self-test');
	const dh = diffieHellman(23n, 5n, 6n, 15n);
	console.log('DH(23,5,6,15) — agree:', dh.agree, '· shared:', dh.sharedFromAlice.toString());
	const A = modPow(5n, 6n, 23n);
	const broken = babyStepGiantStep(5n, A, 23n, 22n);
	console.log('discrete-log recovered a =', broken.x?.toString(), '(real a = 6)');
	const m = mitm(2357n, 2n, 1751n, 998n, 333n, 777n);
	console.log('MITM — Alice key === Bob key?', m.aliceAndBobShareKey, '(should be false)');
	console.groupEnd();
}

mountApp(document.querySelector<HTMLDivElement>('#app')!);
