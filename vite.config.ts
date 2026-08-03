import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-diffie-hellman-mitm/',
  // Pin the preview port. Without this, `vite preview` binds its default 4173 —
  // a port a dozen labs in this fleet used to share. That made this lab both a
  // victim (a sibling already on 4173 would be scanned by our smoke/axe runs)
  // and a squatter (our preview would be scanned by theirs). It also keeps
  // scripts/smoke.mjs honest: it targets this port and tells you to reach it
  // with `npm run preview`.
  preview: { port: 4700, strictPort: true },
});
