import { defineConfig } from 'vitest/config';

// Standalone config: this package is published on its own (MIT) and must be
// testable without the site's build. `environment: 'node'` is deliberate —
// the rules are pure functions with no DOM, and proving that they never need
// one is part of the "runs anywhere, touches nothing" claim.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
