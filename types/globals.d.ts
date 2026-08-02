/**
 * The only ambient declaration in the repo.
 *
 * `lib` is ES2022 and nothing else, and `types` is empty — no DOM, no
 * @types/node — so `fetch`, `XMLHttpRequest`, `require` and `fs` are compile
 * errors rather than things we promise not to use. That is what makes "opens
 * no socket, reads no file" checkable instead of asserted.
 *
 * `performance.now()` is used by two tests to assert the analysis is fast on a
 * large paste. It is standard in Node >= 16 and every browser; declared
 * narrowly here rather than by widening `lib`.
 */
declare const performance: { now(): number };

/** vite's `?raw` suffix, used by the RULES.md drift guard. */
declare module '*?raw' {
  const contents: string;
  export default contents;
}
