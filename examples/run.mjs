// Runs the rules over the bundled sample paste and prints what comes back.
//
//   npm run example
//
// The sample is made-up data covering shapes a real account often lacks —
// IPv6-only exposure, a numeric IANA protocol, a policy-managed snapshot. To
// run it against your own account instead, replace EXAMPLE_PASTE with the
// output of any of the read-only commands listed in the README.

import { analyzeAll, describeMissing, EXAMPLE_PASTE } from '../dist/index.js';

const result = analyzeAll(EXAMPLE_PASTE, new Date());

const line = (n) => '─'.repeat(n);
const money = (f) => (f.cost ? `  ~$${f.cost.monthlyUsd.toFixed(2)}/month` : '');

console.log(`\nRead: ${result.recognized.map((r) => `${r.count} ${r.kind}`).join(', ')}`);
console.log(line(72));

console.log(`\nFINDINGS (${result.findings.length})\n`);
for (const f of result.findings) {
  // severity is null whenever the paste cannot support a grade — printed as
  // "ungraded" with the reason, rather than defaulted to something.
  const grade = f.severity ? f.severity.toUpperCase() : 'ungraded';
  console.log(`  [${grade}] ${f.title}${money(f)}`);
  console.log(`      ${f.resource} — ${f.evidence.detail}`);
  if (f.unknowable) console.log(`      can't grade: ${f.unknowable}`);
  console.log(`      fix: ${f.fix.cli}\n`);
}

if (result.notes.length) {
  console.log(`NOTES (${result.notes.length}) — worth seeing, not wrong\n`);
  for (const n of result.notes) console.log(`  · ${n.title} (${n.resource})`);
  console.log();
}

if (result.gaps.length) {
  console.log(`GAPS (${result.gaps.length}) — this input couldn't answer these\n`);
  for (const g of result.gaps) console.log(`  ? ${g.resource}: ${g.reason}`);
  console.log();
}

const missing = describeMissing(result);
if (missing.length) {
  console.log('NOT PASTED — commands that would add coverage\n');
  for (const m of missing) console.log(`  $ ${m.command}`);
  console.log();
}
