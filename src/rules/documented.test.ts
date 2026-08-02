/**
 * RULES.md is the spec a reader checks the code against, so a rule id in it
 * that does not exist is the cheapest possible way to look dishonest — one
 * grep and the document is falsified.
 *
 * It had drifted: the table listed `sg.ssh-open-to-world`, `sg.rdp-open-to-world`,
 * `sg.all-ports-open-to-world` and `sg.sensitive-port-open-to-world`, none of
 * which were ever emitted. SSH and RDP are the first two entries of
 * SENSITIVE_PORTS and both report `sg.sensitive-port-open`.
 *
 * Both directions are pinned, because each catches a different mistake:
 * documenting a rule that does not exist, and shipping one nobody wrote down.
 */

import { describe, expect, it } from 'vitest';

// Loaded through vite's `?raw` rather than node:fs on purpose: `types` is
// empty in tsconfig.json, so `node:fs` is a compile error, and that is how
// "reads no file" stays enforced rather than merely promised.
import RULES_MD from '../../RULES.md?raw';

import { BEDROCK_RULE_IDS } from './bedrock';
import { COST_RULE_IDS } from './cost';
import { SG_RULE_IDS } from './securityGroups';

const IMPLEMENTED: ReadonlySet<string> = new Set([
  ...Object.values(SG_RULE_IDS),
  ...Object.values(COST_RULE_IDS),
  ...Object.values(BEDROCK_RULE_IDS),
]);

/**
 * Every backticked token in RULES.md that is shaped like one of our rule ids.
 * Anchored on the four real prefixes rather than "anything with a dot", so
 * `0.0.0.0/0`, `IpProtocol: "-1"` and `aws:dlm:*` are not mistaken for rules.
 */
function documentedRuleIds(): string[] {
  const found = new Set<string>();
  for (const [, token] of RULES_MD.matchAll(/`((?:sg|cost|ebs|ai)\.[a-z0-9-]+)`/g)) {
    found.add(token);
  }
  return [...found].sort();
}

describe('RULES.md and the code agree', () => {
  it('documents no rule that does not exist', () => {
    const ghosts = documentedRuleIds().filter((id) => !IMPLEMENTED.has(id));
    expect(ghosts).toEqual([]);
  });

  it('documents every rule that does exist', () => {
    const documented = new Set(documentedRuleIds());
    const undocumented = [...IMPLEMENTED].filter((id) => !documented.has(id)).sort();
    expect(undocumented).toEqual([]);
  });

  it('actually found rule ids to check', () => {
    // Anti-vacuity: if the regex stopped matching, both assertions above pass
    // while checking nothing at all.
    expect(documentedRuleIds().length).toBe(IMPLEMENTED.size);
    expect(IMPLEMENTED.size).toBeGreaterThan(10);
  });
});
