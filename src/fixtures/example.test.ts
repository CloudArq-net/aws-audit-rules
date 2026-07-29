/**
 * The example doubles as a coverage check — it holds the shapes a real account
 * rarely has, so if a rule stops handling one of them these fail.
 */

import { describe, expect, it } from 'vitest';

import { analyzeAll } from '../analyze';
import { EXAMPLE_LABEL, EXAMPLE_PASTE } from './example';

const NOW = new Date('2026-07-28T00:00:00.000Z');
const run = () => analyzeAll(EXAMPLE_PASTE, NOW);

describe('the example is honest about being made up', () => {
  it('says so in its own label', () => {
    expect(EXAMPLE_LABEL).toMatch(/example|made-up/i);
    expect(EXAMPLE_LABEL).toMatch(/not a real/i);
  });

  it('uses only addresses reserved for documentation', () => {
    // RFC 5737 and RFC 3849 documentation ranges only.
    const publicish = EXAMPLE_PASTE.match(/"(?:CidrIp|PublicIp)":\s*"([^"]+)"/g) ?? [];
    for (const entry of publicish) {
      expect(entry).toMatch(/0\.0\.0\.0\/0|192\.0\.2\.|198\.51\.100\.|203\.0\.113\./);
    }
    expect(EXAMPLE_PASTE).not.toMatch(/2001:(?!db8)/i);
  });

  it('carries no real account id', () => {
    // AWS's own documentation placeholder.
    const twelveDigit = EXAMPLE_PASTE.match(/\b\d{12}\b/g) ?? [];
    for (const id of twelveDigit) expect(id).toBe('111111111111');
  });
});

describe('every command is read, from one paste', () => {
  it('recognises all six documents', () => {
    expect(run().recognized).toHaveLength(6);
  });

  it('parses cleanly — no separators, six documents back to back', () => {
    expect(run().parseErrors).toHaveLength(0);
    expect(run().unrecognized).toHaveLength(0);
  });
});

describe('it exercises the shapes a real account rarely has', () => {
  const ids = () => run().findings.map((f) => f.ruleId);

  it.each([
    ['IPv6-only exposure', /ipv6/i],
    ['an all-traffic rule', /all-traffic|all-ports/i],
    ['a sensitive port from the world', /sensitive-port|ssh|rdp/i],
    ['an unattached volume', /unattached-volume/i],
    ['gp2 that should be gp3', /gp3/i],
    ['an unassociated Elastic IP', /unattached-elastic-ip/i],
    ['a genuine orphan snapshot', /old-snapshot/i],
    ['backup retention', /backup-retention/i],
    ['Bedrock logging that records nothing', /metadata-only/i],
    ['an unencrypted volume', /unencrypted/i],
  ])('produces %s', (_label, pattern) => {
    expect(ids().some((id) => pattern.test(id))).toBe(true);
  });

  it('reports the prefix list as unexamined rather than guessing', () => {
    expect(run().gaps.some((g) => g.reason.includes('prefix-list'))).toBe(true);
  });

  it('flags only the unencrypted volume, not all three', () => {
    const unencrypted = run().findings.filter((f) => f.ruleId.includes('unencrypted'));
    expect(unencrypted).toHaveLength(1);
    expect(unencrypted[0].resource).toContain('60002');
  });

  it('notes the snapshot whose source volume is gone', () => {
    expect(run().notes.some((n) => n.ruleId.includes('source-volume-gone'))).toBe(true);
  });

  it('notes the guardrail without counting it as a problem', () => {
    expect(run().notes.some((n) => n.ruleId.includes('guardrail'))).toBe(true);
  });
});

describe('the restraint is visible in the example itself', () => {
  it('does not flag 443 open to the world', () => {
    // The one people check first.
    const port443 = run().findings.filter((f) => /443/.test(f.evidence.detail));
    expect(port443).toHaveLength(0);
  });

  it('does not flag the address held by a network interface', () => {
    // Scoped to the allocation id — a looser match catches the gp2 volume
    // that shares a suffix.
    const flagged = run()
      .findings.filter((f) => f.ruleId.includes('unattached-elastic-ip'))
      .map((f) => f.resource);
    expect(flagged).toEqual(['eipalloc-0a1b2c3d4e5f60001']);
  });

  it('lists three policy snapshots as ONE advisory, not three', () => {
    const retention = run().findings.filter((f) => f.ruleId.includes('backup-retention'));
    expect(retention).toHaveLength(1);
    expect(retention[0].severity).toBeNull();
  });

  it('renders no severity it cannot derive', () => {
    for (const f of run().findings) {
      if (f.severity === null) expect(f.unknowable).toBeTruthy();
    }
  });
});
