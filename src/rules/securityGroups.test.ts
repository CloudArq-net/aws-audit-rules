/**
 * Most of these cover the edges rather than the happy path: ICMP, `-1`, prefix
 * lists, IPv6-only, missing keys. That's where security-group parsing usually
 * goes wrong.
 *
 * The restraint cases matter as much as the detection ones — `0.0.0.0/0` on
 * 443 is a web server, and flagging it would make everything else suspect.
 */

import { describe, expect, it } from 'vitest';

import {
  SG_RULE_IDS,
  analyzeSecurityGroups,
  describePortRange,
  isAllPortsRule,
  isIpv6OnlyExposure,
  isOpenToWorld,
  normalizeProtocol,
  ruleCoversPort,
  type SecurityGroup,
} from './securityGroups';

const sg = (over: Partial<SecurityGroup> = {}): SecurityGroup => ({
  GroupId: 'sg-0123456789abcdef0',
  GroupName: 'app-tier',
  VpcId: 'vpc-0abc',
  IpPermissions: [],
  ...over,
});

const world = { IpRanges: [{ CidrIp: '0.0.0.0/0' }] };
const world6 = { Ipv6Ranges: [{ CidrIpv6: '::/0' }] };

// ── protocol normalisation ─────────────────────────────────────────────

describe('protocol normalisation', () => {
  it.each([
    ['tcp', 'tcp'], ['udp', 'udp'], ['icmp', 'icmp'],
    ['6', 'tcp'], ['17', 'udp'], ['1', 'icmp'], ['58', 'icmpv6'],
    ['-1', '-1'], ['TCP', 'tcp'],
  ])('maps %s to %s', (raw, expected) => {
    expect(normalizeProtocol({ IpProtocol: raw })).toBe(expected);
  });

  it('passes an unknown protocol through rather than guessing', () => {
    expect(normalizeProtocol({ IpProtocol: '132' })).toBe('132');
  });

  it('catches SSH open to the world under the IANA spelling', () => {
    // AWS returns "6" for TCP on some rules; comparing to the name alone
    // reports a world-open SSH port as clean.
    expect(ruleCoversPort({ IpProtocol: '6', FromPort: 22, ToPort: 22 }, 22)).toBe(true);
  });

  it('still does not treat UDP as SSH (ENG-145)', () => {
    expect(ruleCoversPort({ IpProtocol: 'udp', FromPort: 0, ToPort: 65535 }, 22)).toBe(false);
    expect(ruleCoversPort({ IpProtocol: '17', FromPort: 0, ToPort: 65535 }, 22)).toBe(false);
  });
});

// ── ICMP: the tell ─────────────────────────────────────────────────────

describe('ICMP is never rendered as ports', () => {
  it('never prints "port -1"', () => {
    const text = describePortRange({ IpProtocol: 'icmp', FromPort: -1, ToPort: -1 });
    expect(text).not.toContain('port -1');
    expect(text).toBe('icmp (all types)');
  });

  it('names the type and code, because that is what they are', () => {
    expect(describePortRange({ IpProtocol: 'icmp', FromPort: 8, ToPort: 0 }))
      .toBe('icmp type 8, code 0');
    expect(describePortRange({ IpProtocol: 'icmp', FromPort: 8, ToPort: -1 }))
      .toBe('icmp type 8, all codes');
  });

  it('handles icmpv6 under its IANA number', () => {
    expect(describePortRange({ IpProtocol: '58', FromPort: -1, ToPort: -1 }))
      .toBe('icmpv6 (all types)');
  });

  it('is never an all-ports rule', () => {
    expect(isAllPortsRule({ IpProtocol: 'icmp', FromPort: -1, ToPort: -1 })).toBe(false);
  });
});

// ── the all-ports boundary ─────────────────────────────────────────────

describe('all-ports detection', () => {
  it.each([0, 1])('treats %i-65535 as all ports', (from) => {
    expect(isAllPortsRule({ IpProtocol: 'tcp', FromPort: from, ToPort: 65535 })).toBe(true);
  });

  it('treats -1 as all ports even though AWS omits the port keys', () => {
    expect(isAllPortsRule({ IpProtocol: '-1' })).toBe(true);
  });

  it('does not call a genuinely narrow range all-ports', () => {
    expect(isAllPortsRule({ IpProtocol: 'tcp', FromPort: 80, ToPort: 443 })).toBe(false);
    expect(isAllPortsRule({ IpProtocol: 'tcp', FromPort: 1, ToPort: 1024 })).toBe(false);
  });
});

// ── world-open ─────────────────────────────────────────────────────────

describe('world-open', () => {
  it('is exact equality, not CIDR containment', () => {
    expect(isOpenToWorld({ IpRanges: [{ CidrIp: '0.0.0.0/0' }] })).toBe(true);
    // 0.0.0.0/1 covers half the internet and is deliberately not matched.
    expect(isOpenToWorld({ IpRanges: [{ CidrIp: '0.0.0.0/1' }] })).toBe(false);
  });

  it('reads IPv6 from its own array', () => {
    expect(isOpenToWorld(world6)).toBe(true);
  });

  it('does not treat a prefix list or group reference as world-open', () => {
    expect(isOpenToWorld({ PrefixListIds: [{ PrefixListId: 'pl-0abc' }] })).toBe(false);
    expect(isOpenToWorld({ UserIdGroupPairs: [{ GroupId: 'sg-0abc' }] })).toBe(false);
  });

  it('detects IPv6-only exposure — the headline finding', () => {
    expect(isIpv6OnlyExposure({ ...world6 })).toBe(true);
    expect(isIpv6OnlyExposure({ ...world, ...world6 })).toBe(false);
  });
});

// ── restraint ──────────────────────────────────────────────────────────

describe('false-positive restraint', () => {
  it('does NOT flag 443 open to the world', () => {
    const r = analyzeSecurityGroups([
      sg({ IpPermissions: [{ IpProtocol: 'tcp', FromPort: 443, ToPort: 443, ...world }] }),
    ]);
    expect(r.findings).toHaveLength(0);
  });

  it('does NOT flag 80 open to the world', () => {
    const r = analyzeSecurityGroups([
      sg({ IpPermissions: [{ IpProtocol: 'tcp', FromPort: 80, ToPort: 80, ...world }] }),
    ]);
    expect(r.findings).toHaveLength(0);
  });

  it('does not flag a restricted SSH rule', () => {
    const r = analyzeSecurityGroups([
      sg({
        IpPermissions: [
          { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '10.0.0.0/8' }] },
        ],
      }),
    ]);
    expect(r.findings).toHaveLength(0);
  });

  it('reports one finding per group per port, not one per rule', () => {
    // Twelve redundant SSH rules are one problem.
    const rules = Array.from({ length: 12 }, () => ({
      IpProtocol: 'tcp', FromPort: 22, ToPort: 22, ...world,
    }));
    const r = analyzeSecurityGroups([sg({ IpPermissions: rules })]);
    expect(r.findings.filter((f) => f.title.includes('SSH'))).toHaveLength(1);
  });
});

// ── severity honesty ───────────────────────────────────────────────────

describe('severity is null and says why', () => {
  it('never asserts a severity it cannot derive', () => {
    const r = analyzeSecurityGroups([
      sg({ IpPermissions: [{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, ...world }] }),
    ]);
    expect(r.findings[0].severity).toBeNull();
    expect(r.findings[0].unknowable).toContain('rules, not attachments');
  });
});

// ── gaps ───────────────────────────────────────────────────────────────

describe('prefix lists are reported as unexamined, never guessed', () => {
  it('records a gap naming the command that would resolve it', () => {
    const r = analyzeSecurityGroups([
      sg({
        IpPermissions: [
          { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, PrefixListIds: [{ PrefixListId: 'pl-0abc' }] },
        ],
      }),
    ]);
    expect(r.findings).toHaveLength(0);
    expect(r.gaps).toHaveLength(1);
    expect(r.gaps[0].reason).toContain('pl-0abc');
    expect(r.gaps[0].reason).toContain('get-managed-prefix-list-entries');
  });
});

// ── robustness ─────────────────────────────────────────────────────────

describe('missing keys and odd shapes never throw', () => {
  it.each([
    ['no IpPermissions', {}],
    ['empty rule', { IpPermissions: [{}] }],
    ['rule with no ranges', { IpPermissions: [{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22 }] }],
    ['no GroupName', { GroupName: undefined }],
  ])('survives %s', (_label, over) => {
    expect(() => analyzeSecurityGroups([sg(over as Partial<SecurityGroup>)])).not.toThrow();
  });

  it('handles an empty account', () => {
    const r = analyzeSecurityGroups([]);
    expect(r.findings).toHaveLength(0);
  });

  it('stays fast on a 600-group paste', () => {
    const groups = Array.from({ length: 600 }, (_, i) =>
      sg({
        GroupId: `sg-${String(i).padStart(17, '0')}`,
        IpPermissions: [
          { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, ...world },
          { IpProtocol: 'tcp', FromPort: 443, ToPort: 443, ...world },
          { IpProtocol: 'icmp', FromPort: -1, ToPort: -1, ...world },
        ],
      }),
    );
    const started = performance.now();
    const r = analyzeSecurityGroups(groups);
    expect(performance.now() - started).toBeLessThan(500);
    expect(r.findings).toHaveLength(600);
  });
});

// ── all traffic from one host ──────────────────────────────────────────

describe('all traffic from a single host', () => {
  const oneHost = { IpRanges: [{ CidrIp: '203.0.113.7/32' }] };

  it('is a note, not a finding — it is not world exposure', () => {
    const r = analyzeSecurityGroups([
      sg({ IpPermissions: [{ IpProtocol: '-1', ...oneHost }] }),
    ]);
    expect(r.findings).toHaveLength(0);
    expect(r.notes.map((n) => n.ruleId)).toContain(SG_RULE_IDS.allTrafficFromSingleHost);
  });

  it('names the address and says every port is reachable from it', () => {
    const note = analyzeSecurityGroups([
      sg({ IpPermissions: [{ IpProtocol: '-1', ...oneHost }] }),
    ]).notes[0];
    expect(note.evidence.detail).toContain('203.0.113.7/32');
    expect(note.explanation).toMatch(/every port/i);
  });

  it('covers an explicit 0-65535 range, not just -1', () => {
    const r = analyzeSecurityGroups([
      sg({ IpPermissions: [{ IpProtocol: 'tcp', FromPort: 0, ToPort: 65535, ...oneHost }] }),
    ]);
    expect(r.notes.map((n) => n.ruleId)).toContain(SG_RULE_IDS.allTrafficFromSingleHost);
  });

  it('says nothing about a single host on one port', () => {
    const r = analyzeSecurityGroups([
      sg({ IpPermissions: [{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, ...oneHost }] }),
    ]);
    expect(r.notes).toHaveLength(0);
  });

  it('does not fire for a whole subnet — that is not a single host', () => {
    const r = analyzeSecurityGroups([
      sg({ IpPermissions: [{ IpProtocol: '-1', IpRanges: [{ CidrIp: '10.0.0.0/8' }] }] }),
    ]);
    expect(r.notes.map((n) => n.ruleId)).not.toContain(SG_RULE_IDS.allTrafficFromSingleHost);
  });

  it('does not fire for 0.0.0.0/0 — that is the finding, not a note', () => {
    const r = analyzeSecurityGroups([
      sg({ IpPermissions: [{ IpProtocol: '-1', ...world }] }),
    ]);
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.notes.map((n) => n.ruleId)).not.toContain(SG_RULE_IDS.allTrafficFromSingleHost);
  });

  it('handles a single IPv6 host', () => {
    const r = analyzeSecurityGroups([
      sg({ IpPermissions: [{ IpProtocol: '-1', Ipv6Ranges: [{ CidrIpv6: '2001:db8::1/128' }] }] }),
    ]);
    expect(r.notes.map((n) => n.ruleId)).toContain(SG_RULE_IDS.allTrafficFromSingleHost);
  });

  it('ignores a self-reference, which is how a default group is meant to look', () => {
    const r = analyzeSecurityGroups([
      sg({
        GroupId: 'sg-0self',
        IpPermissions: [{ IpProtocol: '-1', UserIdGroupPairs: [{ GroupId: 'sg-0self' }] }],
      }),
    ]);
    expect(r.notes.map((n) => n.ruleId)).not.toContain(SG_RULE_IDS.allTrafficFromSingleHost);
  });
});

// ── shadowed rules ─────────────────────────────────────────────────────

describe('rules a broader rule already covers', () => {
  const host = { IpRanges: [{ CidrIp: '203.0.113.7/32' }] };

  it('flags an SSH rule sitting under an all-traffic rule from the same source', () => {
    const r = analyzeSecurityGroups([
      sg({
        IpPermissions: [
          { IpProtocol: '-1', ...host },
          { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, ...host },
        ],
      }),
    ]);
    const note = r.notes.find((n) => n.ruleId === SG_RULE_IDS.shadowedRule);
    expect(note).toBeDefined();
    expect(note!.explanation).toMatch(/already/i);
  });

  it('flags a narrower port range under a wider one on the same protocol', () => {
    const r = analyzeSecurityGroups([
      sg({
        IpPermissions: [
          { IpProtocol: 'tcp', FromPort: 8000, ToPort: 9000, ...host },
          { IpProtocol: 'tcp', FromPort: 8080, ToPort: 8080, ...host },
        ],
      }),
    ]);
    expect(r.notes.map((n) => n.ruleId)).toContain(SG_RULE_IDS.shadowedRule);
  });

  it('does not flag rules from different sources', () => {
    const r = analyzeSecurityGroups([
      sg({
        IpPermissions: [
          { IpProtocol: '-1', ...host },
          { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '198.51.100.9/32' }] },
        ],
      }),
    ]);
    expect(r.notes.map((n) => n.ruleId)).not.toContain(SG_RULE_IDS.shadowedRule);
  });

  it('does not flag different protocols on the same ports', () => {
    const r = analyzeSecurityGroups([
      sg({
        IpPermissions: [
          { IpProtocol: 'tcp', FromPort: 53, ToPort: 53, ...host },
          { IpProtocol: 'udp', FromPort: 53, ToPort: 53, ...host },
        ],
      }),
    ]);
    expect(r.notes.map((n) => n.ruleId)).not.toContain(SG_RULE_IDS.shadowedRule);
  });

  it('does not flag two ranges that merely overlap', () => {
    const r = analyzeSecurityGroups([
      sg({
        IpPermissions: [
          { IpProtocol: 'tcp', FromPort: 100, ToPort: 200, ...host },
          { IpProtocol: 'tcp', FromPort: 150, ToPort: 300, ...host },
        ],
      }),
    ]);
    expect(r.notes.map((n) => n.ruleId)).not.toContain(SG_RULE_IDS.shadowedRule);
  });

  it('leaves ICMP alone — FromPort/ToPort are type and code, not a range', () => {
    const r = analyzeSecurityGroups([
      sg({
        IpPermissions: [
          { IpProtocol: 'icmp', FromPort: -1, ToPort: -1, ...host },
          { IpProtocol: 'icmp', FromPort: 8, ToPort: 0, ...host },
        ],
      }),
    ]);
    expect(r.notes.map((n) => n.ruleId)).not.toContain(SG_RULE_IDS.shadowedRule);
  });

  it('reports each shadowed rule once, not once per covering rule', () => {
    const r = analyzeSecurityGroups([
      sg({
        IpPermissions: [
          { IpProtocol: '-1', ...host },
          { IpProtocol: 'tcp', FromPort: 0, ToPort: 65535, ...host },
          { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, ...host },
        ],
      }),
    ]);
    const shadowed = r.notes.filter((n) => n.ruleId === SG_RULE_IDS.shadowedRule);
    expect(shadowed.length).toBeLessThanOrEqual(2);
  });
});

// ── the default group ──────────────────────────────────────────────────

describe('default security group', () => {
  it('is a note, not a finding', () => {
    const r = analyzeSecurityGroups([
      sg({
        GroupName: 'default',
        IpPermissions: [{ IpProtocol: 'tcp', FromPort: 8080, ToPort: 8080, IpRanges: [{ CidrIp: '10.0.0.0/8' }] }],
      }),
    ]);
    expect(r.findings).toHaveLength(0);
    expect(r.notes).toHaveLength(1);
    expect(r.notes[0].ruleId).toBe('sg.default-group-has-rules');
  });
});
