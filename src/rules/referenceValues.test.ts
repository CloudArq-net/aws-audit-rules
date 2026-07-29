/**
 * Reference values over a sanitized capture of a real account, rather than a
 * hand-written fixture. Real output contains shapes that are easy to miss —
 * notably an `IpProtocol: "-1"` rule with the port keys absent, which breaks
 * anything assuming FromPort exists.
 */

import { describe, expect, it } from 'vitest';

import fixture from '../fixtures/real-account-sanitized.json';
import {
  isAllPortsRule,
  isOpenToWorld,
  normalizeProtocol,
  ruleCoversPort,
  type SecurityGroup,
} from './securityGroups';

/** Expected values for each rule in the fixture. */
interface ExpectedRule {
  sg: string;
  rule: number;
  proto: string | null;
  world: boolean;
  allPorts: boolean;
  ssh: boolean;
  rdp: boolean;
  pg: boolean;
}

const EXPECTED: readonly ExpectedRule[] = [
  { sg: 'sg-00000000000000000', rule: 0, proto: 'udp', world: true, allPorts: false, ssh: false, rdp: false, pg: false },
  { sg: 'sg-00000000000000000', rule: 1, proto: 'tcp', world: true, allPorts: false, ssh: false, rdp: false, pg: false },
  { sg: 'sg-00000000000000000', rule: 2, proto: 'tcp', world: true, allPorts: false, ssh: false, rdp: false, pg: false },
];

const groups = (fixture as { SecurityGroups: SecurityGroup[] }).SecurityGroups;

describe('the fixture is a real capture, not a hand-written happy path', () => {
  it('contains groups', () => {
    expect(groups.length).toBeGreaterThan(0);
  });

  it('contains an all-traffic rule with the port keys ABSENT', () => {
    // AWS omits FromPort/ToPort entirely on `-1`. If this stops holding the
    // fixture no longer covers that path with real data.
    const rules = groups.flatMap((g) => g.IpPermissions ?? []);
    const allTraffic = rules.filter((r) => r.IpProtocol === '-1');
    expect(allTraffic.length).toBeGreaterThan(0);
    expect(allTraffic.every((r) => r.FromPort === undefined)).toBe(true);
  });

  it('carries no account id, ARN or real resource id', () => {
    // The sanitiser runs offline; this runs on every test run.
    const raw = JSON.stringify(fixture);
    expect(raw).not.toMatch(/\b(?!111111111111)\d{12}\b/);
    expect(raw).not.toContain('arn:aws');
  });
});

describe('each rule matches its reference values', () => {
  const byKey = new Map<string, ExpectedRule>(
    EXPECTED.map((v) => [`${v.sg}#${v.rule}`, v]),
  );

  for (const g of groups) {
    (g.IpPermissions ?? []).forEach((rule, index) => {
      const key = `${g.GroupId}#${index}`;
      const expected = byKey.get(key);
      if (!expected) return; // only the rules we captured verdicts for

      it(`${key} — protocol, world-open, all-ports and port coverage match`, () => {
        expect(normalizeProtocol(rule)).toBe(expected.proto);
        expect(isOpenToWorld(rule)).toBe(expected.world);
        expect(isAllPortsRule(rule)).toBe(expected.allPorts);
        expect(ruleCoversPort(rule, 22, ['tcp', 'udp'])).toBe(expected.ssh);
        expect(ruleCoversPort(rule, 3389, ['tcp', 'udp'])).toBe(expected.rdp);
        expect(ruleCoversPort(rule, 5432, ['tcp', 'udp'])).toBe(expected.pg);
      });
    });
  }

  it('covered every rule we captured a verdict for', () => {
    // If the fixture is regenerated and ids shift, every `it` above would
    // silently skip and this file would pass having tested nothing.
    const present = new Set(
      groups.flatMap((g) => (g.IpPermissions ?? []).map((_, i) => `${g.GroupId}#${i}`)),
    );
    for (const v of EXPECTED) {
      expect(present.has(`${v.sg}#${v.rule}`)).toBe(true);
    }
  });
});
