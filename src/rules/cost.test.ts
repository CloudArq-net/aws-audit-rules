/**
 * Two things these are mostly about: not recommending you delete snapshots a
 * backup policy created, and getting the money right — every figure is a
 * us-east-1 list rate, and gp2→gp3 has to net out the IOPS gp3 charges for.
 */

import { describe, expect, it } from 'vitest';

import {
  COST_RULE_IDS,
  PRICING_BASIS,
  analyzeAddresses,
  analyzeSnapshots,
  analyzeVolumes,
  gp2BaselineIops,
  monthlyForEbs,
  parseAwsTimestamp,
  type Address,
  type Snapshot,
  type Volume,
} from './cost';

const DLM_TAG = [{ Key: 'aws:dlm:lifecycle-policy-id', Value: 'policy-0abc' }];
const BACKUP_TAG = [{ Key: 'aws:backup:source-resource', Value: 'vol-0abc' }];

// Encrypted by default so tests about other rules aren't perturbed by the
// encryption finding; the encryption tests set it false explicitly.
const vol = (over: Partial<Volume> = {}): Volume => ({
  VolumeId: 'vol-0123456789abcdef0',
  VolumeType: 'gp3',
  Size: 100,
  State: 'available',
  Encrypted: true,
  ...over,
});

const snap = (over: Partial<Snapshot> = {}): Snapshot => ({
  SnapshotId: 'snap-0123456789abcdef0',
  VolumeSize: 100,
  StartTime: '2026-01-01T00:00:00.000Z',
  ...over,
});

const NOW = new Date('2026-07-28T00:00:00.000Z');

// ── pricing ───────────────────────────────────────────────────────────

describe('pricing', () => {
  it.each([
    ['gp2', 100, 10.0],
    ['gp3', 100, 8.0],
    ['io1', 100, 12.5],
    ['io2', 100, 12.5],
    ['st1', 100, 4.5],
    ['sc1', 100, 1.5],
    ['standard', 100, 5.0],
  ])('prices 100 GB of %s at $%s/month', (type, size, expected) => {
    expect(monthlyForEbs(type, size as number)).toBe(expected);
  });

  it('falls back to gp3 for an unknown type rather than returning zero', () => {
    // Returning 0 would silently hide the cost.
    expect(monthlyForEbs('gp9-imaginary', 100)).toBe(8.0);
  });

  it('states the basis of every figure, and does not imply a region', () => {
    expect(PRICING_BASIS).toContain('us-east-1');
    expect(PRICING_BASIS).toMatch(/list price/i);
  });

  it.each([
    [8, 100], // 3 × 8 = 24, floored at 100
    [1000, 3000],
    [6000, 16000], // capped
  ])('gp2 baseline IOPS for %i GiB is %i', (size, iops) => {
    expect(gp2BaselineIops(size)).toBe(iops);
  });
});

// ── the timestamp trap ─────────────────────────────────────────────────

describe('timestamps are read as UTC', () => {
  it('treats a zone-less timestamp as UTC, not local', () => {
    // `new Date("2026-01-01T00:00:00")` is local time, so without this a
    // reader's offset shifts the age — enough to cross the 90-day cutoff.
    const naive = parseAwsTimestamp('2026-01-01T00:00:00');
    const explicit = parseAwsTimestamp('2026-01-01T00:00:00Z');
    expect(naive?.getTime()).toBe(explicit?.getTime());
  });

  it('accepts the offset form the CLI also emits', () => {
    expect(parseAwsTimestamp('2026-01-01T00:00:00+00:00')?.getTime()).toBe(
      Date.UTC(2026, 0, 1),
    );
  });

  it('returns null for junk rather than an Invalid Date that spreads NaN', () => {
    expect(parseAwsTimestamp('yesterday')).toBeNull();
    expect(parseAwsTimestamp('')).toBeNull();
  });
});

// ── volumes ────────────────────────────────────────────────────────────

describe('unattached volumes', () => {
  it('flags an available volume with its real monthly cost', () => {
    const r = analyzeVolumes([vol({ VolumeType: 'gp3', Size: 500 })]);
    const f = r.findings.filter((x) => x.ruleId === COST_RULE_IDS.unattachedVolume);
    expect(f).toHaveLength(1);
    expect(f[0].cost?.monthlyUsd).toBe(40.0);
  });

  it('does NOT flag an in-use volume', () => {
    const r = analyzeVolumes([vol({ State: 'in-use' })]);
    expect(r.findings.filter((f) => f.ruleId.includes('unattached'))).toHaveLength(0);
  });

  it('never says "unused" — available does not mean empty', () => {
    // "unused, delete it" would be telling someone to destroy data.
    const r = analyzeVolumes([vol()]);
    const f = r.findings.find((x) => x.ruleId === COST_RULE_IDS.unattachedVolume)!;
    const text = `${f.title} ${f.explanation} ${f.fix.console.join(' ')}`.toLowerCase();
    expect(text).not.toContain('unused');
    expect(text).toContain('snapshot');
  });

  it('reads State, not status — the filter name is not the key name', () => {
    // The CLI filter is `status`; the JSON key is `State`.
    const r = analyzeVolumes([{ ...vol(), State: 'available' } as Volume]);
    expect(r.findings.length).toBeGreaterThan(0);
  });
});

describe('unencrypted volumes', () => {
  it('flags a volume with Encrypted false', () => {
    const r = analyzeVolumes([vol({ Encrypted: false, State: 'in-use' })]);
    const f = r.findings.find((x) => x.ruleId === COST_RULE_IDS.unencryptedVolume);
    expect(f).toBeDefined();
    expect(f!.severity).toBe('high');
  });

  it('flags one with the field absent — AWS omits it when false', () => {
    // Built without the helper, which encrypts by default.
    const r = analyzeVolumes([
      { VolumeId: 'vol-0abc', VolumeType: 'gp3', Size: 100, State: 'in-use' },
    ]);
    expect(r.findings.map((f) => f.ruleId)).toContain(COST_RULE_IDS.unencryptedVolume);
  });

  it('says nothing about an encrypted volume', () => {
    const r = analyzeVolumes([vol({ Encrypted: true, State: 'in-use' })]);
    expect(r.findings.map((f) => f.ruleId)).not.toContain(COST_RULE_IDS.unencryptedVolume);
  });

  it('applies to detached volumes too', () => {
    const r = analyzeVolumes([vol({ Encrypted: false, State: 'available' })]);
    expect(r.findings.map((f) => f.ruleId)).toContain(COST_RULE_IDS.unencryptedVolume);
  });

  it('carries no cost — it is not a spend problem', () => {
    const f = analyzeVolumes([vol({ Encrypted: false, State: 'in-use' })])
      .findings.find((x) => x.ruleId === COST_RULE_IDS.unencryptedVolume)!;
    expect(f.cost).toBeUndefined();
  });

  it('says encryption cannot be turned on in place', () => {
    const f = analyzeVolumes([vol({ Encrypted: false, State: 'in-use' })])
      .findings.find((x) => x.ruleId === COST_RULE_IDS.unencryptedVolume)!;
    expect(f.fix.console.join(' ')).toMatch(/snapshot/i);
  });
});

describe('snapshots whose source volume is gone', () => {
  const volumes = [vol({ VolumeId: 'vol-alive', State: 'in-use' })];

  it('is only claimed when the volume list was also pasted', () => {
    // Without it we have no idea whether the volume exists.
    const r = analyzeSnapshots([snap({ VolumeId: 'vol-deleted' })], NOW);
    expect(r.notes.map((n) => n.ruleId)).not.toContain(COST_RULE_IDS.snapshotSourceGone);
  });

  it('notes a snapshot whose volume is absent from the pasted list', () => {
    const r = analyzeSnapshots([snap({ VolumeId: 'vol-deleted' })], NOW, volumes);
    expect(r.notes.map((n) => n.ruleId)).toContain(COST_RULE_IDS.snapshotSourceGone);
  });

  it('says nothing when the volume is present', () => {
    const r = analyzeSnapshots([snap({ VolumeId: 'vol-alive' })], NOW, volumes);
    expect(r.notes.map((n) => n.ruleId)).not.toContain(COST_RULE_IDS.snapshotSourceGone);
  });

  it('ignores snapshots a backup policy made', () => {
    const r = analyzeSnapshots(
      [snap({ VolumeId: 'vol-deleted', Tags: DLM_TAG })],
      NOW,
      volumes,
    );
    expect(r.notes.map((n) => n.ruleId)).not.toContain(COST_RULE_IDS.snapshotSourceGone);
  });

  it('says nothing when the pasted volume list is empty', () => {
    // An empty list is not evidence that every volume is gone.
    const r = analyzeSnapshots([snap({ VolumeId: 'vol-deleted' })], NOW, []);
    expect(r.notes.map((n) => n.ruleId)).not.toContain(COST_RULE_IDS.snapshotSourceGone);
  });
});

describe('gp2 volumes cheaper as gp3 — the finding a healthy account still gets', () => {
  it('flags an IN-USE gp2 volume, because the conversion is online', () => {
    const r = analyzeVolumes([vol({ VolumeType: 'gp2', Size: 100, State: 'in-use' })]);
    const gp3 = r.findings.filter((f) => f.ruleId.includes('gp3'));
    expect(gp3).toHaveLength(1);
    // 100 GB × ($0.10 − $0.08) = $2.00, and gp3's free 3,000 IOPS already
    // covers a 100 GiB gp2 baseline of 300, so nothing nets out.
    expect(gp3[0].cost?.monthlyUsd).toBe(2.0);
  });

  /**
   * At 2,000 GiB the storage delta is $40, but gp3 has to buy back 3,000 IOPS
   * ($15) and 125 MB/s ($5) that gp2 included — so the quoted saving is $20.
   */
  it.each([
    [100, 2.0],
    [333, 6.66], // just under the throughput cliff
    [334, 1.68], // …and just over it: the parity cost swamps the delta
    [2000, 20.0],
    [5000, 35.0],
  ])('quotes %i GiB at $%s/month', (size, expected) => {
    const r = analyzeVolumes([vol({ VolumeType: 'gp2', Size: size, State: 'in-use' })]);
    const gp3 = r.findings.find((f) => f.ruleId.includes('gp3'))!;
    expect(gp3.cost?.monthlyUsd).toBe(expected);
  });

  it('shows its working when performance has to be bought back', () => {
    const r = analyzeVolumes([vol({ VolumeType: 'gp2', Size: 2000, State: 'in-use' })]);
    const gp3 = r.findings.find((f) => f.ruleId.includes('gp3'))!;
    // The netting is on the finding, since that's the number people check.
    expect(gp3.why).toMatch(/baseline/i);
    expect(gp3.why).toContain('40.00');
  });

  it('never reports a negative saving', () => {
    const r = analyzeVolumes([vol({ VolumeType: 'gp2', Size: 16000, State: 'in-use' })]);
    const gp3 = r.findings.find((f) => f.ruleId.includes('gp3'));
    if (gp3) expect(gp3.cost?.monthlyUsd).toBeGreaterThanOrEqual(0);
  });

  it('leaves gp3 volumes alone', () => {
    const r = analyzeVolumes([vol({ VolumeType: 'gp3', State: 'in-use' })]);
    expect(r.findings).toHaveLength(0);
  });

  it('a healthy encrypted in-use gp3 volume produces nothing at all', () => {
    expect(analyzeVolumes([vol({ State: 'in-use' })]).findings).toHaveLength(0);
  });
});

// ── elastic IPs ────────────────────────────────────────────────────────

describe('elastic IPs', () => {
  const eip = (over: Partial<Address> = {}): Address => ({
    PublicIp: '192.0.2.10',
    AllocationId: 'eipalloc-0abc',
    ...over,
  });

  it('flags a truly unassociated address', () => {
    const r = analyzeAddresses([eip()]);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].cost?.monthlyUsd).toBe(3.65);
  });

  it.each([
    ['AssociationId', { AssociationId: 'eipassoc-0abc' }],
    ['NetworkInterfaceId', { NetworkInterfaceId: 'eni-0abc' }],
    ['InstanceId', { InstanceId: 'i-0abc' }],
  ])('does not flag one bound via %s', (_label, over) => {
    // A NAT gateway's ENI holds one without surfacing an association.
    expect(analyzeAddresses([eip(over as Partial<Address>)]).findings).toHaveLength(0);
  });
});

// ── snapshots: the restraint that matters ──────────────────────────────

describe('snapshots created by a backup policy', () => {
  it('does not tell you to delete a single one of them', () => {
    const snaps = Array.from({ length: 40 }, (_, i) =>
      snap({ SnapshotId: `snap-${i}`, Tags: DLM_TAG }),
    );
    const r = analyzeSnapshots(snaps, NOW);
    expect(r.findings.filter((f) => f.ruleId.includes('old-snapshot'))).toHaveLength(0);
  });

  it('still reports what they cost, once, pointed at the policy', () => {
    const snaps = Array.from({ length: 40 }, (_, i) =>
      snap({ SnapshotId: `snap-${i}`, VolumeSize: 100, Tags: BACKUP_TAG }),
    );
    const r = analyzeSnapshots(snaps, NOW);
    const advisory = r.findings.find((f) => f.ruleId.includes('retention'))!;
    expect(advisory).toBeDefined();
    // 40 × 100 GB × $0.05 = $200/month.
    expect(advisory.cost?.monthlyUsd).toBe(200.0);
    const steps = advisory.fix.console.join(' ');
    expect(steps).toMatch(/retention period/i);
    // "Do not delete the snapshots individually" is the allowed mention.
    expect(steps).not.toMatch(/\bdelete the snapshot\b(?! individually)/i);
  });

  it('still flags a genuine orphan alongside it', () => {
    const r = analyzeSnapshots(
      [snap({ SnapshotId: 'snap-orphan' }), snap({ SnapshotId: 'snap-policy', Tags: DLM_TAG })],
      NOW,
    );
    expect(r.findings.some((f) => f.resource === 'snap-orphan')).toBe(true);
  });

  it('does not trust a customer-writable lookalike tag', () => {
    // `dlm:managed` has no `aws:` prefix, so anyone can write it. Trusting it
    // would let a user suppress their own findings by tagging.
    const r = analyzeSnapshots(
      [snap({ SnapshotId: 'snap-x', Tags: [{ Key: 'dlm:managed', Value: 'true' }] })],
      NOW,
    );
    expect(r.findings.some((f) => f.resource === 'snap-x')).toBe(true);
  });

  it('treats an aws: tag from another service as ordinary estate', () => {
    const r = analyzeSnapshots(
      [
        snap({
          SnapshotId: 'snap-cfn',
          Tags: [{ Key: 'aws:cloudformation:stack-name', Value: 'prod' }],
        }),
      ],
      NOW,
    );
    expect(r.findings.some((f) => f.resource === 'snap-cfn')).toBe(true);
  });
});

describe('snapshot age', () => {
  it('does not flag one exactly at the threshold', () => {
    // Strict cutoff.
    const exactly90 = new Date(NOW.getTime() - 90 * 86_400_000).toISOString();
    const r = analyzeSnapshots([snap({ StartTime: exactly90 })], NOW);
    expect(r.findings).toHaveLength(0);
  });

  it('flags one a day past it', () => {
    const day91 = new Date(NOW.getTime() - 91 * 86_400_000).toISOString();
    expect(analyzeSnapshots([snap({ StartTime: day91 })], NOW).findings).toHaveLength(1);
  });

  it('skips a snapshot whose timestamp it cannot read, and says so', () => {
    // Skipped rather than guessed at, and reported as a gap.
    const r = analyzeSnapshots([snap({ StartTime: 'not-a-date' })], NOW);
    expect(r.findings).toHaveLength(0);
    expect(r.gaps).toHaveLength(1);
  });
});

describe('what a paste cannot tell us about snapshots', () => {
  it('reports the AMI dependency as unexamined, with the command to resolve it', () => {
    // describe-snapshots can't say which snapshots back an AMI.
    const r = analyzeSnapshots([snap({ SnapshotId: 'snap-old' })], NOW);
    expect(r.gaps.some((g) => g.reason.includes('describe-images'))).toBe(true);
    // `why`, not `unknowable` — this finding has a severity.
    expect(r.findings[0].why).toMatch(/ami/i);
  });

  it('raises no AMI gap when there is nothing to warn about', () => {
    expect(analyzeSnapshots([], NOW).gaps).toHaveLength(0);
  });
});

// ── robustness ─────────────────────────────────────────────────────────

describe('missing keys never throw', () => {
  it.each([
    ['volume with no type', () => analyzeVolumes([{ VolumeId: 'v', Size: 1 } as Volume])],
    ['volume with no size', () => analyzeVolumes([{ VolumeId: 'v', State: 'available' } as Volume])],
    ['address with nothing', () => analyzeAddresses([{} as Address])],
    ['snapshot with no size', () => analyzeSnapshots([{ SnapshotId: 's' } as Snapshot], NOW)],
    ['empty everything', () => analyzeVolumes([])],
  ])('survives a %s', (_label, run) => {
    expect(run).not.toThrow();
  });
});
