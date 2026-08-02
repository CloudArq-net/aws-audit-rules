/**
 * `examined.rulesRun` is the field that lets a clean result be told apart from
 * a no-op — "nothing found" only means something if you know what was looked
 * for. It was hand-maintained, and two entries had already drifted: volumes
 * emitted `ebs.unencrypted-volume` without listing it, and snapshots emitted
 * `cost.snapshot-source-volume-gone` without listing it.
 *
 * So this pins the property rather than the lists: anything a source can emit
 * must be something that source declares it ran. Adding a rule and forgetting
 * the declaration fails here.
 */

import { describe, expect, it } from 'vitest';

import { analyzeBedrock } from './bedrock';
import { analyzeAddresses, analyzeSnapshots, analyzeVolumes } from './cost';
import { analyzeSecurityGroups } from './securityGroups';

import type { AnalysisResult } from '../types';

const NOW = new Date('2026-08-02T00:00:00.000Z');

/** Every ruleId the result actually reported, from all three channels. */
function emitted(r: AnalysisResult & { gaps?: readonly { ruleId: string }[] }): string[] {
  return [
    ...r.findings.map((f) => f.ruleId),
    ...r.notes.map((n) => n.ruleId),
    ...(r.gaps ?? []).map((g) => g.ruleId),
  ];
}

/**
 * Inputs chosen to fire as many rules per source as one document can. Each is
 * a shape the corresponding `describe-*` genuinely returns.
 */
const CASES: readonly [string, () => AnalysisResult][] = [
  [
    'security groups',
    () =>
      analyzeSecurityGroups([
        {
          GroupId: 'sg-01',
          GroupName: 'default',
          IpPermissions: [
            { IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
            { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
          ],
        },
        {
          GroupId: 'sg-02',
          GroupName: 'db',
          IpPermissions: [
            { IpProtocol: 'tcp', FromPort: 5432, ToPort: 5432, Ipv6Ranges: [{ CidrIpv6: '::/0' }] },
            { IpProtocol: 'tcp', FromPort: 3306, ToPort: 3306, PrefixListIds: [{ PrefixListId: 'pl-01' }] },
            { IpProtocol: '-1', IpRanges: [{ CidrIp: '198.51.100.4/32' }] },
          ],
        },
      ]),
  ],
  [
    'volumes',
    () =>
      analyzeVolumes([
        // unencrypted + in-use gp2 (gp3 candidate)
        { VolumeId: 'vol-01', VolumeType: 'gp2', Size: 2000, State: 'in-use' },
        // unattached
        { VolumeId: 'vol-02', VolumeType: 'gp3', Size: 100, State: 'available', Encrypted: true },
      ]),
  ],
  [
    'addresses',
    () => analyzeAddresses([{ PublicIp: '192.0.2.1', AllocationId: 'eipalloc-01' }]),
  ],
  [
    'snapshots',
    () =>
      analyzeSnapshots(
        [
          // old, unmanaged, and its source volume is not in the list below
          {
            SnapshotId: 'snap-01',
            VolumeId: 'vol-gone',
            VolumeSize: 50,
            StartTime: '2024-01-01T00:00:00.000Z',
          },
          // old and policy-managed -> retention advisory, not a deletion
          {
            SnapshotId: 'snap-02',
            VolumeId: 'vol-01',
            VolumeSize: 50,
            StartTime: '2024-01-01T00:00:00.000Z',
            Tags: [{ Key: 'aws:dlm:lifecycle-policy-id', Value: 'policy-01' }],
          },
        ],
        NOW,
        [{ VolumeId: 'vol-01', VolumeType: 'gp3', Size: 50, State: 'in-use', Encrypted: true }],
      ),
  ],
  [
    'bedrock',
    () =>
      analyzeBedrock({
        logging: {
          loggingConfig: {
            s3Config: { bucketName: 'b', keyPrefix: 'p/' },
            textDataDeliveryEnabled: true,
          },
        },
        guardrails: [{ id: 'gr-1', name: 'g', status: 'FAILED', version: 'DRAFT' }],
      }),
  ],
];

describe('examined.rulesRun', () => {
  it.each(CASES)('%s declares every rule it emitted', (_label, run) => {
    const result = run();
    const declared = new Set(result.examined.rulesRun);
    const undeclared = [...new Set(emitted(result))].filter((id) => !declared.has(id));

    expect(undeclared).toEqual([]);
  });

  it.each(CASES)('%s reports a non-empty rulesRun', (_label, run) => {
    // Guards against "fix" the assertion above by declaring nothing and
    // emitting nothing.
    expect(run().examined.rulesRun.length).toBeGreaterThan(0);
  });

  it('the volumes case really does exercise more than one rule', () => {
    // Anti-vacuity: if the fixture stopped triggering anything, the subset
    // assertion above would pass for the wrong reason.
    const result = CASES.find(([l]) => l === 'volumes')![1]();
    expect(new Set(emitted(result)).size).toBeGreaterThan(1);
  });
});
