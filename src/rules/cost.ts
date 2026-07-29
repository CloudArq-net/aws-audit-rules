/**
 * Cost rules.
 *
 * Three things this tries not to get wrong:
 *
 *   - snapshots created by a backup policy aren't orphans, and deleting one
 *     breaks a retention window nothing will refill
 *   - gp2→gp3 savings have to net out the baseline IOPS gp3 charges for and
 *     gp2 includes, or the number is roughly double what you'd actually save
 *   - "available" doesn't mean empty, so every remediation snapshots first
 *
 * Prices are us-east-1 on-demand list rates with no region adjustment. That's
 * what `PRICING_BASIS` says, and it travels with every figure.
 */

import type { AnalysisResult, Finding, Gap, Note } from '../types';

/** Attached to every figure below. */
export const PRICING_BASIS =
  'us-east-1 on-demand list price, no region adjustment — an estimate, not a bill';

// ── AWS shapes (only the fields we read) ───────────────────────────────

export interface Tag {
  Key?: string;
  Value?: string;
}

export interface Volume {
  VolumeId?: string;
  VolumeType?: string;
  Size?: number;
  State?: string;
  Iops?: number;
  SnapshotId?: string;
  Encrypted?: boolean;
  Tags?: Tag[];
}

export interface Address {
  PublicIp?: string;
  AllocationId?: string;
  AssociationId?: string;
  NetworkInterfaceId?: string;
  InstanceId?: string;
  Tags?: Tag[];
}

export interface Snapshot {
  SnapshotId?: string;
  VolumeSize?: number;
  VolumeId?: string;
  StartTime?: string;
  Description?: string;
  Tags?: Tag[];
}

export const COST_RULE_IDS = {
  unencryptedVolume: 'ebs.unencrypted-volume',
  snapshotSourceGone: 'cost.snapshot-source-volume-gone',
  unattachedVolume: 'cost.unattached-volume',
  gp2ToGp3: 'cost.gp2-cheaper-as-gp3',
  unattachedEip: 'cost.unattached-elastic-ip',
  oldSnapshot: 'cost.old-snapshot',
  backupRetention: 'cost.backup-retention',
} as const;

// ── pricing ───────────────────────────────────────────────────────────

const EBS_PRICE_PER_GB_MONTH: Record<string, number> = {
  gp2: 0.1,
  gp3: 0.08,
  io1: 0.125,
  io2: 0.125,
  st1: 0.045,
  sc1: 0.015,
  standard: 0.05,
};

const SNAPSHOT_PRICE_PER_GB_MONTH = 0.05;
/** $0.005/hr × 730. AWS bills every public IPv4 address, attached or not. */
const EIP_MONTHLY = 3.65;

const GP2_IOPS_PER_GIB = 3;
const GP2_MIN_BASELINE_IOPS = 100;
const GP2_MAX_BASELINE_IOPS = 16_000;
const GP2_SUSTAINED_THROUGHPUT_MIN_SIZE_GIB = 334;
const GP2_SUSTAINED_THROUGHPUT_MIBPS = 250;
const GP3_FREE_IOPS = 3_000;
const GP3_FREE_THROUGHPUT_MIBPS = 125;
const GP3_IOPS_PRICE_PER_MONTH = 0.005;
const GP3_THROUGHPUT_PRICE_PER_MBPS_MONTH = 0.04;

const SNAPSHOT_AGE_DAYS = 90;

/** Two decimals. */
const money = (n: number): number => Math.round(n * 100) / 100;

/** Unknown volume types fall back to gp3 rather than $0, which would hide cost. */
export function monthlyForEbs(volumeType: string | undefined, sizeGb: number): number {
  const rate = EBS_PRICE_PER_GB_MONTH[volumeType ?? ''] ?? EBS_PRICE_PER_GB_MONTH.gp3;
  return money(rate * (sizeGb || 0));
}

/** gp2 baseline IOPS: 3/GiB, floored at 100, capped at 16,000. */
export function gp2BaselineIops(sizeGb: number): number {
  const raw = GP2_IOPS_PER_GIB * sizeGb;
  return Math.floor(Math.min(Math.max(raw, GP2_MIN_BASELINE_IOPS), GP2_MAX_BASELINE_IOPS));
}

/**
 * Parse an AWS timestamp as UTC. A zone-less string like
 * `2026-01-01T00:00:00` is local time to `new Date`, which shifts a snapshot's
 * age by the reader's offset — enough to cross the 90-day cutoff. Returns null
 * rather than an Invalid Date, whose NaN spreads silently.
 */
export function parseAwsTimestamp(raw: string | undefined): Date | null {
  if (!raw || typeof raw !== 'string') return null;
  const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw.trim());
  const value = new Date(hasZone ? raw : `${raw}Z`);
  return Number.isNaN(value.getTime()) ? null : value;
}

/**
 * True when a backup policy created this rather than a person.
 *
 * AWS reserves the `aws:` tag prefix, so these can't be forged — which matters,
 * or anyone could silence findings by tagging. Kept narrow on purpose:
 * `dlm:managed` has no `aws:` prefix and is customer-writable, and
 * `aws:cloudformation:*` is just the customer's own infrastructure.
 */
const BACKUP_ARTEFACT_TAG_PREFIXES = ['aws:dlm:', 'aws:backup:'] as const;

export function isBackupArtefact(resource: { Tags?: Tag[] }): boolean {
  return (resource.Tags ?? []).some((tag) =>
    BACKUP_ARTEFACT_TAG_PREFIXES.some((prefix) => (tag?.Key ?? '').startsWith(prefix)),
  );
}

// ── volumes ────────────────────────────────────────────────────────────

/** Unattached volumes, plus in-use gp2 volumes that would be cheaper as gp3. */
export function analyzeVolumes(volumes: readonly Volume[]): AnalysisResult {
  const findings: Finding[] = [];

  for (const volume of volumes) {
    const id = volume.VolumeId ?? '(unnamed volume)';
    const size = volume.Size ?? 0;
    const type = volume.VolumeType;

    // The JSON key is `State`; the CLI *filter* is `status`. Easy to mix up,
    // and reading the wrong one silently finds nothing.
    if (volume.State === 'available') {
      findings.push({
        ruleId: COST_RULE_IDS.unattachedVolume,
        title: `Volume ${id} is not attached to anything`,
        // Gradable, unlike the SG rules — doesn't depend on missing data.
        severity: 'medium',
        explanation:
          `${size} GB ${type ?? 'volume'}, detached, still billing every ` +
          'month. Detached does not mean empty — it may hold the only copy ' +
          'of something, which is why the first step below is a snapshot.',
        resource: id,
        evidence: {
          locator: id,
          detail: `State "available", ${type ?? 'unknown type'}, ${size} GB`,
        },
        cost: { monthlyUsd: monthlyForEbs(type, size), basis: PRICING_BASIS },
        fix: {
          console: [
            `Snapshot ${id} before touching it — "available" is not "empty".`,
            'Confirm no AMI or launch template depends on the volume.',
            'Delete the volume once the snapshot is confirmed.',
          ],
          cli: `aws ec2 create-snapshot --volume-id ${id} --description "pre-delete"`,
        },
      });
    }

    if (type === 'gp2' && volume.State === 'in-use') {
      findings.push(gp2Finding(id, size));
    }

    // AWS omits `Encrypted` when it is false on some responses, so absent is
    // treated the same as false. Not a cost problem, but it is in this input
    // and saying nothing about it would be the bigger omission.
    if (!volume.Encrypted) {
      findings.push({
        ruleId: COST_RULE_IDS.unencryptedVolume,
        title: `Volume ${id} is not encrypted`,
        severity: 'high',
        explanation:
          `${size} GB ${type ?? 'volume'} stored in plaintext. Anyone who ` +
          'obtains a snapshot of it, or the underlying hardware, can read it.',
        why:
          'Encryption cannot be turned on in place. It has to be done by ' +
          'snapshotting, copying the snapshot with encryption enabled, and ' +
          'replacing the volume — which needs a maintenance window.',
        resource: id,
        evidence: {
          locator: id,
          detail: `Encrypted: ${volume.Encrypted === undefined ? 'absent' : 'false'}`,
        },
        fix: {
          console: [
            `Snapshot ${id}.`,
            'Copy the snapshot with encryption enabled, choosing your KMS key.',
            'Create a volume from the encrypted copy and swap it in.',
            'Turn on EBS encryption by default so new volumes are covered.',
          ],
          cli: `aws ec2 create-snapshot --volume-id ${id} --description "pre-encryption"`,
        },
      });
    }
  }

  return {
    findings,
    notes: [],
    gaps: [],
    examined: {
      source: 'volumes',
      resourceCount: volumes.length,
      rulesRun: [COST_RULE_IDS.unattachedVolume, COST_RULE_IDS.gp2ToGp3],
    },
  };
}

/**
 * gp3 is cheaper per GB but charges for IOPS above 3,000, which gp2 includes.
 * On a 2 TiB volume that's $20 of the $40 storage delta, so the saving quoted
 * here is net of buying that performance back.
 */
function gp2Finding(id: string, sizeGb: number): Finding {
  const storageDelta = money(sizeGb * (EBS_PRICE_PER_GB_MONTH.gp2 - EBS_PRICE_PER_GB_MONTH.gp3));

  const baselineIops = gp2BaselineIops(sizeGb);
  const extraIops = Math.max(0, baselineIops - GP3_FREE_IOPS);
  const iopsCost = money(extraIops * GP3_IOPS_PRICE_PER_MONTH);

  const throughputCost =
    sizeGb >= GP2_SUSTAINED_THROUGHPUT_MIN_SIZE_GIB
      ? money(
          (GP2_SUSTAINED_THROUGHPUT_MIBPS - GP3_FREE_THROUGHPUT_MIBPS) *
            GP3_THROUGHPUT_PRICE_PER_MBPS_MONTH,
        )
      : 0;

  const net = Math.max(0, money(storageDelta - iopsCost - throughputCost));
  const adjusted = iopsCost > 0 || throughputCost > 0;

  return {
    ruleId: COST_RULE_IDS.gp2ToGp3,
    title: `Volume ${id} would be cheaper as gp3`,
    severity: 'low',
    explanation:
      `${sizeGb} GB on gp2 at $0.10/GB-month. gp3 is $0.08 and the ` +
      'conversion is online — no detach, no downtime.',
    why: adjusted
      ? `The saving shown is NET. gp3 charges for IOPS above 3,000 and ` +
        `throughput above 125 MB/s, both of which gp2 includes free, so ` +
        `matching this volume's gp2 baseline of ${baselineIops} IOPS costs ` +
        `about $${money(iopsCost + throughputCost).toFixed(2)}/month against ` +
        `a storage delta of $${storageDelta.toFixed(2)}. You save the full ` +
        'delta only if nothing relies on that baseline.'
      : undefined,
    resource: id,
    evidence: {
      locator: id,
      detail: adjusted
        ? `gp2, ${sizeGb} GB, baseline ${baselineIops} IOPS; storage delta ` +
          `$${storageDelta.toFixed(2)} less $${money(iopsCost + throughputCost).toFixed(2)} parity`
        : `gp2, ${sizeGb} GB, baseline ${baselineIops} IOPS (within gp3's free tier)`,
    },
    cost: { monthlyUsd: net, basis: PRICING_BASIS },
    fix: {
      console: [
        'Check whether anything depends on this volume sustaining its gp2 ' +
          'baseline before converting.',
        'Modify the volume type to gp3 — the change is online and needs no ' +
          'detach.',
        'Provision matching IOPS or throughput on the gp3 volume if the ' +
          'workload needs them.',
      ],
      cli: `aws ec2 modify-volume --volume-id ${id} --volume-type gp3`,
    },
  };
}

// ── elastic IPs ────────────────────────────────────────────────────────

/**
 * A missing `AssociationId` doesn't mean the address is free — a NAT gateway's
 * ENI holds one without surfacing an association. All three fields must be clear.
 */
export function analyzeAddresses(addresses: readonly Address[]): AnalysisResult {
  const findings: Finding[] = [];

  for (const address of addresses) {
    if (address.AssociationId) continue;
    if (address.NetworkInterfaceId || address.InstanceId) continue;

    const ip = address.PublicIp ?? '(unknown address)';
    const allocation = address.AllocationId ?? ip;

    findings.push({
      ruleId: COST_RULE_IDS.unattachedEip,
      title: `Elastic IP ${ip} is allocated but not in use`,
      severity: 'low',
      explanation:
        'Not bound to an instance or a network interface. AWS bills every ' +
        'public IPv4 address at $0.005/hour whether or not anything answers ' +
        'on it.',
      resource: allocation,
      evidence: {
        locator: allocation,
        detail: `${ip}: no AssociationId, no NetworkInterfaceId, no InstanceId`,
      },
      cost: { monthlyUsd: EIP_MONTHLY, basis: PRICING_BASIS },
      fix: {
        console: [
          'Confirm nothing is waiting to claim it — a detached ENI held for ' +
            'reuse, a failover target, a pending association.',
          'Release the address once you are sure.',
        ],
        cli: `aws ec2 release-address --allocation-id ${allocation}`,
      },
    });
  }

  return {
    findings,
    notes: [],
    gaps: [],
    examined: {
      source: 'addresses',
      resourceCount: addresses.length,
      rulesRun: [COST_RULE_IDS.unattachedEip],
    },
  };
}

// ── snapshots ──────────────────────────────────────────────────────────

/** Old snapshots, minus the ones a policy made. `now` is injected for tests. */
export function analyzeSnapshots(
  snapshots: readonly Snapshot[],
  now: Date,
  /**
   * The volumes from the same paste, when there are any. Only used to say
   * whether a snapshot's source still exists — an empty or absent list means
   * we don't know, not that everything is gone.
   */
  volumes?: readonly Volume[],
): AnalysisResult {
  const findings: Finding[] = [];
  const notes: Note[] = [];
  const gaps: Gap[] = [];
  const knownVolumes = new Set((volumes ?? []).map((v) => v.VolumeId).filter(Boolean));

  const cutoff = now.getTime() - SNAPSHOT_AGE_DAYS * 86_400_000;
  let policyCount = 0;
  let policyGb = 0;
  let unreadable = 0;

  for (const snapshot of snapshots) {
    const id = snapshot.SnapshotId ?? '(unnamed snapshot)';
    const size = snapshot.VolumeSize ?? 0;

    const started = parseAwsTimestamp(snapshot.StartTime);
    if (started === null) {
      // Report it as unchecked rather than guess the age.
      unreadable += 1;
      continue;
    }

    // Strict — exactly 90 days is not flagged.
    if (started.getTime() >= cutoff) continue;

    if (isBackupArtefact(snapshot)) {
      policyCount += 1;
      policyGb += size;
      continue;
    }

    const ageDays = Math.floor((now.getTime() - started.getTime()) / 86_400_000);

    // Only meaningful when the volume list was pasted too.
    if (knownVolumes.size > 0 && snapshot.VolumeId && !knownVolumes.has(snapshot.VolumeId)) {
      notes.push({
        ruleId: COST_RULE_IDS.snapshotSourceGone,
        title: `Snapshot ${id} outlived the volume it came from`,
        explanation:
          `${snapshot.VolumeId} is not in the volumes you pasted, so this ` +
          'snapshot is the only remaining copy of whatever was on it. That ' +
          'makes it either the thing you keep or the thing you delete — but ' +
          'not something to leave undecided.',
        resource: id,
        evidence: { locator: id, detail: `source ${snapshot.VolumeId} not present` },
      });
    }

    findings.push({
      ruleId: COST_RULE_IDS.oldSnapshot,
      title: `Snapshot ${id} is ${ageDays} days old`,
      severity: 'low',
      explanation:
        `${size} GB, taken ${started.toISOString().slice(0, 10)}, billing ` +
        'ever since. No backup-policy tag, so nothing scheduled created it.',
      why:
        'Deleting a snapshot that backs a registered AMI makes that AMI ' +
        'unlaunchable, and the failure only shows up the next time someone ' +
        'tries to scale out. Check before you delete, not after.',
      resource: id,
      evidence: {
        locator: id,
        detail: `StartTime ${snapshot.StartTime}, ${size} GB, ${ageDays} days old`,
      },
      cost: {
        monthlyUsd: money(size * SNAPSHOT_PRICE_PER_GB_MONTH),
        basis: PRICING_BASIS,
      },
      fix: {
        console: [
          `Check whether any AMI you own is backed by ${id}.`,
          'Confirm the snapshot is not the last recovery point for a volume ' +
            'someone still depends on.',
          'Delete it once both are clear.',
        ],
        cli:
          'aws ec2 describe-images --owners self ' +
          `--filters Name=block-device-mapping.snapshot-id,Values=${id}`,
      },
    });
  }

  if (findings.length > 0) {
    gaps.push({
      ruleId: COST_RULE_IDS.oldSnapshot,
      resource: 'AMI dependencies',
      reason:
        'A snapshot that backs a registered AMI cannot be deleted without ' +
        'breaking that AMI, and describe-snapshots does not say which ones ' +
        'do. Run `aws ec2 describe-images --owners self` and check each ' +
        "image's BlockDeviceMappings before deleting anything.",
    });
  }

  if (unreadable > 0) {
    gaps.push({
      ruleId: COST_RULE_IDS.oldSnapshot,
      resource: `${unreadable} snapshot${unreadable === 1 ? '' : 's'} with an unreadable timestamp`,
      reason:
        'StartTime could not be parsed, so the age is unknown. These were ' +
        'skipped rather than guessed at.',
    });
  }

  if (policyCount > 0) {
    findings.push(retentionAdvisory(policyCount, policyGb));
  }

  return {
    findings,
    notes,
    gaps,
    examined: {
      source: 'snapshots',
      resourceCount: snapshots.length,
      rulesRun: [COST_RULE_IDS.oldSnapshot, COST_RULE_IDS.backupRetention],
    },
  };
}

/**
 * One finding for all policy-managed snapshots past the cutoff, not one each —
 * a 35-day policy over 50 volumes is 1,750 of them.
 *
 * The cost is still reported in full, since retention is often the biggest line
 * on an EBS bill. What changes is where it points: the retention period, which
 * is the only thing anyone can actually change. No severity, because a policy
 * doing its job isn't a misconfiguration.
 */
function retentionAdvisory(count: number, totalGb: number): Finding {
  return {
    ruleId: COST_RULE_IDS.backupRetention,
    title: `${count} snapshots past ${SNAPSHOT_AGE_DAYS} days are held by a backup policy`,
    severity: null,
    unknowable:
      'Whether the retention period is longer than you need. That is a ' +
      'recovery decision, not something the tags can tell us.',
    explanation:
      `${totalGb} GB, created on a schedule by AWS Backup or Data Lifecycle ` +
      'Manager. These are not orphans and they are not listed individually — ' +
      'deleting one would punch a hole in a retention policy that will not ' +
      'refill it.',
    resource: `${count} policy-managed snapshots`,
    evidence: {
      locator: `${count} snapshots, ${totalGb} GB`,
      detail: `tagged ${BACKUP_ARTEFACT_TAG_PREFIXES.join(' or ')}`,
    },
    cost: {
      monthlyUsd: money(totalGb * SNAPSHOT_PRICE_PER_GB_MONTH),
      basis: PRICING_BASIS,
    },
    fix: {
      console: [
        'Read the retention period on your DLM policies and AWS Backup plans.',
        'Confirm no compliance obligation depends on the current window.',
        'Shorten the retention period in the policy if it is more history ' +
          'than you need. Do not delete the snapshots individually.',
      ],
      cli: 'aws dlm get-lifecycle-policies',
    },
  };
}
