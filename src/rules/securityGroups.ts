/**
 * Security-group rules.
 *
 * Quirks worth knowing, all matching how AWS actually behaves:
 *
 *   - world-open is exact string equality on `0.0.0.0/0`, not CIDR
 *     containment, so `0.0.0.0/1` is not matched
 *   - IPv6 is a separate array (`Ipv6Ranges[].CidrIpv6`)
 *   - `IpProtocol: "-1"` means all protocols and all ports, and AWS omits
 *     FromPort/ToPort entirely on those rules
 *   - a tcp/udp rule with no port range is treated as covering every port
 *
 * Severity is null throughout: whether an open rule matters depends on the
 * group being attached to an ENI, which describe-security-groups doesn't tell
 * us. See `unknowable` on each finding.
 */

import type { AnalysisResult, Evidence, Finding, Gap, Note } from '../types';

/** IANA numbers AWS may return instead of names. Mirrors `_PROTOCOL_NUMBERS`. */
const PROTOCOL_NUMBERS: Readonly<Record<string, string>> = {
  '1': 'icmp',
  '6': 'tcp',
  '17': 'udp',
  '58': 'icmpv6',
};

export interface IpRange { readonly CidrIp?: string; readonly Description?: string }
export interface Ipv6Range { readonly CidrIpv6?: string; readonly Description?: string }
export interface PrefixListId { readonly PrefixListId?: string; readonly Description?: string }
export interface UserIdGroupPair {
  readonly GroupId?: string;
  readonly UserId?: string;
  readonly Description?: string;
}

export interface IpPermission {
  readonly IpProtocol?: string;
  readonly FromPort?: number;
  readonly ToPort?: number;
  readonly IpRanges?: readonly IpRange[];
  readonly Ipv6Ranges?: readonly Ipv6Range[];
  readonly PrefixListIds?: readonly PrefixListId[];
  readonly UserIdGroupPairs?: readonly UserIdGroupPair[];
}

export interface SecurityGroup {
  readonly GroupId?: string;
  readonly GroupName?: string;
  readonly VpcId?: string;
  readonly Description?: string;
  readonly IpPermissions?: readonly IpPermission[];
  readonly IpPermissionsEgress?: readonly IpPermission[];
}

export function normalizeProtocol(rule: IpPermission): string | null {
  const raw = rule.IpProtocol;
  if (raw === undefined || raw === null) return null;
  const lower = String(raw).toLowerCase();
  if (lower === '-1') return '-1';
  return PROTOCOL_NUMBERS[lower] ?? lower;
}

export function isOpenToWorld(rule: IpPermission): boolean {
  for (const r of rule.IpRanges ?? []) if (r.CidrIp === '0.0.0.0/0') return true;
  for (const r of rule.Ipv6Ranges ?? []) if (r.CidrIpv6 === '::/0') return true;
  return false;
}

/** True when the rule is world-open on IPv6 ONLY — our headline finding. */
export function isIpv6OnlyExposure(rule: IpPermission): boolean {
  const v4 = (rule.IpRanges ?? []).some((r) => r.CidrIp === '0.0.0.0/0');
  const v6 = (rule.Ipv6Ranges ?? []).some((r) => r.CidrIpv6 === '::/0');
  return v6 && !v4;
}

export function ruleCoversPort(
  rule: IpPermission,
  port: number,
  protocols: readonly string[] = ['tcp'],
): boolean {
  const proto = normalizeProtocol(rule);
  if (proto === '-1') return true;
  if (proto === null || !protocols.includes(proto)) return false;
  const { FromPort: from, ToPort: to } = rule;
  if (from === undefined || to === undefined) return true;
  return from <= port && port <= to;
}

export function isAllPortsRule(rule: IpPermission): boolean {
  const proto = normalizeProtocol(rule);
  if (proto === '-1') return true;
  if (proto !== 'tcp' && proto !== 'udp') return false;
  const { FromPort: from, ToPort: to } = rule;
  if (from === undefined || to === undefined) return false;
  // `<= 1` rather than `<= 0`: Terraform writes `1-65535` for
  // `from_port = 1`, which is the same exposure as `0-65535`.
  return from <= 1 && to >= 65535;
}

/** For ICMP, FromPort/ToPort are type and code — not ports. `-1` is "all". */
export function describePortRange(rule: IpPermission): string {
  const proto = normalizeProtocol(rule);
  if (proto === '-1') return 'all ports, all protocols';
  if (proto === 'icmp' || proto === 'icmpv6') {
    const type = rule.FromPort;
    const code = rule.ToPort;
    if (type === undefined || type === -1) return `${proto} (all types)`;
    const codeText = code === undefined || code === -1 ? 'all codes' : `code ${code}`;
    return `${proto} type ${type}, ${codeText}`;
  }
  const { FromPort: from, ToPort: to } = rule;
  if (from === undefined || to === undefined) return `${proto ?? 'unknown'} (all ports)`;
  if (from === to) return `${proto} port ${from}`;
  return `${proto} ports ${from}-${to}`;
}

const evidenceFor = (sg: SecurityGroup, rule: IpPermission, index: number): Evidence => ({
  locator: `${sg.GroupId ?? 'unknown group'} · ingress rule ${index + 1}`,
  detail: `${describePortRange(rule)} from ${
    isIpv6OnlyExposure(rule) ? '::/0' : '0.0.0.0/0'
  }`,
});

/** Severity is not knowable from this input. Stated once, reused everywhere. */
const ATTACHMENT_UNKNOWABLE =
  'This JSON lists rules, not attachments. We cannot tell whether anything ' +
  'is actually using this security group, so we do not guess at a severity — ' +
  'an unattached group exposes nothing today, and an attached one may expose ' +
  'a production database.';

export interface SgAnalysis {
  readonly findings: Finding[];
  readonly notes: Note[];
  readonly gaps: Gap[];
  /** What was read, so a clean result can be told apart from a no-op. */
  readonly examined: AnalysisResult['examined'];
}

/** Ports worth flagging. 80 and 443 are deliberately absent — that's a web server. */
const SENSITIVE_PORTS: ReadonlyArray<readonly [number, string, string]> = [
  [22, 'SSH', 'Remote shell access. Exposed SSH is scanned and brute-forced continuously.'],
  [3389, 'RDP', 'Remote desktop. A primary ransomware entry point when reachable from the internet.'],
  [5432, 'PostgreSQL', 'Database port. Should reach only your application tier.'],
  [3306, 'MySQL', 'Database port. Should reach only your application tier.'],
  [1433, 'SQL Server', 'Database port. Should reach only your application tier.'],
  [27017, 'MongoDB', 'Historically shipped without authentication; a common source of public data leaks.'],
  [6379, 'Redis', 'Unauthenticated by default before Redis 6 — an open port is often an open database.'],
  [9200, 'Elasticsearch', 'No authentication in the open-source distribution by default.'],
  [11211, 'Memcached', 'No authentication, and amplification-attack traffic is routinely reflected off it.'],
];

/** Rules this module runs, surfaced so a clean result can prove it worked. */
export const SG_RULE_IDS = {
  ipv6OnlyExposure: 'sg.ipv6-only-exposure',
  allTrafficOpen: 'sg.all-traffic-open',
  sensitivePortOpen: 'sg.sensitive-port-open',
  defaultGroupHasRules: 'sg.default-group-has-rules',
  prefixListUnexaminable: 'sg.prefix-list-unexaminable',
  allTrafficFromSingleHost: 'sg.all-traffic-from-single-host',
  shadowedRule: 'sg.rule-already-covered',
} as const;

/** `/32` for IPv4, `/128` for IPv6 — one address, not a range. */
function singleHostSource(rule: IpPermission): string | null {
  const v4 = (rule.IpRanges ?? []).find((r) => r.CidrIp?.endsWith('/32'));
  if (v4?.CidrIp) return v4.CidrIp;
  const v6 = (rule.Ipv6Ranges ?? []).find((r) => r.CidrIpv6?.endsWith('/128'));
  return v6?.CidrIpv6 ?? null;
}

/** Every source a rule allows, as comparable strings. */
function sourcesOf(rule: IpPermission): string[] {
  return [
    ...(rule.IpRanges ?? []).map((r) => `v4:${r.CidrIp}`),
    ...(rule.Ipv6Ranges ?? []).map((r) => `v6:${r.CidrIpv6}`),
    ...(rule.UserIdGroupPairs ?? []).map((r) => `sg:${r.GroupId}`),
    ...(rule.PrefixListIds ?? []).map((r) => `pl:${r.PrefixListId}`),
  ].filter((x) => !x.endsWith('undefined'));
}

/**
 * True when `wide` allows everything `narrow` does, from the same sources.
 *
 * ICMP is excluded on both sides unless `wide` is all-traffic: FromPort and
 * ToPort are a type and a code there, so comparing them as a range would be
 * meaningless.
 */
function covers(wide: IpPermission, narrow: IpPermission): boolean {
  const wideSources = new Set(sourcesOf(wide));
  const narrowSources = sourcesOf(narrow);
  if (narrowSources.length === 0) return false;
  if (!narrowSources.every((src) => wideSources.has(src))) return false;

  const wideProto = normalizeProtocol(wide);
  if (wideProto === '-1') return true;

  const narrowProto = normalizeProtocol(narrow);
  if (wideProto !== narrowProto) return false;
  if (wideProto === 'icmp' || wideProto === 'icmpv6') return false;

  const wf = wide.FromPort ?? 0;
  const wt = wide.ToPort ?? 65535;
  const nf = narrow.FromPort ?? 0;
  const nt = narrow.ToPort ?? 65535;
  // Strictly wider, so two identical rules don't shadow each other both ways.
  return wf <= nf && wt >= nt && (wf < nf || wt > nt);
}

export function analyzeSecurityGroups(groups: readonly SecurityGroup[]): SgAnalysis {
  const findings: Finding[] = [];
  const notes: Note[] = [];
  const gaps: Gap[] = [];

  for (const sg of groups) {
    const sgId = sg.GroupId ?? 'unknown';
    const sgName = sg.GroupName ?? sgId;
    const resource = sgName === sgId ? sgId : `${sgId} (${sgName})`;
    const rules = sg.IpPermissions ?? [];

    // One finding per (group, port), not per rule — redundant rules for the
    // same port are one problem.
    const flaggedPorts = new Set<number>();
    let reportedAllTraffic = false;

    rules.forEach((rule, index) => {
      // Prefix list contents aren't in this response, so report it as
      // unchecked rather than guess either way.
      for (const pl of rule.PrefixListIds ?? []) {
        if (pl.PrefixListId) {
          gaps.push({
            ruleId: 'sg.prefix-list-unexaminable',
            resource,
            reason:
              `Rule ${index + 1} allows traffic from managed prefix list ` +
              `${pl.PrefixListId}. Its contents are not in this output, so we ` +
              'cannot tell what it permits. Run ' +
              `\`aws ec2 get-managed-prefix-list-entries --prefix-list-id ${pl.PrefixListId}\` ` +
              'to see it.',
          });
        }
      }

      if (!isOpenToWorld(rule)) return;

      const ipv6Only = isIpv6OnlyExposure(rule);
      const evidence = evidenceFor(sg, rule, index);

      if (isAllPortsRule(rule)) {
        if (reportedAllTraffic) return;
        reportedAllTraffic = true;
        findings.push({
          ruleId: 'sg.all-traffic-open',
          title: `All traffic open to the internet: ${sgName}`,
          explanation:
            `Security group ${sgId} allows every port and protocol from ` +
            `${ipv6Only ? '::/0' : '0.0.0.0/0'}. Anything using this group is ` +
            'reachable on every service it runs, not just the one it was ' +
            'opened for.',
          severity: null,
          unknowable: ATTACHMENT_UNKNOWABLE,
          resource,
          evidence,
          fix: {
            console: [
              `Remove the all-traffic rule from ${sgId} immediately.`,
              'Replace it with rules for only the specific ports and protocols needed.',
              'Review which instances use this security group and audit their exposure.',
            ],
            cli:
              `aws ec2 revoke-security-group-ingress --group-id ${sgId} ` +
              `--ip-permissions '${JSON.stringify([{ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }])}'`,
          },
        });
        return;
      }

      for (const [port, service, why] of SENSITIVE_PORTS) {
        if (flaggedPorts.has(port)) continue;
        if (!ruleCoversPort(rule, port, ['tcp', 'udp'])) continue;
        flaggedPorts.add(port);
        findings.push({
          ruleId: ipv6Only ? 'sg.ipv6-only-exposure' : 'sg.sensitive-port-open',
          title: ipv6Only
            ? `${service} open to the internet over IPv6 only: ${sgName}`
            : `${service} open to the internet: ${sgName}`,
          explanation: ipv6Only
            ? `Security group ${sgId} allows ${service} (port ${port}) from ::/0 — ` +
              'the whole IPv6 internet — while IPv4 is restricted. This is easy ' +
              'to miss: a rule that looks locked down on IPv4 can be wide open ' +
              'on IPv6, and most audits only check IPv4.'
            : `Security group ${sgId} allows ${service} (port ${port}) from ` +
              '0.0.0.0/0 — any host on the internet can attempt to connect.',
          severity: null,
          unknowable: ATTACHMENT_UNKNOWABLE,
          resource,
          evidence,
          why,
          fix: {
            console: [
              `Open the EC2 console → Security Groups → ${sgId} → Inbound rules.`,
              `Edit the rule allowing port ${port} and replace the source with your trusted range.`,
              port === 22
                ? 'Consider AWS Systems Manager Session Manager instead of exposing SSH at all.'
                : `Restrict the source to the security group or CIDR that actually needs ${service}.`,
            ],
            cli:
              `aws ec2 revoke-security-group-ingress --group-id ${sgId} ` +
              `--protocol tcp --port ${port} --cidr ${ipv6Only ? '::/0' : '0.0.0.0/0'}\n` +
              `aws ec2 authorize-security-group-ingress --group-id ${sgId} ` +
              `--protocol tcp --port ${port} --cidr <YOUR-TRUSTED-CIDR>`,
          },
        });
      }
    });

    // Not world exposure, so not a finding — but every port reachable from one
    // address is worth seeing, and consumer IPs change hands.
    for (const rule of rules) {
      if (!isAllPortsRule(rule) || isOpenToWorld(rule)) continue;
      const host = singleHostSource(rule);
      if (!host) continue;
      notes.push({
        ruleId: SG_RULE_IDS.allTrafficFromSingleHost,
        title: `All traffic allowed from one address: ${sgName}`,
        explanation:
          `${sgId} allows every port and protocol from ${host}. That is not ` +
          'open to the internet, but it does mean anything running in this ' +
          'group is fully reachable from that one address — worth checking it ' +
          'is still the address you think it is, since consumer connections ' +
          'change theirs.',
        resource,
        evidence: {
          locator: sgId,
          detail: `all traffic from ${host}`,
        },
      });
    }

    // A rule that grants nothing the group doesn't already grant.
    for (const [index, rule] of rules.entries()) {
      const wider = rules.find((other, otherIndex) => otherIndex !== index && covers(other, rule));
      if (!wider) continue;
      const widerProto = normalizeProtocol(wider);
      notes.push({
        ruleId: SG_RULE_IDS.shadowedRule,
        title: `A rule on ${sgName} is already covered by a broader one`,
        explanation:
          `${describePortRange(rule)} from ${sourcesOf(rule).join(', ').replace(/v[46]:|sg:|pl:/g, '')} ` +
          `is already allowed by the ${widerProto === '-1' ? 'all-traffic' : describePortRange(wider)} ` +
          'rule in the same group, so removing it changes nothing. Worth ' +
          'tidying, and worth knowing if you thought the narrower rule was ' +
          'what limited access.',
        resource,
        evidence: {
          locator: sgId,
          detail: `${describePortRange(rule)} covered by ${describePortRange(wider)}`,
        },
      });
    }

    // A note, not a finding — rules on the default SG are worth seeing but
    // aren't an exposure on their own.
    if (sgName === 'default' && rules.length > 0) {
      notes.push({
        ruleId: 'sg.default-group-has-rules',
        title: `Default security group has ${rules.length} inbound rule${rules.length === 1 ? '' : 's'}`,
        explanation:
          'The default security group is attached automatically to resources ' +
          'launched without an explicit group, so rules on it apply more ' +
          'widely than people expect. AWS recommends leaving it empty.',
        resource,
        evidence: { locator: sgId, detail: `${rules.length} inbound rules` },
      });
    }
  }

  return {
    findings,
    notes,
    gaps,
    examined: {
      source: 'security-groups',
      resourceCount: groups.length,
      rulesRun: Object.values(SG_RULE_IDS),
    },
  };
}
