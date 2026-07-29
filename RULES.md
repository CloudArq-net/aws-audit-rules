# Rules

Every rule, what it needs, and what it won't claim.

This reports rule-level configuration risk, not live exposure. SSH open to the
world is an incident if the group is attached to a running instance and dead
config if it isn't — and that's a second API call a paste can't carry.

## Severity

`severity` is nullable. A rule grades when the grading is a pure function of
the input, and returns null otherwise with `unknowable` naming what's missing.

That's why most security-group findings have no severity and cost findings do:
an unattached volume is medium whatever else is true, while SSH-open depends on
ENI attachment that `describe-security-groups` doesn't return.

---

## Security groups

Input: `aws ec2 describe-security-groups`

| Rule | Fires when |
|---|---|
| `sg.ssh-open-to-world` | A rule reaches port 22 from `0.0.0.0/0` or `::/0` |
| `sg.rdp-open-to-world` | Same, port 3389 |
| `sg.all-ports-open-to-world` | An all-ports or all-traffic rule from the world |
| `sg.sensitive-port-open-to-world` | A database, cache, or admin port from the world |
| `sg.ipv6-only-exposure` | Open on `::/0` but **not** `0.0.0.0/0` |
| `sg.default-group-has-rules` | The `default` group has rules (a note, not a finding) |
| `sg.all-traffic-from-single-host` | Every port open to one `/32` or `/128` (a note) |
| `sg.rule-already-covered` | A rule a broader rule in the same group already allows (a note) |

The last two are notes because neither is exposure. All traffic from one
address isn't open to the internet — but every port being reachable from a
single host is worth seeing, and consumer addresses change hands. A shadowed
rule grants nothing the group doesn't already grant, which matters mostly when
someone believes the narrower rule is what limits access.

Shadowing is only claimed when it's certain: same sources, and either an
all-traffic rule or the same protocol with a strictly wider port range. ICMP is
excluded, since FromPort/ToPort are a type and a code there rather than a range.

### Deliberately not flagged

- **`0.0.0.0/0` on 80 and 443** — that's a web server. Absent from the
  sensitive-port list on purpose, with a test pinning the absence.
- **Prefix-list sources.** `pl-0abc` could be a corporate CIDR block or
  `0.0.0.0/0`. Reported as a gap with
  `aws ec2 get-managed-prefix-list-entries` rather than guessed.
- **Security-group and cross-account references** — not world exposure.

### Details worth knowing

- **ICMP `FromPort`/`ToPort` are type and code, not ports.** `-1` is "all
  types", and is never rendered as a port.
- **`IpProtocol: "-1"` omits the port keys entirely** — absent, not zero.
- **IPv6 lives in `Ipv6Ranges[].CidrIpv6`,** a separate array.
- **Protocols can arrive as IANA numbers**: `"6"` is TCP, `"17"` UDP, `"1"`
  ICMP, `"58"` ICMPv6. Comparing to the name alone reports a world-open SSH
  port as clean.
- **World-open is exact string equality, not CIDR containment.** `0.0.0.0/1`
  covers half the internet and is not matched.
- **All-ports is `from <= 1 && to >= 65535`.** Both `0-65535` and `1-65535`
  occur in the wild.
- One finding per group per port, not one per rule. Twelve redundant SSH rules
  are one problem.

---

## Cost

Inputs: `aws ec2 describe-volumes`, `describe-addresses`,
`describe-snapshots --owner-ids self`

| Rule | Fires when |
|---|---|
| `ebs.unencrypted-volume` | `Encrypted` is false or absent |
| `cost.unattached-volume` | `State === "available"` |
| `cost.gp2-cheaper-as-gp3` | An **in-use** gp2 volume |
| `cost.unattached-elastic-ip` | No association, no ENI, no instance |
| `cost.old-snapshot` | Older than 90 days and not policy-managed |
| `cost.backup-retention` | Policy-managed snapshots past 90 days (one finding, not one each) |
| `cost.snapshot-source-volume-gone` | The source volume isn't in the pasted volume list (a note) |

`ebs.unencrypted-volume` is the one rule here that isn't about money — it's in
this table because `describe-volumes` is where the field lives. It grades HIGH,
because that grading needs nothing the paste is missing.

`cost.snapshot-source-volume-gone` only fires when the volume list was pasted
too. An absent or empty list means we don't know, not that everything is gone.

### Money

Every figure is the us-east-1 on-demand list rate with no region adjustment,
exposed as `PRICING_BASIS` and attached to each finding. Unknown volume types
fall back to gp3 pricing rather than $0, which would hide the cost.

**gp2 → gp3 nets out performance parity.** gp3 is $0.02/GB cheaper but charges
for IOPS above 3,000 and throughput above 125 MB/s on volumes ≥ 334 GiB, both
of which gp2 includes. On a 2,000 GiB volume the storage delta is $40/month and
the parity cost is $20.

### Deliberately not flagged

**Idle and rightsizing** — needs CloudWatch metrics, which a `describe-*`
response doesn't contain.

**Backup-policy snapshots, individually.** A 35-day policy over 50 volumes is
1,750 snapshots, and deleting one breaks a retention window nothing will refill.
Reported once, with the full cost, pointed at the retention period.

AWS reserves the `aws:` tag prefix, so `aws:dlm:*` and `aws:backup:*` can't be
forged. Kept narrow: `dlm:managed` has no `aws:` prefix and is
customer-writable, and `aws:cloudformation:*` is the customer's own
infrastructure.

### Correctness details

- **The JSON key is `State`; the CLI filter is `status`.** Reading the wrong
  one finds nothing.
- **A missing `AssociationId` doesn't mean an Elastic IP is free.** A NAT
  gateway's ENI holds one without surfacing an association, so all three of
  `AssociationId`, `NetworkInterfaceId` and `InstanceId` must be clear.
- **Timestamps without a zone are read as UTC.**
  `new Date("2026-01-01T00:00:00")` is local time, which shifts a snapshot's
  age by the reader's offset — enough to cross the 90-day cutoff.
- **The age cutoff is strict.** Exactly 90 days is not flagged.
- **"Available" does not mean "empty".** Every remediation snapshots first,
  and the word "unused" is never used — a test pins that.
- **AMI dependencies are a gap, not an assumption.** Deleting a snapshot that
  backs a registered AMI makes that AMI unlaunchable, and `describe-snapshots`
  can't say which ones do.

---

## Bedrock

Inputs: `aws bedrock get-model-invocation-logging-configuration`,
`aws bedrock list-guardrails`

| Rule | Fires when |
|---|---|
| `ai.invocation-logging-off` | No config, or a config with no destination |
| `ai.invocation-logging-metadata-only` | Logging on, every body-delivery flag off |
| `ai.invocation-logs-carry-prompts` | Logging on with body delivery — names the sink |
| `ai.guardrail-not-ready` | A guardrail whose status isn't READY |
| `ai.guardrail-draft-only` | Every guardrail is still on DRAFT (a note) |
| `ai.large-data-delivery-sink` | Oversized payloads spill to a second bucket (a note) |
| `ai.guardrail-enforcement-unverifiable` | Guardrails exist (a note, not a finding) |

Every severity here is null: these are all configuration, and the questions
that would grade them are runtime.

### Three things worth knowing

**Logging can be on and record nothing.** AWS accepts a `loggingConfig` with
delivery flags and no destination, in which case nothing is written anywhere.
Testing `loggingConfig !== null` reports that account as logging its prompts.

**"Logging is enabled" usually doesn't mean the prompts are recorded.** With
the `*DataDeliveryEnabled` flags off you have a record that a model was invoked
— when, which one, by whom — and nothing about what was asked or answered. All
four flags are checked, not just `text`; an embeddings pipeline delivers
`embeddingData` and no text at all.

**A guardrail is passed per request**, via `guardrailIdentifier` on
`InvokeModel`. Configuring one in the console does nothing on its own, and no
AWS API reports whether your application passes it. Reported as a note for
exactly that reason.

### Deliberately not flagged

- **An account with no guardrails** — plenty of legitimate use needs none.
- **Whether the log sink is public** — needs `s3:GetBucketPolicyStatus` and
  `s3:GetBucketAcl`. Reported as a gap naming the bucket and both commands.
- **That anyone is invoking models at all** — this is configuration, not
  traffic.

---

## Adding a rule

1. Write the test first and watch it fail.
2. If the rule needs a fact the input can't carry, it's a `Gap` or an
   `unknowable`, not a rule.
3. If it can fire on a healthy configuration, add the restraint case first.
4. Update this file in the same change.
