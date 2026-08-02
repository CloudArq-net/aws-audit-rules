# @cloudarq/aws-audit-rules

Audit rules for AWS CLI output. Pure functions, no dependencies, nothing that
opens a socket.

Give it the JSON from a read-only `aws` command and it reports what that JSON
can prove — and what it can't, with the command that would answer it.

```bash
git clone https://github.com/CloudArq-net/aws-audit-rules
cd aws-audit-rules
npm install
npm test
npm run example    # runs the rules over a sample paste and prints the output
```

```ts
import { analyzeAll } from '@cloudarq/aws-audit-rules';

const result = analyzeAll(pastedJson, new Date());

result.findings;   // what's wrong
result.notes;      // worth seeing, not wrong
result.gaps;       // what this input couldn't answer, and how to answer it
result.examined;   // what was actually read
```

The import above works after the first npm publish; until then use the clone.

Paste one command's output or several, in any order, with or without
separators. It works out which is which from the envelope key.

## Supported input

| Command | Rules |
|---|---|
| `aws ec2 describe-security-groups` | SSH/RDP/sensitive ports open to the world, all-traffic rules, IPv6-only exposure, all traffic from a single host, rules a broader rule already covers |
| `aws ec2 describe-volumes` | unencrypted volumes, unattached volumes, gp2 that would be cheaper as gp3 |
| `aws ec2 describe-addresses` | Elastic IPs allocated but not in use |
| `aws ec2 describe-snapshots --owner-ids self` | old snapshots, backup-policy retention, snapshots whose source volume is gone |
| `aws bedrock get-model-invocation-logging-configuration` | logging off, logging on but recording nothing, prompts in the log sink |
| `aws bedrock list-guardrails` | guardrails not READY, DRAFT-only versions, guardrails present but unverifiable |

## Severity is nullable

The engine only ever sees one pasted response — no account context, no second
API call, no metrics. Whether SSH open to `0.0.0.0/0` matters depends on
whether the security group is attached to anything, and that's a separate API
call this input doesn't contain.

So the rule reports the exposure, sets `severity: null`, and fills in
`unknowable` with what's missing. `Gap` exists for the same reason: a managed
prefix list names its contents somewhere we weren't given, so it's reported as
unchecked with `aws ec2 get-managed-prefix-list-entries` attached rather than
guessed at in either direction.

Cost and encryption findings do carry a severity, because that grading doesn't
depend on anything the paste is missing. `cost.basis` travels with every
figure — all prices are us-east-1 list rates with no region adjustment.

Some results are notes rather than findings: things worth seeing that aren't
defects. All traffic from a single host isn't exposure. A rule a broader rule
already covers grants nothing. Guardrails existing isn't a problem. Notes don't
inflate the finding count.

## What it deliberately doesn't report

- `0.0.0.0/0` on 80 and 443. That's a web server.
- Accounts with no Bedrock guardrails. Plenty of legitimate use needs none.
- Idle or over-provisioned instances — that needs CloudWatch metrics, which a
  `describe-*` response doesn't contain.
- Backup-policy snapshots individually. A 35-day policy over 50 volumes is
  1,750 snapshots, and deleting one breaks a retention window nothing will
  refill. Reported once, with the full cost, pointed at the policy.

Twelve redundant SSH rules produce one finding.

## Details worth knowing

Most of these are why the test suite is the size it is.

- **ICMP `FromPort`/`ToPort` are type and code, not ports.** `-1` means "all
  types".
- **`IpProtocol: "-1"` omits the port keys entirely** — absent, not zero.
- **IPv6 is a separate array** (`Ipv6Ranges[].CidrIpv6`).
- **Protocols arrive as IANA numbers too**: `"6"` is TCP, `"17"` UDP, `"1"`
  ICMP, `"58"` ICMPv6.
- **The JSON key is `State`; the CLI filter is `status`.**
- **A missing `AssociationId` doesn't mean an Elastic IP is free** — a NAT
  gateway's ENI holds one without surfacing an association.
- **A zone-less timestamp is parsed as local time** by `new Date`, which shifts
  a snapshot's age by the reader's UTC offset.
- **AWS puts braces inside strings** — descriptions, embedded policies, tag
  values — so splitting concatenated documents has to track strings and escapes.
- **Bedrock is lowerCamelCase where EC2 is PascalCase.**
- **`{"loggingConfig": null}` is what Bedrock returns when logging is off**, so
  the check is `in`, not truthiness.
- **Logging can be on and record nothing** — AWS accepts a config with delivery
  flags and no destination.

`RULES.md` has the full list, including every deliberate non-finding.

## Parse errors never contain your input

V8 embeds a slice of the offending text in `SyntaxError.message`:

```
JSON.parse('{"SecurityGroups": [{"GroupId": sg-0abc}]}')
→ SyntaxError: Unexpected token 's', ..."GroupId": sg-0abc}]}" is not valid JSON
```

Anything that captures errors would then be holding a piece of whatever was
pasted. `safeParseJson` catches it, drops the message, and throws a `ParseError`
carrying a position and a diagnosis built from constants — and doesn't attach
the original as `cause`, since reporters serialise that.

The diagnoses are more useful than V8's anyway: *"there is an extra comma just
before a closing bracket"*, *"the JSON ends before it is closed — it looks
truncated"*.

## Tests

```bash
npm test
```

247 of them. `rules/referenceValues.test.ts` runs against real CLI output with
the identifiers stripped and the service ports renumbered, rather than a
hand-written fixture, because real output contains shapes that are easy to miss
— an `IpProtocol: "-1"` rule with the port keys absent breaks anything assuming
`FromPort` exists.

## Where this comes from

These rules power the free auditor at
[cloudarq.net/tools/aws-auditor](https://cloudarq.net/tools/aws-auditor), which
runs entirely in the browser. Published because a page claiming nothing you
paste leaves your machine should let you check.

## Contributing

Three things the engine deliberately does not do yet are open as issues —
resolving managed prefix lists, region-aware pricing, and S3 bucket-policy
rules. Each is a real limit rather than a placeholder.

If you add a rule: write the test first, and if the rule needs a fact the
input can't carry, it belongs in `Gap` or `unknowable` rather than in a
guess. `RULES.md` has the full conventions.

MIT.
