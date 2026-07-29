/**
 * Routing matters more than it looks: sending a document to the wrong rules
 * produces no findings, which is indistinguishable from a clean account. Most
 * of these cover the ways a real paste is messy — several commands at once, no
 * separators, a truncated document among good ones, bare arrays from jq.
 */

import { describe, expect, it } from 'vitest';

import { INPUT_KINDS, analyzeAll, describeMissing } from './analyze';
import { ParseError } from './types';

const NOW = new Date('2026-07-28T00:00:00.000Z');

const SG = JSON.stringify({
  SecurityGroups: [
    {
      GroupId: 'sg-0abc',
      GroupName: 'web',
      IpPermissions: [
        { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
      ],
    },
  ],
});

const VOLUMES = JSON.stringify({
  Volumes: [{ VolumeId: 'vol-0abc', VolumeType: 'gp3', Size: 100, State: 'available' }],
});

const LOGGING = JSON.stringify({ loggingConfig: null });

const kinds = (text: string) => analyzeAll(text, NOW).recognized.map((r) => r.kind);

// ── routing ────────────────────────────────────────────────────────────

describe('it works out what you pasted', () => {
  it.each([
    ['security groups', SG, INPUT_KINDS.securityGroups],
    ['volumes', VOLUMES, INPUT_KINDS.volumes],
    ['logging config', LOGGING, INPUT_KINDS.bedrockLogging],
    ['addresses', JSON.stringify({ Addresses: [{ PublicIp: '192.0.2.1' }] }), INPUT_KINDS.addresses],
    [
      'snapshots',
      JSON.stringify({ Snapshots: [{ SnapshotId: 'snap-1', VolumeSize: 1 }] }),
      INPUT_KINDS.snapshots,
    ],
    ['guardrails', JSON.stringify({ guardrails: [{ id: 'gr-1' }] }), INPUT_KINDS.guardrails],
  ])('recognises %s', (_label, text, expected) => {
    expect(kinds(text)).toContain(expected);
  });

  it('handles Bedrock lowerCamelCase alongside EC2 PascalCase', () => {
    // EC2 is PascalCase, Bedrock lowerCamelCase.
    const both = analyzeAll(`${SG}\n${LOGGING}`, NOW);
    expect(both.recognized.map((r) => r.kind)).toEqual(
      expect.arrayContaining([INPUT_KINDS.securityGroups, INPUT_KINDS.bedrockLogging]),
    );
  });
});

describe('several command outputs pasted together', () => {
  it('reads them all', () => {
    const result = analyzeAll([SG, VOLUMES, LOGGING].join('\n'), NOW);
    expect(result.recognized).toHaveLength(3);
  });

  it('reads them with no separator at all', () => {
    // What copying a whole terminal window gives you.
    expect(analyzeAll(SG + VOLUMES, NOW).recognized).toHaveLength(2);
  });

  it('finds problems from every one of them', () => {
    const result = analyzeAll([SG, VOLUMES].join('\n'), NOW);
    expect(result.findings.some((f) => f.ruleId.startsWith('sg.'))).toBe(true);
    expect(result.findings.some((f) => f.ruleId.startsWith('cost.'))).toBe(true);
  });

  it('is not fooled by a brace inside a string value', () => {
    // AWS puts braces in descriptions and tags, so brace counting alone
    // cuts mid-document.
    const tricky = JSON.stringify({
      Snapshots: [
        { SnapshotId: 'snap-1', VolumeSize: 8, Description: 'policy {"Statement": [{}]} applied' },
      ],
    });
    const result = analyzeAll(`${tricky}\n${VOLUMES}`, NOW);
    expect(result.parseErrors).toHaveLength(0);
    expect(result.recognized.map((r) => r.kind)).toEqual(
      expect.arrayContaining([INPUT_KINDS.snapshots, INPUT_KINDS.volumes]),
    );
  });

  it('is not fooled by an escaped quote before a brace', () => {
    // `\"` doesn't end a string; treating it as if it does miscounts
    // every brace after it.
    const tricky = JSON.stringify({
      Snapshots: [{ SnapshotId: 'snap-2', VolumeSize: 8, Description: 'he said "go} now"' }],
    });
    expect(analyzeAll(`${tricky}\n${VOLUMES}`, NOW).parseErrors).toHaveLength(0);
  });

  it('does not double-count a document pasted twice', () => {
    // Easy to do with a scrollback selection.
    const once = analyzeAll(SG, NOW).findings.length;
    expect(analyzeAll(`${SG}\n${SG}`, NOW).findings).toHaveLength(once);
  });
});

describe('messy real-world pastes', () => {
  const GROUPS = `    "SecurityGroups": [
        {
            "GroupId": "sg-0abc",
            "GroupName": "web",
            "IpPermissions": [
                { "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                  "IpRanges": [{ "CidrIp": "0.0.0.0/0" }] }
            ]
        }
    ]
}`;

  it('ignores a shell prompt and the command in front of the JSON', () => {
    const text = `abdallah@mac ~ % aws ec2 describe-security-groups\n{\n${GROUPS}`;
    expect(kinds(text)).toContain(INPUT_KINDS.securityGroups);
  });

  it('ignores trailing shell noise', () => {
    const text = `{\n${GROUPS}\nabdallah@mac ~ %`;
    expect(kinds(text)).toContain(INPUT_KINDS.securityGroups);
  });

  it('recovers output that went through a pager', () => {
    // `less` redraws the screen as you scroll, so the paste is several
    // truncated copies separated by `:` prompts — and the final complete
    // screen is missing the opening brace that scrolled off the top.
    const text = [
      'abdallah@mac ~ % aws ec2 describe-security-groups',
      '{',
      '    "SecurityGroups": [',
      '        {',
      '            "GroupId": "sg-0abc",',
      ':',
      '    "SecurityGroups": [',
      '        {',
      '            "GroupId": "sg-0abc",',
      '            "IpPermissions": [',
      ':',
      GROUPS,
    ].join('\n');

    const result = analyzeAll(text, NOW);
    expect(result.recognized.map((r) => r.kind)).toContain(INPUT_KINDS.securityGroups);
    expect(result.findings.some((f) => /SSH open/i.test(f.title))).toBe(true);
  });

  it('does not double-count the pager\'s repeated screens', () => {
    const text = ['{', '  "SecurityGroups": [', ':', GROUPS].join('\n');
    const result = analyzeAll(text, NOW);
    expect(result.recognized.filter((r) => r.kind === INPUT_KINDS.securityGroups)).toHaveLength(1);
    expect(result.recognized[0].count).toBe(1);
  });

  it('recovers an array whose enclosing object never closes', () => {
    const text = `{\n    "SecurityGroups": [{ "GroupId": "sg-0abc", "IpPermissions": [] }]`;
    expect(kinds(text)).toContain(INPUT_KINDS.securityGroups);
  });

  it('still says truncated when there is genuinely nothing complete', () => {
    expect(() => analyzeAll('{\n  "SecurityGroups": [\n    { "GroupId": "sg-0abc",', NOW))
      .toThrow(/truncated/i);
  });

  it('recovers a Bedrock logging config from a partial paste', () => {
    const text = `% aws bedrock get-model-invocation-logging-configuration\n{\n    "loggingConfig": null\n`;
    expect(kinds(text)).toContain(INPUT_KINDS.bedrockLogging);
  });
});

describe('the shapes people actually paste', () => {
  const SG_DOC = JSON.stringify({
    SecurityGroups: [
      {
        GroupId: 'sg-0abc',
        GroupName: 'web',
        IpPermissions: [
          { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
        ],
      },
    ],
  }, null, 2);

  const sawGroups = (text: string) => {
    const r = analyzeAll(text, NOW);
    return r.recognized.some((k) => k.kind === INPUT_KINDS.securityGroups);
  };

  it('a markdown code fence around it', () => {
    expect(sawGroups('```json\n' + SG_DOC + '\n```')).toBe(true);
  });

  it('a bare fence with no language', () => {
    expect(sawGroups('```\n' + SG_DOC + '\n```')).toBe(true);
  });

  it('smart quotes from a word processor', () => {
    // Never valid JSON, so rewriting them can't break a good paste.
    expect(sawGroups(SG_DOC.replace(/"/g, '\u201c'))).toBe(true);
  });

  it('non-breaking spaces from a browser copy', () => {
    expect(sawGroups(SG_DOC.replace(/ /g, '\u00a0'))).toBe(true);
  });

  it('trailing commas from a hand edit', () => {
    expect(sawGroups(SG_DOC.replace(/\n(\s*)\}/g, ',\n$1}'))).toBe(true);
  });

  it('line numbers from an editor or a diff view', () => {
    const numbered = SG_DOC.split('\n').map((l, i) => `${i + 1}  ${l}`).join('\n');
    expect(sawGroups(numbered)).toBe(true);
  });

  it('prose above and below', () => {
    expect(sawGroups(`here is my output, what do you think?\n\n${SG_DOC}\n\nthanks!`)).toBe(true);
  });

  it('newline-delimited objects from `jq \'.SecurityGroups[]\'`', () => {
    const ndjson = [
      '{ "GroupId": "sg-0abc", "IpPermissions": [{ "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{ "CidrIp": "0.0.0.0/0" }] }] }',
      '{ "GroupId": "sg-0def", "IpPermissions": [] }',
    ].join('\n');
    const r = analyzeAll(ndjson, NOW);
    expect(r.recognized.find((k) => k.kind === INPUT_KINDS.securityGroups)?.count).toBe(2);
  });

  it('a single group object with no envelope', () => {
    expect(sawGroups('{ "GroupId": "sg-0abc", "IpPermissions": [] }')).toBe(true);
  });

  it('one good document and one mangled one, both recovered', () => {
    // The mangled half used to be lost entirely, because recovery only ran
    // when NOTHING parsed.
    const volumes = '{\n  "Volumes": [{ "VolumeId": "vol-0abc", "VolumeType": "gp3", "Size": 100, "State": "available" }]';
    const r = analyzeAll(`${SG_DOC}\n${volumes}`, NOW);
    expect(r.recognized.map((k) => k.kind)).toEqual(
      expect.arrayContaining([INPUT_KINDS.securityGroups, INPUT_KINDS.volumes]),
    );
  });

  it('CRLF line endings', () => {
    expect(sawGroups(SG_DOC.replace(/\n/g, '\r\n'))).toBe(true);
  });

  it('everything wrong at once', () => {
    const numbered = SG_DOC.split('\n').map((l, i) => `${i + 1} | ${l}`).join('\r\n');
    const text = `abdallah@mac ~ % aws ec2 describe-security-groups\r\n\`\`\`json\r\n${numbered}\r\n\`\`\`\r\nabdallah@mac ~ %`;
    expect(sawGroups(text)).toBe(true);
  });

  it('still refuses input with no AWS output in it', () => {
    expect(() => analyzeAll('hey can you check my account for me', NOW)).toThrow(ParseError);
  });

  it('does not invent groups from prose that merely mentions the key', () => {
    expect(() => analyzeAll('my SecurityGroups are all fine I think', NOW)).toThrow(ParseError);
  });
});

describe('a bare array, because jq users paste that', () => {
  it('infers volumes from the shape of the first element', () => {
    const text = JSON.stringify([
      { VolumeId: 'vol-0abc', VolumeType: 'gp2', Size: 100, State: 'available' },
    ]);
    expect(kinds(text)).toContain(INPUT_KINDS.volumes);
  });

  it('infers security groups', () => {
    expect(kinds(JSON.stringify([{ GroupId: 'sg-1', IpPermissions: [] }]))).toContain(
      INPUT_KINDS.securityGroups,
    );
  });

  it('says so plainly when the shape matches nothing', () => {
    const result = analyzeAll(JSON.stringify([{ Banana: 1 }]), NOW);
    expect(result.recognized).toHaveLength(0);
    expect(result.unrecognized).toHaveLength(1);
  });
});

// ── telling the user what happened ─────────────────────────────────────

describe('it says what it did and did not read', () => {
  it('names the keys it could not use', () => {
    const result = analyzeAll(JSON.stringify({ Reservations: [], NextToken: 'x' }), NOW);
    expect(result.unrecognized[0].keys).toContain('Reservations');
  });

  it('lists what else it could check, with the command for each', () => {
    const result = analyzeAll(SG, NOW);
    const missing = describeMissing(result);
    expect(missing.some((m) => m.command.includes('describe-volumes'))).toBe(true);
    expect(missing.some((m) => m.kind === INPUT_KINDS.securityGroups)).toBe(false);
  });

  it('has a command for every kind it knows, or the list is a dead end', () => {
    const everyKind = describeMissing(analyzeAll('', NOW)).map((m) => m.kind);
    expect(new Set(everyKind)).toEqual(new Set(Object.values(INPUT_KINDS)));
  });

  it('counts what it read, so the user can check it against their console', () => {
    const result = analyzeAll(VOLUMES, NOW);
    expect(result.recognized[0].count).toBe(1);
  });
});

// ── failure ────────────────────────────────────────────────────────────

describe('bad input', () => {
  it('raises a ParseError that carries no fragment of the paste', () => {
    const secret = '203.0.113.99/32';
    try {
      analyzeAll(`{"IpRanges": [{"CidrIp": "${secret}"},,]}`, NOW);
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(ParseError);
      expect(JSON.stringify(err)).not.toContain('203.0.113');
      expect((err as Error).message).not.toContain('203.0.113');
    }
  });

  it('tells a --output text user what to do instead of doing nothing', () => {
    // No braces means no documents, which would otherwise look like a
    // clean account.
    let raised: unknown;
    try {
      analyzeAll('SECURITYGROUPS\tsg-123\tdefault\tvpc-1', NOW);
    } catch (err) {
      raised = err;
    }
    expect(raised).toBeInstanceOf(ParseError);
    expect((raised as Error).message).toMatch(/--output json/);
  });

  it('says so for prose, too, rather than reporting a clean account', () => {
    expect(() => analyzeAll('there is nothing wrong with my account', NOW)).toThrow(
      ParseError,
    );
  });

  it('treats an empty paste as empty, not as an error', () => {
    const result = analyzeAll('   ', NOW);
    expect(result.recognized).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });

  it('reports the good documents when one of several is malformed', () => {
    // One bad document shouldn't discard the good ones.
    const result = analyzeAll(`${SG}\n{"Volumes": [`, NOW);
    expect(result.recognized.map((r) => r.kind)).toContain(INPUT_KINDS.securityGroups);
    expect(result.parseErrors).toHaveLength(1);
    expect(result.parseErrors[0].message).toMatch(/truncated/i);
  });
});

// ── scale ──────────────────────────────────────────────────────────────

describe('a big paste stays instant', () => {
  it('handles 500 groups and 500 volumes under 500ms', () => {
    const groups = JSON.stringify({
      SecurityGroups: Array.from({ length: 500 }, (_, i) => ({
        GroupId: `sg-${i}`,
        IpPermissions: [
          { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
        ],
      })),
    });
    const volumes = JSON.stringify({
      Volumes: Array.from({ length: 500 }, (_, i) => ({
        VolumeId: `vol-${i}`,
        VolumeType: 'gp2',
        Size: 100,
        State: 'in-use',
      })),
    });

    const started = performance.now();
    const result = analyzeAll(`${groups}\n${volumes}`, NOW);
    expect(performance.now() - started).toBeLessThan(500);
    // 500 SSH-open + 500 gp2→gp3 + 500 unencrypted; the fixture volumes set
    // no `Encrypted`, which is how AWS returns an unencrypted volume.
    expect(result.findings.length).toBe(1500);
  });
});
