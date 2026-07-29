/**
 * These inputs are configuration, so a lot of what's asserted here is what the
 * rules refuse to claim — nothing about whether models are actually invoked,
 * and nothing about whether a configured guardrail is passed at runtime.
 */

import { describe, expect, it } from 'vitest';

import {
  BEDROCK_RULE_IDS,
  analyzeBedrock,
  type Guardrail,
  type LoggingResponse,
} from './bedrock';

const off: LoggingResponse = { loggingConfig: null };

const withS3 = (over: Record<string, unknown> = {}): LoggingResponse => ({
  loggingConfig: {
    s3Config: { bucketName: 'my-bedrock-logs', keyPrefix: 'prod/' },
    textDataDeliveryEnabled: true,
    ...over,
  },
});

const guardrail = (over: Partial<Guardrail> = {}): Guardrail => ({
  id: 'gr-0abc',
  name: 'content-filter',
  status: 'READY',
  version: 'DRAFT',
  ...over,
});

const ids = (r: { findings: { ruleId: string }[] }) => r.findings.map((f) => f.ruleId);

// ── logging off: the headline ──────────────────────────────────────────

describe('invocation logging switched off', () => {
  it('is flagged', () => {
    expect(ids(analyzeBedrock({ logging: off }))).toContain(
      BEDROCK_RULE_IDS.loggingOff,
    );
  });

  it('treats a config with no destination as off, because it is', () => {
    // A config with delivery flags and no destination writes nothing.
    const r = analyzeBedrock({ logging: { loggingConfig: { textDataDeliveryEnabled: true } } });
    expect(ids(r)).toContain(BEDROCK_RULE_IDS.loggingOff);
  });

  it('does not claim anyone is actually invoking models', () => {
    // Whether traffic exists is a runtime fact this input can't carry.
    const f = analyzeBedrock({ logging: off }).findings[0];
    expect(f.severity).toBeNull();
    expect(f.unknowable).toMatch(/configuration, not traffic|actually being invoked/i);
  });

  it('is silent when logging is properly on', () => {
    expect(ids(analyzeBedrock({ logging: withS3() }))).not.toContain(
      BEDROCK_RULE_IDS.loggingOff,
    );
  });
});

// ── the surprise ───────────────────────────────────────────────────────

describe('logging on, but recording no prompts', () => {
  it('flags a config where every body-delivery flag is off', () => {
    const r = analyzeBedrock({
      logging: withS3({
        textDataDeliveryEnabled: false,
        imageDataDeliveryEnabled: false,
        embeddingDataDeliveryEnabled: false,
        videoDataDeliveryEnabled: false,
      }),
    });
    expect(ids(r)).toContain(BEDROCK_RULE_IDS.metadataOnly);
  });

  it('says what you would and would not have in an investigation', () => {
    const r = analyzeBedrock({ logging: withS3({ textDataDeliveryEnabled: false }) });
    const f = r.findings.find((x) => x.ruleId === BEDROCK_RULE_IDS.metadataOnly)!;
    expect(f.explanation).toMatch(/that a model was invoked/i);
  });

  it('checks all four flags, not just text', () => {
    // An embeddings pipeline delivers embeddingData and no text at all.
    const r = analyzeBedrock({
      logging: withS3({ textDataDeliveryEnabled: false, embeddingDataDeliveryEnabled: true }),
    });
    expect(ids(r)).not.toContain(BEDROCK_RULE_IDS.metadataOnly);
  });

  it('is not raised when logging is off entirely', () => {
    // Otherwise logging-off accounts get two findings for one problem.
    expect(ids(analyzeBedrock({ logging: off }))).not.toContain(
      BEDROCK_RULE_IDS.metadataOnly,
    );
  });
});

// ── the sink ───────────────────────────────────────────────────────────

describe('logs that carry prompts and completions', () => {
  it('names the bucket receiving them', () => {
    const r = analyzeBedrock({ logging: withS3() });
    const f = r.findings.find((x) => x.ruleId === BEDROCK_RULE_IDS.sinkCarriesPrompts)!;
    expect(f.explanation).toContain('my-bedrock-logs');
  });

  it('names a CloudWatch destination too', () => {
    const r = analyzeBedrock({
      logging: {
        loggingConfig: {
          cloudWatchConfig: { logGroupName: '/aws/bedrock/invocations' },
          textDataDeliveryEnabled: true,
        },
      },
    });
    const f = r.findings.find((x) => x.ruleId === BEDROCK_RULE_IDS.sinkCarriesPrompts)!;
    expect(f.explanation).toContain('/aws/bedrock/invocations');
  });

  it('never claims the sink is or is not exposed', () => {
    // That needs s3:GetBucketPolicyStatus and s3:GetBucketAcl.
    const f = analyzeBedrock({ logging: withS3() }).findings.find(
      (x) => x.ruleId === BEDROCK_RULE_IDS.sinkCarriesPrompts,
    )!;
    expect(f.severity).toBeNull();
    expect(`${f.title} ${f.explanation}`).not.toMatch(/\bpublic\b|world-readable|exposed/i);
  });

  it('hands over the commands that would answer it', () => {
    const r = analyzeBedrock({ logging: withS3() });
    const gap = r.gaps.find((g) => g.reason.includes('get-bucket-policy-status'));
    expect(gap).toBeDefined();
    expect(gap!.reason).toContain('my-bedrock-logs');
  });

  it('raises no S3 gap when the destination is CloudWatch only', () => {
    const r = analyzeBedrock({
      logging: {
        loggingConfig: {
          cloudWatchConfig: { logGroupName: '/aws/bedrock' },
          textDataDeliveryEnabled: true,
        },
      },
    });
    expect(r.gaps.some((g) => g.reason.includes('get-bucket-policy-status'))).toBe(false);
  });
});

// ── guardrails: the honest limit ───────────────────────────────────────

describe('guardrails', () => {
  it('does not nag an account with none — that is not evidence of anything', () => {
    // Plenty of legitimate Bedrock use needs no guardrail.
    const r = analyzeBedrock({ logging: withS3(), guardrails: [] });
    expect(ids(r)).not.toContain(BEDROCK_RULE_IDS.guardrailNotProvablyEnforced);
  });

  it('records the enforcement gap as a NOTE, not a finding', () => {
    // Having guardrails isn't a defect, so it shouldn't inflate the count.
    const r = analyzeBedrock({ logging: withS3(), guardrails: [guardrail()] });
    expect(ids(r)).not.toContain(BEDROCK_RULE_IDS.guardrailNotProvablyEnforced);
    expect(r.notes.map((n) => n.ruleId)).toContain(
      BEDROCK_RULE_IDS.guardrailNotProvablyEnforced,
    );
  });

  it('explains that a guardrail is passed per request, not attached', () => {
    // A guardrail does nothing unless the caller passes guardrailIdentifier
    // on InvokeModel, and no API reports whether it does.
    const note = analyzeBedrock({ logging: withS3(), guardrails: [guardrail()] })
      .notes.find((n) => n.ruleId === BEDROCK_RULE_IDS.guardrailNotProvablyEnforced)!;
    expect(note.explanation).toMatch(/guardrailIdentifier|per request/i);
  });

  it('counts them without naming what it cannot verify', () => {
    const r = analyzeBedrock({
      logging: withS3(),
      guardrails: [guardrail({ id: 'gr-1' }), guardrail({ id: 'gr-2' })],
    });
    const note = r.notes.find((n) => n.ruleId === BEDROCK_RULE_IDS.guardrailNotProvablyEnforced)!;
    expect(note.explanation).toContain('2');
  });
});

// ── guardrail state ────────────────────────────────────────────────────

describe('guardrails that are not doing anything yet', () => {
  it('flags one that is not READY', () => {
    const r = analyzeBedrock({
      logging: withS3(),
      guardrails: [guardrail({ status: 'FAILED' })],
    });
    expect(ids(r)).toContain(BEDROCK_RULE_IDS.guardrailNotReady);
  });

  it('names the status rather than describing it vaguely', () => {
    const f = analyzeBedrock({
      logging: withS3(),
      guardrails: [guardrail({ status: 'FAILED', name: 'pii-filter' })],
    }).findings.find((x) => x.ruleId === BEDROCK_RULE_IDS.guardrailNotReady)!;
    expect(f.evidence.detail).toContain('FAILED');
    expect(f.resource).toContain('pii-filter');
  });

  it('grades it null — whether anything references it is a runtime fact', () => {
    const f = analyzeBedrock({
      logging: withS3(),
      guardrails: [guardrail({ status: 'FAILED' })],
    }).findings.find((x) => x.ruleId === BEDROCK_RULE_IDS.guardrailNotReady)!;
    expect(f.severity).toBeNull();
    expect(f.unknowable).toBeTruthy();
  });

  it('says nothing about a READY one', () => {
    const r = analyzeBedrock({ logging: withS3(), guardrails: [guardrail()] });
    expect(ids(r)).not.toContain(BEDROCK_RULE_IDS.guardrailNotReady);
  });

  it('notes when every guardrail is still on DRAFT', () => {
    const r = analyzeBedrock({ logging: withS3(), guardrails: [guardrail({ version: 'DRAFT' })] });
    const note = r.notes.find((n) => n.ruleId === BEDROCK_RULE_IDS.guardrailDraftOnly);
    expect(note).toBeDefined();
    expect(note!.explanation).toMatch(/version/i);
  });

  it('says nothing when a numbered version exists', () => {
    const r = analyzeBedrock({ logging: withS3(), guardrails: [guardrail({ version: '3' })] });
    expect(r.notes.map((n) => n.ruleId)).not.toContain(BEDROCK_RULE_IDS.guardrailDraftOnly);
  });
});

// ── the second log sink people forget ──────────────────────────────────

describe('large-data delivery bucket', () => {
  it('names it, because it holds the same prompt text', () => {
    const r = analyzeBedrock({
      logging: {
        loggingConfig: {
          cloudWatchConfig: {
            logGroupName: '/aws/bedrock',
            largeDataDeliveryS3Config: { bucketName: 'overflow-bucket' },
          },
          textDataDeliveryEnabled: true,
        },
      },
    });
    const note = r.notes.find((n) => n.ruleId === BEDROCK_RULE_IDS.largeDataSink);
    expect(note).toBeDefined();
    expect(note!.explanation).toContain('overflow-bucket');
  });

  it('says nothing when there is no overflow bucket', () => {
    const r = analyzeBedrock({ logging: withS3() });
    expect(r.notes.map((n) => n.ruleId)).not.toContain(BEDROCK_RULE_IDS.largeDataSink);
  });

  it('says nothing when bodies are not delivered at all', () => {
    const r = analyzeBedrock({
      logging: {
        loggingConfig: {
          cloudWatchConfig: {
            logGroupName: '/aws/bedrock',
            largeDataDeliveryS3Config: { bucketName: 'overflow-bucket' },
          },
          textDataDeliveryEnabled: false,
        },
      },
    });
    expect(r.notes.map((n) => n.ruleId)).not.toContain(BEDROCK_RULE_IDS.largeDataSink);
  });
});

// ── robustness ─────────────────────────────────────────────────────────

describe('odd shapes never throw', () => {
  it.each([
    ['nothing at all', {}],
    ['an empty logging response', { logging: {} as LoggingResponse }],
    ['a null config with guardrails', { logging: off, guardrails: [guardrail()] }],
    ['an empty guardrail object', { logging: off, guardrails: [{} as Guardrail] }],
  ])('survives %s', (_label, input) => {
    expect(() => analyzeBedrock(input as Parameters<typeof analyzeBedrock>[0])).not.toThrow();
  });

  it('returns nothing at all when given nothing', () => {
    const r = analyzeBedrock({});
    expect(r.findings).toHaveLength(0);
    expect(r.notes).toHaveLength(0);
  });
});
