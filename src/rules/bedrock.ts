/**
 * Bedrock rules.
 *
 * Everything here is configuration, and most of the interesting questions are
 * runtime ones — whether anyone is actually invoking a model, whether the
 * application passes its guardrail, whether a filter ever blocked anything.
 * None of that is in these responses, which is why nearly every severity here
 * is null.
 *
 * The one people don't expect: logging can be enabled and still record no
 * prompts at all.
 */

import type { AnalysisResult, Finding, Gap, Note, SourceKind } from '../types';

// Bedrock's API is lowerCamelCase (`loggingConfig`) where EC2's is PascalCase.
// Worth remembering when matching on keys.

export interface S3Config {
  bucketName?: string;
  keyPrefix?: string;
}

export interface CloudWatchConfig {
  logGroupName?: string;
  roleArn?: string;
  /** Payloads too big for CloudWatch spill here — a second store of the same text. */
  largeDataDeliveryS3Config?: S3Config;
}

export interface LoggingConfig {
  s3Config?: S3Config;
  cloudWatchConfig?: CloudWatchConfig;
  textDataDeliveryEnabled?: boolean;
  imageDataDeliveryEnabled?: boolean;
  embeddingDataDeliveryEnabled?: boolean;
  videoDataDeliveryEnabled?: boolean;
}

export interface LoggingResponse {
  loggingConfig?: LoggingConfig | null;
}

export interface Guardrail {
  id?: string;
  arn?: string;
  name?: string;
  status?: string;
  version?: string;
}

export interface BedrockInput {
  logging?: LoggingResponse;
  guardrails?: readonly Guardrail[];
}

export const BEDROCK_RULE_IDS = {
  guardrailNotReady: 'ai.guardrail-not-ready',
  guardrailDraftOnly: 'ai.guardrail-draft-only',
  largeDataSink: 'ai.large-data-delivery-sink',
  loggingOff: 'ai.invocation-logging-off',
  metadataOnly: 'ai.invocation-logging-metadata-only',
  sinkCarriesPrompts: 'ai.invocation-logs-carry-prompts',
  guardrailNotProvablyEnforced: 'ai.guardrail-enforcement-unverifiable',
} as const;

/**
 * Whether the logs contain request/response bodies rather than just metadata.
 * All four flags, not just text — an embeddings pipeline delivers
 * `embeddingData` and no text at all.
 */
const BODY_DELIVERY_FLAGS = [
  'textDataDeliveryEnabled',
  'imageDataDeliveryEnabled',
  'embeddingDataDeliveryEnabled',
  'videoDataDeliveryEnabled',
] as const;

const deliversBodies = (config: LoggingConfig): boolean =>
  BODY_DELIVERY_FLAGS.some((flag) => Boolean(config[flag]));

/**
 * Where the logs go, or null if nowhere. AWS accepts a `loggingConfig` with
 * delivery flags and no destination, in which case nothing is written — so
 * testing `loggingConfig !== null` is not enough.
 */
function describeDestination(config: LoggingConfig): string | null {
  const bucket = config.s3Config?.bucketName;
  const logGroup = config.cloudWatchConfig?.logGroupName;

  if (bucket && logGroup) return `s3://${bucket} and CloudWatch log group ${logGroup}`;
  if (bucket) return `s3://${bucket}`;
  if (logGroup) return `CloudWatch log group ${logGroup}`;
  return null;
}

/** Both inputs are optional and independent. */
export function analyzeBedrock(input: BedrockInput): AnalysisResult {
  const findings: Finding[] = [];
  const notes: Note[] = [];
  const gaps: Gap[] = [];

  const config = input.logging?.loggingConfig ?? null;
  const destination = config ? describeDestination(config) : null;

  if (input.logging !== undefined && destination === null) {
    findings.push({
      ruleId: BEDROCK_RULE_IDS.loggingOff,
      title: 'Model invocation logging is not recording anything',
      severity: null,
      // Whether anything is actually invoking a model is a runtime fact, so
      // the consequence is stated conditionally.
      unknowable:
        'Whether models are actually being invoked in this region — this ' +
        'response describes configuration, not traffic.',
      explanation:
        config === null
          ? 'GetModelInvocationLoggingConfiguration returned no configuration. ' +
            'If anything invokes a model in this region, there is no record of ' +
            'what was asked or what came back — nothing to investigate an ' +
            'incident with, and nothing to show an auditor.'
          : 'A logging configuration exists but names no destination — no S3 ' +
            'bucket and no CloudWatch log group — so nothing is written ' +
            'anywhere. Delivery flags alone do not create a log.',
      resource: 'model-invocation-logging',
      evidence: {
        locator: 'GetModelInvocationLoggingConfiguration',
        detail:
          config === null
            ? 'loggingConfig: null'
            : 'loggingConfig present, but no s3Config and no cloudWatchConfig',
      },
      fix: {
        console: [
          'Decide where the logs should land — a bucket or log group you ' +
            'already control and already know the read access of.',
          'Enable invocation logging against it.',
          'Turn on delivery for the data types you actually run, knowing the ' +
            'logs then inherit the sensitivity of the content.',
        ],
        cli:
          'aws bedrock put-model-invocation-logging-configuration ' +
          "--logging-config '{\"s3Config\":{\"bucketName\":\"<YOUR-BUCKET>\"}," +
          '"textDataDeliveryEnabled":true}\'',
      },
    });
  }

  if (config && destination !== null) {
    if (deliversBodies(config)) {
      findings.push({
        ruleId: BEDROCK_RULE_IDS.sinkCarriesPrompts,
        title: 'Your invocation logs contain prompts and completions',
        severity: null,
        unknowable:
          'Who can read that destination. Answering it needs ' +
          's3:GetBucketPolicyStatus and s3:GetBucketAcl, which this paste ' +
          'does not contain.',
        explanation:
          `Body delivery is on, so ${destination} receives the text sent to ` +
          'and returned by your models, verbatim. Worth checking who has read ' +
          'access to it.',
        resource:
          config.s3Config?.bucketName ??
          config.cloudWatchConfig?.logGroupName ??
          'log destination',
        evidence: {
          locator: destination,
          detail: BODY_DELIVERY_FLAGS.filter((flag) => Boolean(config[flag])).join(', '),
        },
        fix: {
          console: [
            'Check who can read the destination — it now holds prompt text.',
            'Narrow the read access to the people who should see it.',
            'Set a retention that matches how long you are willing to hold ' +
              'that content.',
          ],
          cli: config.s3Config?.bucketName
            ? `aws s3api get-bucket-policy-status --bucket ${config.s3Config.bucketName}`
            : 'aws logs describe-resource-policies',
        },
      });

      const overflow = config.cloudWatchConfig?.largeDataDeliveryS3Config?.bucketName;
      if (overflow) {
        notes.push({
          ruleId: BEDROCK_RULE_IDS.largeDataSink,
          title: 'A second bucket receives the oversized payloads',
          explanation:
            `Anything too large for CloudWatch spills into s3://${overflow}. ` +
            'It holds the same prompt and completion text as the main ' +
            'destination and is easy to miss when access to the primary one ' +
            'gets reviewed.',
          resource: overflow,
          evidence: { locator: overflow, detail: 'largeDataDeliveryS3Config' },
        });
      }

      if (config.s3Config?.bucketName) {
        gaps.push({
          ruleId: BEDROCK_RULE_IDS.sinkCarriesPrompts,
          resource: config.s3Config.bucketName,
          reason:
            `The logs land in ${config.s3Config.bucketName}, but this paste ` +
            'says nothing about who can read it. Run `aws s3api ' +
            `get-bucket-policy-status --bucket ${config.s3Config.bucketName}` +
            '` and `aws s3api get-bucket-acl --bucket ' +
            `${config.s3Config.bucketName}` +
            '` — a world-readable bucket here means your model traffic is ' +
            'public.',
        });
      }
    } else {
      findings.push({
        ruleId: BEDROCK_RULE_IDS.metadataOnly,
        title: 'Logging is on, but it is not recording any prompts',
        severity: null,
        unknowable:
          'Whether that is deliberate. Metadata-only is a reasonable choice ' +
          'if you are avoiding storing prompt text on purpose.',
        explanation:
          `Logging is enabled and writing to ${destination}, but every ` +
          'data-delivery flag is off. What you have is a record that a model ' +
          'was invoked — when, which one, by whom. What you do not have is ' +
          'what was asked or what it answered. In an investigation that is ' +
          'the difference between proving something happened and knowing ' +
          'what happened.',
        resource: 'model-invocation-logging',
        evidence: {
          locator: destination,
          detail: `all four delivery flags off: ${BODY_DELIVERY_FLAGS.join(', ')}`,
        },
        fix: {
          console: [
            'Decide whether you want prompt and completion text stored at ' +
              'all — the logs inherit its sensitivity the moment you do.',
            'If yes, enable delivery for the data types you actually run.',
            'If no, note this deliberately so the next person does not read ' +
              'it as a gap.',
          ],
          cli:
            'aws bedrock put-model-invocation-logging-configuration ' +
            "--logging-config '{...,\"textDataDeliveryEnabled\":true}'",
        },
      });
    }
  }

  const guardrails = input.guardrails ?? [];

  for (const g of guardrails) {
    if (!g.status || g.status === 'READY') continue;
    const label = g.name ?? g.id ?? '(unnamed)';
    findings.push({
      ruleId: BEDROCK_RULE_IDS.guardrailNotReady,
      title: `Guardrail "${label}" is not ready`,
      severity: null,
      unknowable:
        'Whether anything references it. A guardrail in this state either ' +
        'fails the call or lets it through unfiltered, depending on how the ' +
        'caller handles the error — and that lives in your code.',
      explanation:
        `Its status is ${g.status}, not READY, so it is not filtering ` +
        'anything right now.',
      resource: label,
      evidence: { locator: g.id ?? label, detail: `status ${g.status}` },
      fix: {
        console: [
          `Check why "${label}" is in ${g.status} — a failed create usually ` +
            'names the reason on the guardrail itself.',
          'Fix and re-create it, or remove it so nothing references a ' +
            'guardrail that is not working.',
        ],
        cli: `aws bedrock get-guardrail --guardrail-identifier ${g.id ?? '<ID>'}`,
      },
    });
  }

  if (guardrails.length > 0 && guardrails.every((g) => (g.version ?? 'DRAFT') === 'DRAFT')) {
    notes.push({
      ruleId: BEDROCK_RULE_IDS.guardrailDraftOnly,
      title: 'Every guardrail is still on DRAFT',
      explanation:
        'No numbered version has been published, so callers can only reference ' +
        'DRAFT — and DRAFT changes the moment someone edits it in the console. ' +
        'Publishing a version gives you something to pin and something to roll ' +
        'back to.',
      resource: `${guardrails.length} guardrail${guardrails.length === 1 ? "" : "s"}`,
      evidence: { locator: 'ListGuardrails', detail: 'all versions DRAFT' },
    });
  }

  if (guardrails.length > 0) {
    // A note, not a finding — having guardrails isn't a defect.
    notes.push({
      ruleId: BEDROCK_RULE_IDS.guardrailNotProvablyEnforced,
      title: `${guardrails.length} guardrail${guardrails.length === 1 ? '' : 's'} configured — but nothing here proves they run`,
      resource: `${guardrails.length} guardrail${guardrails.length === 1 ? "" : "s"}`,
      evidence: {
        locator: 'ListGuardrails',
        detail: guardrails
          .map((g) => g.name ?? g.id ?? '(unnamed)')
          .slice(0, 5)
          .join(', '),
      },
      explanation:
        `This account has ${guardrails.length} guardrail` +
        `${guardrails.length === 1 ? '' : 's'}. A guardrail is applied per ` +
        'request: the caller passes `guardrailIdentifier` on each InvokeModel ' +
        'call. Configuring one in the console does nothing on its own, and no ' +
        'AWS API can tell you whether your application passes it — that lives ' +
        'in your code. Worth grepping for, because a guardrail everyone ' +
        'believes is running and nothing references is the failure mode here.',
    });
  }

  // Reflects which input actually arrived.
  const source: SourceKind =
    input.logging !== undefined ? 'bedrock-logging' : 'bedrock-guardrails';

  return {
    findings,
    notes,
    gaps,
    examined: {
      source,
      resourceCount: (input.logging !== undefined ? 1 : 0) + guardrails.length,
      rulesRun: Object.values(BEDROCK_RULE_IDS),
    },
  };
}
