/**
 * Core types.
 *
 * The engine only ever sees one pasted CLI response — no account context, no
 * second API call, no metrics. The types are shaped so a claim we can't back
 * up is awkward to express: `severity` is nullable, findings carry the
 * evidence they came from, and unanswerable questions have their own type.
 */

/** Standard severity levels. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Which pasted document a finding came from. */
export type SourceKind =
  | 'security-groups'
  | 'volumes'
  | 'addresses'
  | 'snapshots'
  | 'bedrock-logging'
  | 'bedrock-guardrails';

export interface Evidence {
  /** e.g. `sg-0abc123` */
  readonly locator: string;
  /** The values the rule matched on — not the whole document. */
  readonly detail: string;
}

export interface Fix {
  /** Ordered steps. */
  readonly console: readonly string[];
  /**
   * A runnable command. Placeholders are bracketed and uppercase
   * (`<YOUR-TRUSTED-CIDR>`) so a blind copy-paste fails instead of running
   * against the wrong scope.
   */
  readonly cli: string;
}

export interface Finding {
  readonly ruleId: string;
  readonly title: string;
  readonly explanation: string;
  /** Null when the input can't support a grade. Render `unknowable`, don't default. */
  readonly severity: Severity | null;
  /** Why there's no severity. Set whenever severity is null. */
  readonly unknowable?: string;
  readonly resource: string;
  readonly evidence: Evidence;
  readonly fix: Fix;
  /** Why this one is dangerous, where that isn't obvious. Omit otherwise. */
  readonly why?: string;
  /**
   * Monthly cost, where the input supports the arithmetic. `basis` is required
   * next to the number so a caller can't render the figure without the caveat
   * that it's a us-east-1 list rate.
   */
  readonly cost?: {
    readonly monthlyUsd: number;
    readonly basis: string;
  };
}

/** Something worth seeing that isn't a problem. Keeps findings from inflating. */
export interface Note {
  readonly ruleId: string;
  readonly title: string;
  readonly explanation: string;
  readonly resource: string;
  readonly evidence: Evidence;
}

/**
 * Something referenced in the input that we couldn't evaluate — a managed
 * prefix list, for instance, whose contents aren't in the response. Reported
 * rather than guessed at or silently skipped.
 */
export interface Gap {
  readonly ruleId: string;
  readonly resource: string;
  /** What we could not determine, and what would be needed to determine it. */
  readonly reason: string;
}

export interface AnalysisResult {
  readonly findings: readonly Finding[];
  readonly notes: readonly Note[];
  readonly gaps: readonly Gap[];
  /** What was read. Lets a clean result be told apart from a no-op. */
  readonly examined: {
    readonly source: SourceKind;
    readonly resourceCount: number;
    readonly rulesRun: readonly string[];
  };
}

/**
 * Parse failure carrying a position and a diagnosis, never the source text.
 * V8 puts a slice of the offending input into `SyntaxError.message`, which
 * would then reach any error reporter — see `parse/json.ts`.
 */
export class ParseError extends Error {
  /** What is wrong, in the user's terms. Contains no input-derived text. */
  readonly diagnosis: string;
  /** Character offset when known — enough to locate, not to reconstruct. */
  readonly position?: number;

  // Explicit fields rather than constructor parameter properties, which are
  // TS-only syntax and break under Node's type stripping.
  constructor(diagnosis: string, position?: number) {
    super(diagnosis);
    this.name = 'ParseError';
    this.diagnosis = diagnosis;
    this.position = position;
  }
}
