/**
 * Works out which commands produced a paste, so callers can offer one input
 * box instead of one per command. The envelope key is enough: `Volumes`,
 * `SecurityGroups`, `loggingConfig`.
 *
 * Handles several documents pasted together, in any order, with or without
 * separators. Anything unrecognised is reported rather than dropped — a
 * document that was never read looks the same as a clean one otherwise.
 */

import { safeParseJson } from './parse/json';
import { analyzeAddresses, analyzeSnapshots, analyzeVolumes } from './rules/cost';
import { analyzeBedrock, type Guardrail, type LoggingResponse } from './rules/bedrock';
import { analyzeSecurityGroups, type SecurityGroup, type SgAnalysis } from './rules/securityGroups';
import { ParseError, type AnalysisResult, type Finding, type Gap, type Note } from './types';

export const INPUT_KINDS = {
  securityGroups: 'security-groups',
  volumes: 'volumes',
  addresses: 'addresses',
  snapshots: 'snapshots',
  bedrockLogging: 'bedrock-logging',
  guardrails: 'bedrock-guardrails',
} as const;

export type InputKind = (typeof INPUT_KINDS)[keyof typeof INPUT_KINDS];

export interface RecognizedInput {
  kind: InputKind;
  /** How many items arrived. */
  count: number;
}

export interface UnrecognizedInput {
  /** The top-level keys we saw. Names only — values are never echoed. */
  keys: string[];
}

export interface FullResult {
  findings: Finding[];
  notes: Note[];
  gaps: Gap[];
  /** One entry per document read, not a merged total. */
  examined: AnalysisResult['examined'][];
  recognized: RecognizedInput[];
  unrecognized: UnrecognizedInput[];
  parseErrors: ParseError[];
}

/**
 * One entry per input we know how to read.
 *
 * `looksLike` handles bare arrays, which have no envelope to key on. Note the
 * casing: EC2 uses PascalCase and Bedrock lowerCamelCase, so both spellings
 * have to be listed as AWS returns them.
 */
interface KindSpec {
  kind: InputKind;
  envelopeKey: string;
  label: string;
  command: string;
  /** True when this element could only have come from this command. */
  looksLike: (item: Record<string, unknown>) => boolean;
}

const SPECS: readonly KindSpec[] = [
  {
    kind: INPUT_KINDS.securityGroups,
    envelopeKey: 'SecurityGroups',
    label: 'Security groups',
    command: 'aws ec2 describe-security-groups --output json',
    looksLike: (i) => 'GroupId' in i || 'IpPermissions' in i,
  },
  {
    kind: INPUT_KINDS.volumes,
    envelopeKey: 'Volumes',
    label: 'EBS volumes',
    command: 'aws ec2 describe-volumes --output json',
    looksLike: (i) => 'VolumeId' in i,
  },
  {
    kind: INPUT_KINDS.addresses,
    envelopeKey: 'Addresses',
    label: 'Elastic IPs',
    command: 'aws ec2 describe-addresses --output json',
    looksLike: (i) => 'PublicIp' in i || 'AllocationId' in i,
  },
  {
    kind: INPUT_KINDS.snapshots,
    envelopeKey: 'Snapshots',
    label: 'EBS snapshots',
    command: 'aws ec2 describe-snapshots --owner-ids self --output json',
    looksLike: (i) => 'SnapshotId' in i,
  },
  {
    kind: INPUT_KINDS.bedrockLogging,
    envelopeKey: 'loggingConfig',
    label: 'Bedrock invocation logging',
    command:
      'aws bedrock get-model-invocation-logging-configuration --output json',
    // Never inferred from a bare array — it is an object, not a list.
    looksLike: () => false,
  },
  {
    kind: INPUT_KINDS.guardrails,
    envelopeKey: 'guardrails',
    label: 'Bedrock guardrails',
    command: 'aws bedrock list-guardrails --output json',
    looksLike: (i) => 'guardrailId' in i || ('id' in i && 'arn' in i),
  },
];

export interface MissingInput {
  kind: InputKind;
  label: string;
  command: string;
}

/** What else this account could be checked for, and how to produce it. */
export function describeMissing(result: FullResult): MissingInput[] {
  const have = new Set(result.recognized.map((r) => r.kind));
  return SPECS.filter((spec) => !have.has(spec.kind)).map(({ kind, label, command }) => ({
    kind,
    label,
    command,
  }));
}

/**
 * Split concatenated JSON documents by walking brace depth.
 *
 * Copying a whole terminal window gives you several complete documents with no
 * separator, which `JSON.parse` rejects outright. Tracks strings and escapes,
 * since AWS puts braces inside descriptions and tag values.
 */
function splitDocuments(raw: string): string[] {
  const documents: string[] = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;

  for (let i = 0; i < raw.length; i += 1) {
    const char = raw[i];

    if (inString) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }

    if (char === '"') {
      inString = true;
      continue;
    }

    if (char === '{' || char === '[') {
      if (depth === 0) start = i;
      depth += 1;
      continue;
    }

    if (char === '}' || char === ']') {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        documents.push(raw.slice(start, i + 1));
        start = -1;
      }
      // Unbalanced closer — reset rather than let depth go negative.
      if (depth < 0) depth = 0;
      continue;
    }
  }

  // Never closed — probably truncated. Keep it so the parser can say so.
  if (depth > 0 && start >= 0) documents.push(raw.slice(start));

  return documents;
}

/**
 * Clean up the ways a paste gets mangled between the terminal and the box.
 *
 * Everything here is either invalid JSON to begin with (smart quotes, trailing
 * commas) or outside the JSON entirely (fences, line numbers), so none of it
 * can corrupt input that was already fine.
 */
function normalize(raw: string): string {
  let text = raw.replace(/\r\n?/g, '\n');

  // Markdown fences, from chat apps and docs.
  text = text.replace(/^\s*```[a-z]*\s*$/gim, '');

  // Word processors and browsers substitute these; JSON accepts neither.
  text = text
    .replace(/[\u201c\u201d\u201e\u201f]/g, '"')
    .replace(/[\u2018\u2019\u201a\u201b]/g, "'")
    .replace(/[\u00a0\u2007\u202f\u2009]/g, ' ');

  // Editor and diff-view gutters: `12  {` or `12 | {`. Only stripped when most
  // non-blank lines look that way, so a stray number in the data is safe.
  const lines = text.split('\n');
  const nonBlank = lines.filter((l) => l.trim() !== '');
  const gutter = /^\s*\d+\s*(\||\t|\s\s)\s*/;
  if (nonBlank.length > 2 && nonBlank.filter((l) => gutter.test(l)).length > nonBlank.length * 0.8) {
    text = lines.map((l) => l.replace(gutter, '')).join('\n');
  }

  // Trailing commas, from hand edits.
  text = text.replace(/,(\s*[}\]])/g, '$1');

  return text;
}

/**
 * Walk a balanced `{}` or `[]` starting at `open`, and return the index just
 * past its close — or -1 if it never closes. String- and escape-aware.
 */
function balancedEnd(raw: string, open: number): number {
  const closer = raw[open] === '{' ? '}' : ']';
  const opener = raw[open];
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = open; i < raw.length; i += 1) {
    const char = raw[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') inString = true;
    else if (char === opener) depth += 1;
    else if (char === closer) {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

/**
 * Last resort when nothing parsed cleanly.
 *
 * Terminal pagers redraw the screen as you scroll, so a paste can be several
 * truncated copies of the same output separated by `:` prompts, with the final
 * complete screen missing the opening brace that scrolled off the top. There's
 * no balanced object anywhere in that, but the arrays inside it are intact.
 *
 * So: find each `"Key": [` for a key we know, take the balanced array after
 * it, and keep the ones that parse. Same for `"loggingConfig":`, which is an
 * object. Repeated screens produce repeated matches, which the caller dedupes.
 */
function recoverPayloads(raw: string): Array<{ spec: KindSpec; payload: unknown }> {
  const found: Array<{ spec: KindSpec; payload: unknown }> = [];

  for (const spec of SPECS) {
    const key = `"${spec.envelopeKey}"`;
    let from = 0;
    for (;;) {
      const at = raw.indexOf(key, from);
      if (at === -1) break;
      from = at + key.length;

      // Skip the colon and any whitespace after the key.
      let i = from;
      while (i < raw.length && /\s/.test(raw[i])) i += 1;
      if (raw[i] !== ':') continue;
      i += 1;
      while (i < raw.length && /\s/.test(raw[i])) i += 1;

      if (raw[i] === '[' || raw[i] === '{') {
        const end = balancedEnd(raw, i);
        if (end === -1) continue;
        try {
          found.push({ spec, payload: JSON.parse(raw.slice(i, end)) });
          from = end;
        } catch {
          // Not complete after all; keep looking for a later copy.
        }
      } else if (raw.startsWith('null', i)) {
        found.push({ spec, payload: null });
      }
    }
  }

  return found;
}

function classify(document: unknown): { spec: KindSpec; payload: unknown } | null {
  if (Array.isArray(document)) {
    const first = document.find((item) => item && typeof item === 'object');
    if (!first) return null;
    const spec = SPECS.find((s) => s.looksLike(first as Record<string, unknown>));
    return spec ? { spec, payload: document } : null;
  }

  if (document && typeof document === 'object') {
    const envelope = document as Record<string, unknown>;
    // `in`, not truthiness — `{"loggingConfig": null}` is what Bedrock
    // returns when logging is off, and that's the thing we want to report.
    const spec = SPECS.find((s) => s.envelopeKey in envelope);
    if (spec) return { spec, payload: envelope[spec.envelopeKey] };

    // A single item with no envelope: `jq '.SecurityGroups[]'` emits these
    // one per line, and people paste one object to ask about it.
    const bare = SPECS.find((s) => s.looksLike(envelope));
    if (bare) return { spec: bare, payload: [envelope] };
  }

  return null;
}

const asList = <T,>(value: unknown): T[] => (Array.isArray(value) ? (value as T[]) : []);

/**
 * Analyse whatever was pasted. `now` is injected so snapshot ages are
 * deterministic in tests.
 *
 * @throws {ParseError} only when nothing at all could be read. A malformed
 * document alongside valid ones lands in `parseErrors` instead.
 */
export function analyzeAll(raw: string, now: Date): FullResult {
  const findings: Finding[] = [];
  const notes: Note[] = [];
  const gaps: Gap[] = [];
  const examined: AnalysisResult['examined'][] = [];
  const recognized: RecognizedInput[] = [];
  const unrecognized: UnrecognizedInput[] = [];
  const parseErrors: ParseError[] = [];

  if (!raw.trim()) {
    return { findings, notes, gaps, examined, recognized, unrecognized, parseErrors };
  }

  // Merge by kind first, so the same output pasted twice isn't double-counted.
  const byKind = new Map<InputKind, unknown[]>();
  const pendingRecovery = new Map<InputKind, unknown[]>();
  const seenDocuments = new Set<string>();
  let bedrockLogging: LoggingResponse | undefined;

  const text = normalize(raw);

  for (const document of splitDocuments(text)) {
    const fingerprint = document.replace(/\s+/g, '');
    if (seenDocuments.has(fingerprint)) continue;
    seenDocuments.add(fingerprint);

    let parsed: unknown;
    try {
      parsed = safeParseJson(document);
    } catch (err) {
      if (err instanceof ParseError) parseErrors.push(err);
      continue;
    }

    const classified = classify(parsed);
    if (!classified) {
      const keys =
        parsed && typeof parsed === 'object' && !Array.isArray(parsed)
          ? Object.keys(parsed as Record<string, unknown>)
          : ['(a list of items we have no rules for)'];
      unrecognized.push({ keys });
      continue;
    }

    if (classified.spec.kind === INPUT_KINDS.bedrockLogging) {
      bedrockLogging = { loggingConfig: (classified.payload ?? null) as never };
      recognized.push({ kind: classified.spec.kind, count: 1 });
      continue;
    }

    const items = asList(classified.payload);
    byKind.set(classified.spec.kind, [...(byKind.get(classified.spec.kind) ?? []), ...items]);
  }

  // Fill in kinds the document pass missed. Runs per kind rather than only
  // when everything failed, so one mangled section doesn't disappear just
  // because another section parsed cleanly.
  const recovered = recoverPayloads(text);
  for (const { spec, payload } of recovered) {
    if (spec.kind === INPUT_KINDS.bedrockLogging) {
      if (bedrockLogging !== undefined) continue;
      bedrockLogging = { loggingConfig: (payload ?? null) as never };
      recognized.push({ kind: spec.kind, count: 1 });
      continue;
    }
    if (byKind.has(spec.kind)) continue;
    const items = asList(payload);
    const seen = pendingRecovery.get(spec.kind);
    // Repeated screens from a pager are the same data; keep the longest.
    if (!seen || items.length > seen.length) pendingRecovery.set(spec.kind, items);
  }
  const docPassFoundNothing = byKind.size === 0;
  for (const [kind, items] of pendingRecovery) byKind.set(kind, items);

  // Only drop the parse errors when recovery replaced a total failure — that
  // is the pager case, where every error came from a half-drawn screen of the
  // same output. If the document pass DID read something, a leftover error is
  // about a genuinely separate broken document and is worth showing.
  if (docPassFoundNothing && (byKind.size > 0 || bedrockLogging !== undefined)) {
    parseErrors.length = 0;
  }

  const absorb = (result: AnalysisResult | SgAnalysis) => {
    findings.push(...result.findings);
    notes.push(...result.notes);
    gaps.push(...result.gaps);
    examined.push(result.examined);
  };

  for (const [kind, items] of byKind) {
    recognized.push({ kind, count: items.length });

    switch (kind) {
      case INPUT_KINDS.securityGroups:
        absorb(analyzeSecurityGroups(items as SecurityGroup[]));
        break;
      case INPUT_KINDS.volumes:
        absorb(analyzeVolumes(items as Parameters<typeof analyzeVolumes>[0]));
        break;
      case INPUT_KINDS.addresses:
        absorb(analyzeAddresses(items as Parameters<typeof analyzeAddresses>[0]));
        break;
      case INPUT_KINDS.snapshots:
        // Volumes from the same paste, when there were any — lets a snapshot
        // whose source is gone be identified.
        absorb(
          analyzeSnapshots(
            items as Parameters<typeof analyzeSnapshots>[0],
            now,
            byKind.get(INPUT_KINDS.volumes) as Parameters<typeof analyzeSnapshots>[2],
          ),
        );
        break;
      default:
        break;
    }
  }

  const guardrails = byKind.get(INPUT_KINDS.guardrails) as Guardrail[] | undefined;
  if (bedrockLogging !== undefined || guardrails !== undefined) {
    absorb(analyzeBedrock({ logging: bedrockLogging, guardrails }));
  }

  // Nothing readable: raise rather than return an empty result, which a
  // caller can't tell apart from a clean account. `--output text` is the
  // common case — no braces at all, so nothing to split.
  if (recognized.length === 0 && unrecognized.length === 0) {
    if (parseErrors.length > 0) throw parseErrors[0];
    // Through the same parser, so the diagnosis lives in one place.
    safeParseJson(text);
  }

  return { findings, notes, gaps, examined, recognized, unrecognized, parseErrors };
}
