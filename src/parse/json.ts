/**
 * JSON parsing that never echoes the input back.
 *
 * V8 puts a slice of the offending text into the error message:
 *
 *   JSON.parse('{"SecurityGroups": [{"GroupId": sg-0abc}]}')
 *   → SyntaxError: Unexpected token 's', ..."GroupId": sg-0abc}]}" is not valid JSON
 *
 * Anything that captures errors would then be holding a piece of whatever was
 * pasted. Catching it here and rethrowing our own error is more reliable than
 * scrubbing further down, and the diagnosis ends up more useful than V8's.
 */

import { ParseError } from '../types';

/** Pull just the offset out of a native SyntaxError. */
function positionOf(err: unknown): number | undefined {
  // V8 says "... in JSON at position 123"; take the number, drop the rest.
  const message = err instanceof Error ? err.message : '';
  const atPosition = /position (\d+)/.exec(message);
  if (atPosition) return Number(atPosition[1]);
  return undefined;
}

/**
 * Work out what's wrong from the shape of the document — length, bracket
 * balance, a trailing comma. Every returned string is a constant.
 */
function diagnose(raw: string, position: number | undefined): string {
  const trimmed = raw.trim();

  if (trimmed.length === 0) {
    return 'Nothing was pasted.';
  }

  if (!/^[[{]/.test(trimmed)) {
    // Usually `--output text` or a configured `table` — neither has braces.
    return (
      'This does not start with { or [, so it is not JSON. If the AWS CLI ' +
      'printed a table or tab-separated text, re-run the command with ' +
      '`--output json`. If it is JSON, paste the whole response including ' +
      'the outermost braces — not just one section of it.'
    );
  }

  // Usually a scrollback buffer cutting the output short.
  const opens = (trimmed.match(/[[{]/g) ?? []).length;
  const closes = (trimmed.match(/[\]}]/g) ?? []).length;
  if (opens > closes) {
    return (
      'The JSON ends before it is closed — it looks truncated. If you copied ' +
      'from a terminal, the output may have been cut off by the scrollback ' +
      'buffer. Try `... --output json > file.json` and paste the file.'
    );
  }
  if (closes > opens) {
    return 'There are more closing brackets than opening ones.';
  }

  if (/,\s*[\]}]/.test(trimmed)) {
    return 'There is an extra comma just before a closing bracket or brace.';
  }

  if (/'/.test(trimmed) && !/"/.test(trimmed)) {
    return (
      'This uses single quotes. JSON requires double quotes — if you printed ' +
      'this from Python, use `json.dumps` rather than `print`.'
    );
  }

  return position === undefined
    ? 'This is not valid JSON.'
    : `This is not valid JSON — the problem starts around character ${position}.`;
}

/**
 * Parse untrusted text.
 *
 * @throws {ParseError} always — a native `SyntaxError` never escapes.
 */
export function safeParseJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch (err) {
    // Don't attach the original as `cause` — reporters serialise it, which
    // puts the input text back into the error.
    throw new ParseError(diagnose(raw, positionOf(err)), positionOf(err));
  }
}

/**
 * Unwrap a CLI response envelope. Takes the full response or a bare array,
 * since anyone piping through `jq` will have the latter.
 */
export function unwrapList(value: unknown, key: string): readonly unknown[] {
  if (Array.isArray(value)) return value;

  if (value !== null && typeof value === 'object') {
    const envelope = value as Record<string, unknown>;
    const list = envelope[key];
    if (Array.isArray(list)) return list;

    // Valid JSON of the wrong shape is confusing — the paste worked, so name
    // both the key we wanted and the ones that are there.
    const keys = Object.keys(envelope);
    if (keys.length > 0) {
      throw new ParseError(
        `This JSON is valid, but it has no "${key}" list — it contains ` +
          `${keys.slice(0, 4).map((k) => `"${k}"`).join(', ')}` +
          `${keys.length > 4 ? ', …' : ''}. Check you ran the right command.`,
      );
    }
  }

  throw new ParseError(
    `Expected a "${key}" list, or an array. Paste the full output of the ` +
      'command shown above.',
  );
}
