/**
 * The important one here is that a parse error never contains the input. V8
 * puts a slice of the offending text into the message, so anything capturing
 * errors would otherwise be holding a piece of whatever was pasted.
 */

import { describe, expect, it } from 'vitest';

import { ParseError } from '../types';
import { safeParseJson, unwrapList } from './json';

/** A canary that must never appear in any thrown error. */
const SECRET = '203.0.113.77/32';

describe('a parse error never contains the input', () => {
  it('drops the fragment V8 puts in SyntaxError.message', () => {
    const malformed = `{"IpRanges": [{"CidrIp": "${SECRET}"},,]}`;

    // Check the native error really does echo the input, so this can't pass
    // for the wrong reason on some future engine. `length > 0` used to stand
    // in for this and did not: V8 truncates to a ~15-character tail, so the
    // whole SECRET never appears in the native message either, and the canary
    // assertion below was passing without the leak channel being real.
    let nativeMessage = '';
    try {
      JSON.parse(malformed);
    } catch (e) {
      nativeMessage = (e as Error).message;
    }
    expect(nativeMessage).toContain('3.77/32');

    try {
      safeParseJson(malformed);
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(ParseError);
      const serialised = JSON.stringify({
        message: (err as Error).message,
        name: (err as Error).name,
        stack: (err as Error).stack,
        // Anything an error reporter might walk.
        ...(err as unknown as Record<string, unknown>),
      });
      expect(serialised).not.toContain(SECRET);
      expect(serialised).not.toContain('203.0.113');
    }
  });

  it('does not attach the native error as `cause`', () => {
    // Reporters serialise `cause`, which would put the input text back.
    try {
      safeParseJson(`{"CidrIp": "${SECRET}",,}`);
    } catch (err) {
      expect((err as { cause?: unknown }).cause).toBeUndefined();
    }
  });
});

describe('the diagnosis is useful, not just safe', () => {
  it('names truncation, the most common real failure', () => {
    const truncated = '{"SecurityGroups": [{"GroupId": "sg-0abc", "IpPermissions": [';
    expect(() => safeParseJson(truncated)).toThrow(/truncated/i);
  });

  it('names a trailing comma', () => {
    expect(() => safeParseJson('{"a": 1,}')).toThrow(/extra comma/i);
  });

  it('names single quotes and points at the likely cause', () => {
    expect(() => safeParseJson("{'a': 1}")).toThrow(/single quotes/i);
  });

  it('says so plainly when nothing was pasted', () => {
    expect(() => safeParseJson('   ')).toThrow(/Nothing was pasted/i);
  });

  it('catches a partial paste that does not start with a brace', () => {
    expect(() => safeParseJson('"GroupId": "sg-0abc"')).toThrow(/start with/i);
  });
});

describe('unwrapping the CLI envelope', () => {
  it('accepts the full response', () => {
    expect(unwrapList({ SecurityGroups: [{ GroupId: 'sg-1' }] }, 'SecurityGroups'))
      .toHaveLength(1);
  });

  it('accepts a bare array, because jq users paste that', () => {
    expect(unwrapList([{ GroupId: 'sg-1' }], 'SecurityGroups')).toHaveLength(1);
  });

  it('names the keys actually present when the wrong command was run', () => {
    // The confusing case: valid JSON, so the user expects results.
    try {
      unwrapList({ Volumes: [], NextToken: 'x' }, 'SecurityGroups');
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as Error).message).toContain('SecurityGroups');
      expect((err as Error).message).toContain('Volumes');
    }
  });

  it('does not leak values when reporting the wrong shape', () => {
    // Key names are safe to echo; values are not.
    try {
      unwrapList({ Volumes: [{ VolumeId: SECRET }] }, 'SecurityGroups');
    } catch (err) {
      expect((err as Error).message).not.toContain(SECRET);
    }
  });
});

describe('valid input still parses', () => {
  it('round-trips a real-shaped response', () => {
    const doc = { SecurityGroups: [{ GroupId: 'sg-1', IpPermissions: [] }] };
    expect(safeParseJson(JSON.stringify(doc))).toEqual(doc);
  });
});

/**
 * README.md and the header of `json.ts` both print a worked example of V8
 * echoing pasted text back inside SyntaxError.message. That example is the
 * evidence for the privacy claim, so a reader will run it.
 *
 * The previous one stopped reproducing: V8 rewrote its JSON messages around
 * Node 20.6 and `{"CidrIp": "203.0.113.7/32",,}` now yields "Expected
 * double-quoted property name in JSON at position 28" — no input at all. The
 * documentation was making a claim the reader's own runtime disproved.
 */
describe('the documented example still demonstrates the risk', () => {
  const DOCUMENTED = '{"SecurityGroups": [{"GroupId": sg-0abc}]}';

  it('V8 still echoes the input for it', () => {
    let message = '';
    try {
      JSON.parse(DOCUMENTED);
    } catch (e) {
      message = (e as Error).message;
    }
    // If this fails, the engine changed and both documents are now claiming
    // something a reader cannot reproduce. Pick a new example, don't delete
    // the assertion.
    expect(message).toContain('sg-0abc');
  });

  it('and safeParseJson keeps none of it', () => {
    try {
      safeParseJson(DOCUMENTED);
      throw new Error('expected safeParseJson to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(ParseError);
      // Serialised, because reporters send the whole object — not just
      // `.message` — and `cause` is the channel that caught us before.
      const wire = JSON.stringify({
        message: (err as Error).message,
        diagnosis: (err as ParseError).diagnosis,
        ...(err as object),
      });
      expect(wire).not.toContain('sg-0abc');
      expect(wire).not.toContain('SecurityGroups');
    }
  });
});
