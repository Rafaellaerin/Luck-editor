import { LIMITS } from '../core/constants.js';
import { LuckError } from '../core/errors.js';
import { byteLength } from '../core/text.js';
import { issue, validateCookie } from '../core/validation.js';
import type { EditableCookie, ParseIssue, ParseResult } from '../core/types.js';
import { parseCookieHeader } from './header-parser.js';
import { parseJson } from './json-parser.js';
import { parseLines } from './line-parser.js';
import { parseNetscape } from './netscape-parser.js';
import { parseSetCookie } from './set-cookie-parser.js';

export function parseCookieInput(input: string, fallbackDomain: string): ParseResult {
  if (byteLength(input) > LIMITS.importBytes) throw new LuckError('IMPORT_TOO_LARGE', `Import is limited to ${LIMITS.importBytes} bytes.`);
  const parsers = [
    () => parseJson(input, fallbackDomain),
    () => parseNetscape(input),
    () => parseSetCookie(input, fallbackDomain),
    () => parseCookieHeader(input, fallbackDomain),
    () => parseLines(input, fallbackDomain),
  ];
  let parsed: ParseResult | null = null;
  for (const parser of parsers) {
    parsed = parser();
    if (parsed) break;
  }
  if (!parsed) return { format: 'unknown', cookies: [], issues: [issue('FORMAT_UNKNOWN', 'No supported cookie format was detected.')] };
  const cookies: EditableCookie[] = [];
  const issues: ParseIssue[] = [...parsed.issues];
  const dedupe = new Set<string>();
  for (let index = 0; index < parsed.cookies.length && index < LIMITS.importCookies; index += 1) {
    const candidate = parsed.cookies[index];
    if (!candidate) continue;
    const result = validateCookie(candidate);
    issues.push(...result.issues.map((entry) => ({ ...entry, line: entry.line ?? index + 1 })));
    if (!result.ok || !result.value) continue;
    const key = `${result.value.name}\u0000${result.value.domain}\u0000${result.value.path}`;
    if (dedupe.has(key)) {
      issues.push(issue('DUPLICATE', `Duplicate cookie ${result.value.name} was ignored.`, 'warning', index + 1));
      continue;
    }
    dedupe.add(key);
    cookies.push(result.value);
  }
  if (parsed.cookies.length > LIMITS.importCookies) issues.push(issue('IMPORT_TRUNCATED', `Only the first ${LIMITS.importCookies} cookies were processed.`, 'warning'));
  return { format: parsed.format, cookies, issues };
}
