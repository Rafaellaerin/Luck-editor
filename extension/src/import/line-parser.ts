import { issue } from '../core/validation.js';
import type { EditableCookie, ParseIssue, ParseResult } from '../core/types.js';

export function parseLines(input: string, fallbackDomain: string): ParseResult | null {
  const lines = input.replace(/\r\n?/g, '\n').split('\n');
  const cookies: EditableCookie[] = [];
  const issues: ParseIssue[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? '').trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) {
      issues.push(issue('LINE_PAIR', 'Ignored line without a name=value pair.', 'warning', index + 1));
      continue;
    }
    cookies.push({
      name: line.slice(0, separator).trim(),
      value: line.slice(separator + 1).trim(),
      domain: fallbackDomain,
      path: '/',
      secure: false,
      httpOnly: false,
      sameSite: 'unspecified',
      session: true,
    });
  }
  return cookies.length ? { format: 'lines', cookies, issues } : null;
}
