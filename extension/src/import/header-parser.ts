import { issue } from '../core/validation.js';
import type { EditableCookie, ParseIssue, ParseResult } from '../core/types.js';

export function parseCookieHeader(input: string, fallbackDomain: string): ParseResult | null {
  const compact = input.replace(/\r\n?/g, '\n').split('\n').map((line) => line.trim()).filter(Boolean).join('; ');
  const header = compact.replace(/^cookie\s*:\s*/i, '');
  if (!header.includes('=')) return null;
  if (/;\s*(?:domain|path|expires|max-age|secure|httponly|samesite)(?:=|;|$)/i.test(header)) return null;
  const cookies: EditableCookie[] = [];
  const issues: ParseIssue[] = [];
  const pairs = header.split(';');
  for (let index = 0; index < pairs.length; index += 1) {
    const pair = (pairs[index] ?? '').trim();
    if (!pair) continue;
    const separator = pair.indexOf('=');
    if (separator <= 0) {
      issues.push(issue('HEADER_PAIR', `Ignored malformed cookie pair at position ${index + 1}.`, 'warning'));
      continue;
    }
    cookies.push({
      name: pair.slice(0, separator).trim(),
      value: pair.slice(separator + 1).trim(),
      domain: fallbackDomain,
      path: '/',
      secure: false,
      httpOnly: false,
      sameSite: 'unspecified',
      session: true,
    });
  }
  return cookies.length ? { format: 'cookie-header', cookies, issues } : null;
}
