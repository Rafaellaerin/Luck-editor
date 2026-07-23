import { issue } from '../core/validation.js';
import type { EditableCookie, ParseIssue, ParseResult } from '../core/types.js';

export function parseNetscape(input: string): ParseResult | null {
  if (!input.includes('\t')) return null;
  const cookies: EditableCookie[] = [];
  const issues: ParseIssue[] = [];
  const lines = input.replace(/\r\n?/g, '\n').split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const original = lines[index] ?? '';
    let line = original.trim();
    if (!line) continue;
    let httpOnly = false;
    if (line.startsWith('#HttpOnly_')) {
      httpOnly = true;
      line = line.slice('#HttpOnly_'.length);
    } else if (line.startsWith('#')) {
      continue;
    }
    const fields = line.split('\t');
    if (fields.length < 7) {
      issues.push(issue('NETSCAPE_COLUMNS', 'Netscape row requires at least seven tab-separated fields.', 'warning', index + 1));
      continue;
    }
    const domain = (fields[0] ?? '').trim();
    const includeSubdomains = (fields[1] ?? '').trim().toUpperCase() === 'TRUE';
    const path = (fields[2] ?? '/').trim() || '/';
    const secure = (fields[3] ?? '').trim().toUpperCase() === 'TRUE';
    const expiration = Number.parseInt((fields[4] ?? '0').trim(), 10);
    const name = (fields[5] ?? '').trim();
    const value = fields.slice(6).join('\t');
    cookies.push({
      domain: includeSubdomains && !domain.startsWith('.') ? `.${domain}` : domain,
      path,
      secure,
      httpOnly,
      name,
      value,
      sameSite: 'unspecified',
      session: !Number.isFinite(expiration) || expiration <= 0,
      expirationDate: Number.isFinite(expiration) && expiration > 0 ? expiration : undefined,
    });
  }
  if (!cookies.length && !issues.length) return null;
  return { format: 'netscape', cookies, issues };
}
