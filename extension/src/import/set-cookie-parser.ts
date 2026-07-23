import { issue, normalizeSameSite } from '../core/validation.js';
import type { EditableCookie, ParseIssue, ParseResult } from '../core/types.js';

const ATTRIBUTE_NAMES = new Set(['domain', 'path', 'expires', 'max-age', 'secure', 'httponly', 'samesite', 'priority', 'partitioned']);

export function parseSetCookie(input: string, fallbackDomain: string): ParseResult | null {
  const lines = input.replace(/\r\n?/g, '\n').split('\n').map((line) => line.trim()).filter(Boolean);
  if (!lines.some((line) => /^set-cookie\s*:/i.test(line) || /;\s*(?:domain|path|expires|max-age|secure|httponly|samesite)(?:=|;|$)/i.test(line))) return null;
  const cookies: EditableCookie[] = [];
  const issues: ParseIssue[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? '').replace(/^set-cookie\s*:\s*/i, '');
    const segments = splitAttributes(line);
    const pair = segments.shift();
    if (!pair) continue;
    const separator = pair.indexOf('=');
    if (separator <= 0) {
      issues.push(issue('SET_COOKIE_PAIR', 'Set-Cookie row has no valid name/value pair.', 'warning', index + 1));
      continue;
    }
    const cookie: EditableCookie = {
      name: pair.slice(0, separator).trim(),
      value: pair.slice(separator + 1).trim(),
      domain: fallbackDomain,
      path: '/',
      secure: false,
      httpOnly: false,
      sameSite: 'unspecified',
      session: true,
    };
    for (const segment of segments) {
      const equals = segment.indexOf('=');
      const key = (equals >= 0 ? segment.slice(0, equals) : segment).trim().toLowerCase();
      const value = equals >= 0 ? segment.slice(equals + 1).trim() : '';
      if (!ATTRIBUTE_NAMES.has(key)) {
        issues.push(issue('SET_COOKIE_ATTRIBUTE', `Ignored unsupported attribute ${key || '(empty)'}.`, 'warning', index + 1));
        continue;
      }
      switch (key) {
        case 'domain': cookie.domain = value; break;
        case 'path': cookie.path = value || '/'; break;
        case 'secure': cookie.secure = true; break;
        case 'httponly': cookie.httpOnly = true; break;
        case 'samesite': cookie.sameSite = normalizeSameSite(value); break;
        case 'expires': {
          const timestamp = Date.parse(value);
          if (Number.isFinite(timestamp)) {
            cookie.expirationDate = Math.floor(timestamp / 1000);
            cookie.session = false;
          } else issues.push(issue('SET_COOKIE_EXPIRES', 'Ignored invalid Expires attribute.', 'warning', index + 1));
          break;
        }
        case 'max-age': {
          const seconds = Number.parseInt(value, 10);
          if (Number.isFinite(seconds)) {
            cookie.expirationDate = Math.floor(Date.now() / 1000) + seconds;
            cookie.session = false;
          } else issues.push(issue('SET_COOKIE_MAX_AGE', 'Ignored invalid Max-Age attribute.', 'warning', index + 1));
          break;
        }
        default: break;
      }
    }
    cookies.push(cookie);
  }
  return { format: 'set-cookie', cookies, issues };
}

function splitAttributes(line: string): string[] {
  const parts: string[] = [];
  let current = '';
  let quoted = false;
  let escaped = false;
  for (const character of line) {
    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }
    if (character === '\\' && quoted) {
      current += character;
      escaped = true;
      continue;
    }
    if (character === '"') {
      quoted = !quoted;
      current += character;
      continue;
    }
    if (character === ';' && !quoted) {
      if (current.trim()) parts.push(current.trim());
      current = '';
      continue;
    }
    current += character;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}
