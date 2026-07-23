import { issue } from '../core/validation.js';
import type { EditableCookie, ParseResult } from '../core/types.js';
import { normalizeImportedCookie } from './normalize.js';

export function parseJson(input: string, fallbackDomain: string): ParseResult | null {
  let decoded: unknown;
  try {
    decoded = JSON.parse(input);
  } catch {
    return null;
  }
  const cookies: EditableCookie[] = [];
  if (Array.isArray(decoded)) {
    for (const item of decoded) {
      if (item && typeof item === 'object' && !Array.isArray(item)) cookies.push(normalizeImportedCookie(item as Record<string, unknown>, fallbackDomain));
    }
  } else if (decoded && typeof decoded === 'object') {
    const object = decoded as Record<string, unknown>;
    if ('cookies' in object && Array.isArray(object.cookies)) {
      for (const item of object.cookies) {
        if (item && typeof item === 'object' && !Array.isArray(item)) cookies.push(normalizeImportedCookie(item as Record<string, unknown>, fallbackDomain));
      }
    } else if ('name' in object) {
      cookies.push(normalizeImportedCookie(object, fallbackDomain));
    } else {
      for (const [name, value] of Object.entries(object)) {
        cookies.push(normalizeImportedCookie({ name, value: typeof value === 'string' ? value : JSON.stringify(value) }, fallbackDomain));
      }
    }
  } else {
    return { format: 'json', cookies: [], issues: [issue('JSON_SHAPE', 'JSON must contain a cookie object, array, map, or cookies array.')] };
  }
  return { format: 'json', cookies, issues: cookies.length ? [] : [issue('JSON_EMPTY', 'JSON did not contain any cookie records.', 'warning')] };
}
