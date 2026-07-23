import { createCookie, deduplicateCookies } from './model.js';

export const INPUT_FORMATS = Object.freeze(['auto', 'json', 'netscape', 'cookie-header', 'set-cookie', 'lines']);

export function detectFormat(input) {
  const trimmed = String(input).trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
  if (String(input).split(/\r?\n/).some((line) => line.split('\t').length >= 7)) return 'netscape';
  if (/^\s*set-cookie\s*:/im.test(input)) return 'set-cookie';
  if (/;\s*(secure|httponly|samesite|domain|path|max-age|expires)(?:=|;|$)/i.test(input)) return 'set-cookie';
  if (/^\s*cookie\s*:/i.test(trimmed) || (trimmed.includes(';') && trimmed.includes('='))) return 'cookie-header';
  return 'lines';
}

export function parseCookies(input, options = {}) {
  const text = String(input);
  const maximumBytes = options.maximumBytes ?? 2 * 1024 * 1024;
  const maximumCookies = options.maximumCookies ?? 5000;
  if (new TextEncoder().encode(text).byteLength > maximumBytes) throw new Error(`Input exceeds ${maximumBytes} bytes.`);
  if (!text.trim()) return { format: 'auto', cookies: [], warnings: [{ code: 'input.empty', message: 'Input is empty.' }], duplicatesRemoved: 0 };
  const format = options.format && options.format !== 'auto' ? options.format : detectFormat(text);
  if (!INPUT_FORMATS.includes(format)) throw new Error(`Unsupported input format: ${format}`);
  const parser = {
    json: parseJson,
    netscape: parseNetscape,
    'cookie-header': parseCookieHeader,
    'set-cookie': parseSetCookie,
    lines: parseLines,
  }[format];
  const report = parser(text, options.fallbackDomain ?? '');
  if (report.cookies.length > maximumCookies) throw new Error(`Input contains ${report.cookies.length} cookies; limit is ${maximumCookies}.`);
  const deduplicated = deduplicateCookies(report.cookies);
  return {
    format,
    cookies: deduplicated,
    warnings: report.warnings,
    duplicatesRemoved: report.cookies.length - deduplicated.length,
  };
}

export function parseJson(input, fallbackDomain = '') {
  const decoded = JSON.parse(input);
  const warnings = [];
  let records = [];
  if (Array.isArray(decoded)) records = decoded;
  else if (decoded && typeof decoded === 'object' && Array.isArray(decoded.cookies)) records = decoded.cookies;
  else if (decoded && typeof decoded === 'object' && 'name' in decoded) records = [decoded];
  else if (decoded && typeof decoded === 'object') {
    records = Object.entries(decoded).map(([name, value]) => ({ name, value: typeof value === 'string' ? value : JSON.stringify(value) }));
  } else {
    warnings.push({ code: 'json.shape', message: 'JSON root must be an object or array.' });
  }
  const cookies = records.flatMap((record, index) => {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      warnings.push({ code: 'json.item', message: `Ignored non-object item ${index + 1}.` });
      return [];
    }
    return [createCookie({ ...record, domain: record.domain ?? fallbackDomain })];
  });
  return { cookies, warnings };
}

export function parseNetscape(input) {
  const cookies = [];
  const warnings = [];
  for (const [index, raw] of String(input).replaceAll('\r\n', '\n').split('\n').entries()) {
    let line = raw.trim();
    if (!line) continue;
    let httpOnly = false;
    if (line.startsWith('#HttpOnly_')) {
      httpOnly = true;
      line = line.slice('#HttpOnly_'.length);
    } else if (line.startsWith('#')) continue;
    const fields = line.split('\t');
    if (fields.length < 7) {
      warnings.push({ code: 'netscape.columns', line: index + 1, message: 'Expected seven tab-separated columns.' });
      continue;
    }
    const includeSubdomains = String(fields[1]).toUpperCase() === 'TRUE';
    const rawDomain = String(fields[0]).trim();
    const expirationDate = Number(fields[4]);
    cookies.push(createCookie({
      domain: includeSubdomains && !rawDomain.startsWith('.') ? `.${rawDomain}` : rawDomain,
      path: fields[2] || '/',
      secure: String(fields[3]).toUpperCase() === 'TRUE',
      expirationDate: Number.isFinite(expirationDate) && expirationDate > 0 ? expirationDate : undefined,
      session: !Number.isFinite(expirationDate) || expirationDate <= 0,
      name: fields[5],
      value: fields.slice(6).join('\t'),
      httpOnly,
      hostOnly: !includeSubdomains,
    }));
  }
  return { cookies, warnings };
}

export function parseCookieHeader(input, fallbackDomain = '') {
  const cookies = [];
  const warnings = [];
  const compact = String(input).replace(/^\s*cookie\s*:\s*/i, '').replaceAll(/\r?\n/g, '; ');
  for (const [index, raw] of compact.split(';').entries()) {
    const pair = raw.trim();
    if (!pair) continue;
    const separator = pair.indexOf('=');
    if (separator <= 0) {
      warnings.push({ code: 'header.pair', message: `Ignored malformed pair ${index + 1}.` });
      continue;
    }
    cookies.push(createCookie({
      name: pair.slice(0, separator).trim(),
      value: pair.slice(separator + 1).trim(),
      domain: fallbackDomain,
      path: '/',
      session: true,
    }));
  }
  return { cookies, warnings };
}

export function parseSetCookie(input, fallbackDomain = '') {
  const cookies = [];
  const warnings = [];
  for (const [index, raw] of String(input).replaceAll('\r\n', '\n').split('\n').entries()) {
    const line = raw.trim().replace(/^set-cookie\s*:\s*/i, '');
    if (!line) continue;
    const segments = splitAttributes(line);
    const pair = segments.shift();
    const separator = pair?.indexOf('=') ?? -1;
    if (!pair || separator <= 0) {
      warnings.push({ code: 'set_cookie.pair', line: index + 1, message: 'Missing name/value pair.' });
      continue;
    }
    const cookie = createCookie({
      name: pair.slice(0, separator).trim(),
      value: pair.slice(separator + 1).trim(),
      domain: fallbackDomain,
      session: true,
    });
    for (const segment of segments) {
      const equals = segment.indexOf('=');
      const key = (equals >= 0 ? segment.slice(0, equals) : segment).trim().toLowerCase();
      const value = equals >= 0 ? segment.slice(equals + 1).trim() : '';
      switch (key) {
        case 'domain': cookie.domain = value.toLowerCase(); cookie.hostOnly = false; break;
        case 'path': cookie.path = value || '/'; break;
        case 'secure': cookie.secure = true; break;
        case 'httponly': cookie.httpOnly = true; break;
        case 'samesite': cookie.sameSite = value.toLowerCase() === 'none' ? 'no_restriction' : value.toLowerCase(); break;
        case 'max-age': {
          const seconds = Number.parseInt(value, 10);
          if (Number.isFinite(seconds)) {
            cookie.expirationDate = Math.floor(Date.now() / 1000) + seconds;
            cookie.session = false;
          } else warnings.push({ code: 'set_cookie.max_age', line: index + 1, message: 'Invalid Max-Age.' });
          break;
        }
        case 'expires': {
          const timestamp = Date.parse(value);
          if (Number.isFinite(timestamp)) {
            cookie.expirationDate = Math.floor(timestamp / 1000);
            cookie.session = false;
          } else warnings.push({ code: 'set_cookie.expires', line: index + 1, message: 'Invalid Expires.' });
          break;
        }
        case 'partitioned': cookie.metadata.partitioned = 'true'; cookie.secure = true; break;
        case 'priority': cookie.metadata.priority = value; break;
        default: warnings.push({ code: 'set_cookie.attribute', line: index + 1, message: `Ignored attribute ${key || '(empty)'}.` });
      }
    }
    cookies.push(createCookie(cookie));
  }
  return { cookies, warnings };
}

export function parseLines(input, fallbackDomain = '') {
  const cookies = [];
  const warnings = [];
  for (const [index, raw] of String(input).replaceAll('\r\n', '\n').split('\n').entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) {
      warnings.push({ code: 'lines.pair', line: index + 1, message: 'Ignored line without name=value.' });
      continue;
    }
    cookies.push(createCookie({
      name: line.slice(0, separator).trim(),
      value: line.slice(separator + 1).trim(),
      domain: fallbackDomain,
      session: true,
    }));
  }
  return { cookies, warnings };
}

function splitAttributes(line) {
  const parts = [];
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
    } else if (character === '"') {
      quoted = !quoted;
      current += character;
    } else if (character === ';' && !quoted) {
      if (current.trim()) parts.push(current.trim());
      current = '';
    } else current += character;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}
