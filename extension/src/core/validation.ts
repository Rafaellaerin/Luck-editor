import { COOKIE_PREFIXES, LIMITS, SAFE_SAME_SITE } from './constants.js';
import { LuckError } from './errors.js';
import { byteLength } from './text.js';
import type { EditableCookie, ParseIssue, SameSite } from './types.js';

const COOKIE_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const ASCII_CONTROL_RE = /[\u0000-\u001F\u007F]/;
const DOMAIN_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

export interface ValidationResult<T> {
  readonly ok: boolean;
  readonly value?: T;
  readonly issues: readonly ParseIssue[];
}

export function normalizeDomain(input: string): string {
  let domain = input.trim().toLowerCase();
  if (domain.endsWith('.')) domain = domain.slice(0, -1);
  if (domain.startsWith('http://') || domain.startsWith('https://')) {
    try {
      domain = new URL(domain).hostname;
    } catch {
      return '';
    }
  }
  return domain;
}

export function isValidDomain(input: string): boolean {
  const domain = normalizeDomain(input);
  if (!domain || byteLength(domain) > LIMITS.domainBytes) return false;
  const bare = domain.startsWith('.') ? domain.slice(1) : domain;
  if (!bare || bare.includes('..')) return false;
  if (bare === 'localhost') return true;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(bare)) {
    return bare.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
  }
  return bare.split('.').every((label) => DOMAIN_LABEL_RE.test(label));
}

export function validateCookieName(name: string): readonly ParseIssue[] {
  const issues: ParseIssue[] = [];
  if (!name) issues.push(issue('NAME_EMPTY', 'Cookie name is required.'));
  if (byteLength(name) > LIMITS.cookieNameBytes) issues.push(issue('NAME_TOO_LONG', `Cookie name exceeds ${LIMITS.cookieNameBytes} bytes.`));
  if (!COOKIE_NAME_RE.test(name)) issues.push(issue('NAME_INVALID', 'Cookie name contains characters forbidden by RFC cookie syntax.'));
  return issues;
}

export function validateCookieValue(value: string): readonly ParseIssue[] {
  const issues: ParseIssue[] = [];
  if (byteLength(value) > LIMITS.cookieValueBytes) issues.push(issue('VALUE_TOO_LONG', `Cookie value exceeds ${LIMITS.cookieValueBytes} bytes.`));
  if (ASCII_CONTROL_RE.test(value)) issues.push(issue('VALUE_CONTROL', 'Cookie value contains an ASCII control character.'));
  return issues;
}

export function validatePath(path: string): readonly ParseIssue[] {
  const issues: ParseIssue[] = [];
  if (!path.startsWith('/')) issues.push(issue('PATH_INVALID', 'Cookie path must begin with a slash.'));
  if (byteLength(path) > LIMITS.pathBytes) issues.push(issue('PATH_TOO_LONG', `Cookie path exceeds ${LIMITS.pathBytes} bytes.`));
  if (ASCII_CONTROL_RE.test(path) || /[;?#]/.test(path)) issues.push(issue('PATH_UNSAFE', 'Cookie path contains a character that cannot be represented safely by the browser cookie API.'));
  return issues;
}

export function normalizeSameSite(value: unknown): SameSite {
  const normalized = String(value ?? 'unspecified').trim().toLowerCase().replace('-', '_');
  if (normalized === 'none') return 'no_restriction';
  if (SAFE_SAME_SITE.has(normalized)) return normalized as SameSite;
  return 'unspecified';
}

export function validateCookie(input: EditableCookie): ValidationResult<EditableCookie> {
  const cookie: EditableCookie = {
    ...input,
    name: input.name.trim(),
    domain: normalizeDomain(input.domain),
    path: input.path.trim() || '/',
    sameSite: normalizeSameSite(input.sameSite),
    session: Boolean(input.session),
    secure: Boolean(input.secure),
    httpOnly: Boolean(input.httpOnly),
  };
  const issues: ParseIssue[] = [
    ...validateCookieName(cookie.name),
    ...validateCookieValue(cookie.value),
    ...validatePath(cookie.path),
  ];

  if (!isValidDomain(cookie.domain)) issues.push(issue('DOMAIN_INVALID', 'Cookie domain is invalid.'));
  if (cookie.sameSite === 'no_restriction' && !cookie.secure) issues.push(issue('SAMESITE_SECURE', 'SameSite=None requires Secure.'));
  if (!cookie.session && cookie.expirationDate !== undefined) {
    if (!Number.isFinite(cookie.expirationDate) || cookie.expirationDate <= 0) issues.push(issue('EXPIRY_INVALID', 'Expiration date must be a positive Unix timestamp.'));
    if (cookie.expirationDate > 253402300799) issues.push(issue('EXPIRY_RANGE', 'Expiration date is outside the supported range.'));
  }
  if (cookie.name.startsWith(COOKIE_PREFIXES.host)) {
    if (!cookie.secure) issues.push(issue('HOST_PREFIX_SECURE', '__Host- cookies must be Secure.'));
    if (cookie.path !== '/') issues.push(issue('HOST_PREFIX_PATH', '__Host- cookies must use path /.'));
    if (cookie.domain.startsWith('.')) issues.push(issue('HOST_PREFIX_DOMAIN', '__Host- cookies cannot use a Domain attribute.'));
  }
  if (cookie.name.startsWith(COOKIE_PREFIXES.secure) && !cookie.secure) {
    issues.push(issue('SECURE_PREFIX', '__Secure- cookies must be Secure.'));
  }
  const errors = issues.filter((entry) => entry.severity === 'error');
  return { ok: errors.length === 0, value: errors.length === 0 ? cookie : undefined, issues };
}

export function requireValidCookie(input: EditableCookie): EditableCookie {
  const result = validateCookie(input);
  if (!result.ok || !result.value) {
    throw new LuckError('COOKIE_INVALID', result.issues.map((entry) => entry.message).join(' '), { issues: result.issues });
  }
  return result.value;
}

export function isDomainWithinHost(cookieDomain: string, hostname: string): boolean {
  const domain = normalizeDomain(cookieDomain).replace(/^\./, '');
  const host = normalizeDomain(hostname).replace(/^\./, '');
  return domain === host || host.endsWith(`.${domain}`);
}

export function issue(code: string, message: string, severity: 'warning' | 'error' = 'error', line?: number): ParseIssue {
  return line === undefined ? { code, message, severity } : { code, message, severity, line };
}
