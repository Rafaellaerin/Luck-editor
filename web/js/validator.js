import { cookieSize, normalizeDomain } from './model.js';

export const DEFAULT_LIMITS = Object.freeze({
  nameBytes: 256,
  valueBytes: 4096,
  domainBytes: 253,
  pathBytes: 1024,
  totalBytes: 4352,
});

const TOKEN_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const DOMAIN_LABEL_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const encoder = new TextEncoder();

export function validateCookie(cookie, limits = DEFAULT_LIMITS) {
  const issues = [];
  validateName(cookie, limits, issues);
  validateValue(cookie, limits, issues);
  validateDomain(cookie, limits, issues);
  validatePath(cookie, limits, issues);
  validateFlags(cookie, issues);
  validateExpiration(cookie, issues);
  validatePrefixes(cookie, issues);
  if (cookieSize(cookie) > limits.totalBytes) {
    issues.push(issue('cookie.size', 'Cookie exceeds the configured total byte limit.', 'error', 'value'));
  }
  return {
    valid: !issues.some((entry) => entry.severity === 'error'),
    issues,
    errors: issues.filter((entry) => entry.severity === 'error'),
    warnings: issues.filter((entry) => entry.severity === 'warning'),
  };
}

export function validateCollection(cookies, limits = DEFAULT_LIMITS) {
  const reports = cookies.map((cookie, index) => ({ index, cookie, ...validateCookie(cookie, limits) }));
  const keys = new Map();
  const duplicates = [];
  for (const report of reports) {
    const key = [report.cookie.storeId ?? '', report.cookie.domain, report.cookie.path, report.cookie.name].join('\u0000');
    if (keys.has(key)) duplicates.push({ first: keys.get(key), duplicate: report.index, key });
    keys.set(key, report.index);
  }
  return {
    reports,
    valid: reports.every((report) => report.valid),
    errors: reports.reduce((total, report) => total + report.errors.length, 0),
    warnings: reports.reduce((total, report) => total + report.warnings.length, 0),
    duplicates,
  };
}

export function evaluateSecurity(cookie) {
  const findings = [];
  if (!cookie.secure) findings.push(finding('secure.disabled', 'Cookie can be sent over an unencrypted connection.', 'high'));
  if (!cookie.httpOnly) findings.push(finding('http_only.disabled', 'Cookie can be read by page scripts.', 'medium'));
  if (cookie.sameSite === 'no_restriction') findings.push(finding('same_site.none', 'Cookie is eligible for cross-site requests.', 'medium'));
  if (cookie.sameSite === 'unspecified') findings.push(finding('same_site.unspecified', 'Browser defaults determine cross-site behavior.', 'low'));
  if (cookie.session) findings.push(finding('session.cookie', 'Cookie expires with the browser session.', 'information'));
  if (cookie.value.length === 0) findings.push(finding('value.empty', 'Cookie has an empty value.', 'low'));
  if (/session|auth|token|jwt|bearer/i.test(cookie.name) && !cookie.httpOnly) {
    findings.push(finding('sensitive.script_readable', 'Sensitive-looking cookie name is not HttpOnly.', 'high'));
  }
  return findings;
}

export function summarizeSecurity(cookies) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, information: 0, total: 0 };
  for (const cookie of cookies) {
    for (const item of evaluateSecurity(cookie)) {
      summary[item.risk] += 1;
      summary.total += 1;
    }
  }
  return summary;
}

function validateName(cookie, limits, issues) {
  const bytes = encoder.encode(cookie.name).byteLength;
  if (!cookie.name) issues.push(issue('name.empty', 'Cookie name is required.', 'error', 'name'));
  if (bytes > limits.nameBytes) issues.push(issue('name.length', `Cookie name exceeds ${limits.nameBytes} bytes.`, 'error', 'name'));
  if (cookie.name && !TOKEN_PATTERN.test(cookie.name)) issues.push(issue('name.syntax', 'Cookie name contains a forbidden character.', 'error', 'name'));
}

function validateValue(cookie, limits, issues) {
  const bytes = encoder.encode(cookie.value).byteLength;
  if (bytes > limits.valueBytes) issues.push(issue('value.length', `Cookie value exceeds ${limits.valueBytes} bytes.`, 'error', 'value'));
  if (CONTROL_PATTERN.test(cookie.value)) issues.push(issue('value.control', 'Cookie value contains an ASCII control character.', 'error', 'value'));
  if (cookie.value.includes('\r') || cookie.value.includes('\n')) issues.push(issue('value.injection', 'Cookie value contains a line break.', 'error', 'value'));
}

function validateDomain(cookie, limits, issues) {
  const domain = normalizeDomain(cookie.domain);
  if (!domain) {
    issues.push(issue('domain.empty', 'Cookie domain is required.', 'error', 'domain'));
    return;
  }
  if (encoder.encode(domain).byteLength > limits.domainBytes) issues.push(issue('domain.length', `Cookie domain exceeds ${limits.domainBytes} bytes.`, 'error', 'domain'));
  const bare = domain.replace(/^\./, '');
  if (bare === 'localhost' || isIpv4(bare) || isIpv6(bare)) return;
  if (bare.includes('..')) issues.push(issue('domain.empty_label', 'Cookie domain contains an empty label.', 'error', 'domain'));
  for (const label of bare.split('.')) {
    if (!DOMAIN_LABEL_PATTERN.test(label)) issues.push(issue('domain.label', `Invalid domain label: ${label || '(empty)'}.`, 'error', 'domain'));
  }
  if (!bare.includes('.')) issues.push(issue('domain.single_label', 'Single-label domains are intended only for local development.', 'warning', 'domain'));
}

function validatePath(cookie, limits, issues) {
  if (!cookie.path.startsWith('/')) issues.push(issue('path.slash', 'Cookie path must start with a slash.', 'error', 'path'));
  if (encoder.encode(cookie.path).byteLength > limits.pathBytes) issues.push(issue('path.length', `Cookie path exceeds ${limits.pathBytes} bytes.`, 'error', 'path'));
  if (CONTROL_PATTERN.test(cookie.path) || cookie.path.includes(';')) issues.push(issue('path.syntax', 'Cookie path contains an unsafe character.', 'error', 'path'));
}

function validateFlags(cookie, issues) {
  if (cookie.sameSite === 'no_restriction' && !cookie.secure) issues.push(issue('same_site.secure', 'SameSite=None requires Secure.', 'error', 'secure'));
  if (cookie.metadata.partitioned === 'true' && !cookie.secure) issues.push(issue('partitioned.secure', 'Partitioned cookies require Secure.', 'error', 'secure'));
}

function validateExpiration(cookie, issues) {
  if (cookie.session && cookie.expirationDate !== undefined) issues.push(issue('expiration.session', 'Session cookie also has an expiration date.', 'warning', 'expirationDate'));
  if (cookie.expirationDate !== undefined && (!Number.isFinite(cookie.expirationDate) || cookie.expirationDate <= 0)) {
    issues.push(issue('expiration.invalid', 'Expiration must be a positive Unix timestamp.', 'error', 'expirationDate'));
  }
  if (cookie.expirationDate > 253_402_300_799) issues.push(issue('expiration.range', 'Expiration exceeds year 9999.', 'error', 'expirationDate'));
}

function validatePrefixes(cookie, issues) {
  if (cookie.name.startsWith('__Host-')) {
    if (!cookie.secure) issues.push(issue('prefix.host.secure', '__Host- cookies must be Secure.', 'error', 'secure'));
    if (cookie.path !== '/') issues.push(issue('prefix.host.path', '__Host- cookies must use path /.', 'error', 'path'));
    if (!cookie.hostOnly || cookie.domain.startsWith('.')) issues.push(issue('prefix.host.domain', '__Host- cookies must be host-only.', 'error', 'domain'));
  }
  if (cookie.name.startsWith('__Secure-') && !cookie.secure) issues.push(issue('prefix.secure', '__Secure- cookies must be Secure.', 'error', 'secure'));
}

function issue(code, message, severity, field) {
  return { code, message, severity, field };
}

function finding(code, message, risk) {
  return { code, message, risk };
}

function isIpv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function isIpv6(value) {
  return value.includes(':') && /^[0-9a-f:]+$/i.test(value);
}
