export const SAME_SITE_VALUES = Object.freeze(['unspecified', 'lax', 'strict', 'no_restriction']);

export function createCookie(input = {}) {
  const expiration = normalizeExpiration(input.expirationDate ?? input.expires ?? input.expiry);
  const session = input.session === true || expiration === undefined;
  return {
    name: String(input.name ?? '').trim(),
    value: String(input.value ?? ''),
    domain: normalizeDomain(input.domain ?? ''),
    path: normalizePath(input.path ?? '/'),
    secure: Boolean(input.secure),
    httpOnly: Boolean(input.httpOnly ?? input.http_only),
    sameSite: normalizeSameSite(input.sameSite ?? input.same_site),
    expirationDate: session ? undefined : expiration,
    session,
    hostOnly: input.hostOnly === true || !String(input.domain ?? '').startsWith('.'),
    storeId: typeof input.storeId === 'string' ? input.storeId : undefined,
    metadata: normalizeMetadata(input.metadata),
  };
}

export function cloneCookie(cookie) {
  return createCookie({
    ...cookie,
    metadata: { ...cookie.metadata },
  });
}

export function cookieKey(cookie) {
  return [cookie.storeId ?? '', cookie.domain, cookie.path, cookie.name].join('\u0000');
}

export function normalizeDomain(value) {
  let domain = String(value).trim().toLowerCase();
  if (domain.startsWith('http://') || domain.startsWith('https://')) {
    try {
      domain = new URL(domain).hostname;
    } catch {
      return '';
    }
  }
  return domain.replace(/\.$/, '');
}

export function normalizePath(value) {
  const raw = String(value || '/').trim();
  const candidate = raw.startsWith('/') ? raw : `/${raw}`;
  const segments = [];
  for (const segment of candidate.split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') {
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  const output = `/${segments.join('/')}`;
  return raw.endsWith('/') && output !== '/' ? `${output}/` : output;
}

export function normalizeSameSite(value) {
  const normalized = String(value ?? 'unspecified').trim().toLowerCase().replaceAll('-', '_');
  if (normalized === 'none') return 'no_restriction';
  return SAME_SITE_VALUES.includes(normalized) ? normalized : 'unspecified';
}

export function normalizeExpiration(value) {
  if (value === null || value === undefined || value === '' || value === -1) return undefined;
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value > 1_000_000_000_000 ? Math.floor(value / 1000) : Math.floor(value);
  }
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return normalizeExpiration(numeric);
  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) ? Math.floor(parsed / 1000) : undefined;
}

export function canonicalizeCookie(input) {
  const cookie = createCookie(input);
  const changes = [];
  const original = createCookie(input);
  if (cookie.domain !== String(input.domain ?? '').trim()) changes.push('domain_normalized');
  if (cookie.path !== String(input.path ?? '/').trim()) changes.push('path_normalized');
  if (cookie.sameSite === 'no_restriction' && !cookie.secure) {
    cookie.secure = true;
    changes.push('secure_enabled_for_same_site_none');
  }
  if (cookie.name.startsWith('__Secure-') && !cookie.secure) {
    cookie.secure = true;
    changes.push('secure_enabled_for_prefix');
  }
  if (cookie.name.startsWith('__Host-')) {
    if (!cookie.secure) {
      cookie.secure = true;
      changes.push('secure_enabled_for_host_prefix');
    }
    if (cookie.path !== '/') {
      cookie.path = '/';
      changes.push('host_prefix_path_reset');
    }
    if (cookie.domain.startsWith('.')) {
      cookie.domain = cookie.domain.slice(1);
      changes.push('host_prefix_domain_reset');
    }
    cookie.hostOnly = true;
  }
  return { cookie, changes, changed: changes.length > 0 || !cookiesEqual(cookie, original) };
}

export function cookiesEqual(left, right) {
  return cookieKey(left) === cookieKey(right)
    && left.value === right.value
    && left.secure === right.secure
    && left.httpOnly === right.httpOnly
    && left.sameSite === right.sameSite
    && left.expirationDate === right.expirationDate
    && left.session === right.session
    && left.hostOnly === right.hostOnly
    && JSON.stringify(left.metadata) === JSON.stringify(right.metadata);
}

export function deduplicateCookies(cookies) {
  const map = new Map();
  for (const cookie of cookies) map.set(cookieKey(cookie), cloneCookie(cookie));
  return [...map.values()];
}

export function sortCookies(cookies) {
  return [...cookies].sort((left, right) =>
    left.domain.localeCompare(right.domain)
    || left.path.localeCompare(right.path)
    || left.name.localeCompare(right.name));
}

export function cookieSize(cookie) {
  return new TextEncoder().encode([
    cookie.name,
    cookie.value,
    cookie.domain,
    cookie.path,
    cookie.storeId ?? '',
  ].join('')).byteLength;
}

function normalizeMetadata(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return Object.fromEntries(Object.entries(value).map(([key, entry]) => [String(key), String(entry)]));
}
