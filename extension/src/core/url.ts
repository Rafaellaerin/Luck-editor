import { SUPPORTED_PROTOCOLS } from './constants.js';
import { LuckError } from './errors.js';
import { normalizeDomain } from './validation.js';
import type { ActiveContext, CookieRecord, EditableCookie } from './types.js';

export function activeContext(tab: { id?: number; url?: string }): ActiveContext {
  if (typeof tab.id !== 'number' || !tab.url) throw new LuckError('TAB_UNAVAILABLE', 'No active browser tab is available.');
  const url = new URL(tab.url);
  if (!SUPPORTED_PROTOCOLS.has(url.protocol)) throw new LuckError('TAB_PROTOCOL', 'Luck Editor works only on HTTP and HTTPS pages.');
  return {
    tabId: tab.id,
    url,
    hostname: url.hostname,
    originPattern: `${url.protocol}//${url.host}/*`,
  };
}

export function cookieUrl(cookie: Pick<EditableCookie | CookieRecord, 'domain' | 'path' | 'secure'>): string {
  const host = normalizeDomain(cookie.domain).replace(/^\./, '');
  if (!host) throw new LuckError('DOMAIN_EMPTY', 'Cannot build a cookie URL without a domain.');
  const scheme = cookie.secure ? 'https:' : 'http:';
  const path = normalizeCookiePath(cookie.path);
  return `${scheme}//${host}${path}`;
}

export function normalizeCookiePath(path: string): string {
  const candidate = path.trim() || '/';
  return candidate.startsWith('/') ? candidate : `/${candidate}`;
}

export function originPatternForUrl(url: URL): string {
  if (!SUPPORTED_PROTOCOLS.has(url.protocol)) throw new LuckError('ORIGIN_PROTOCOL', 'Unsupported origin protocol.');
  return `${url.protocol}//${url.host}/*`;
}

export function safeNavigationUrl(hostname: string): string {
  const host = normalizeDomain(hostname).replace(/^\./, '');
  return `https://${host}/`;
}
