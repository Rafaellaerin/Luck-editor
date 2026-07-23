import { cookieUrl } from '../core/url.js';
import type { ActiveContext, CookieRecord, EditableCookie } from '../core/types.js';

export class CookieRepository {
  public async listForContext(context: ActiveContext): Promise<readonly CookieRecord[]> {
    const byUrl = await chrome.cookies.getAll({ url: context.url.href });
    const byDomain = await chrome.cookies.getAll({ domain: context.hostname });
    return deduplicate([...byUrl, ...byDomain]).sort(compareCookies);
  }

  public async listAll(): Promise<readonly CookieRecord[]> {
    return deduplicate(await chrome.cookies.getAll({})).sort(compareCookies);
  }

  public async set(cookie: EditableCookie): Promise<CookieRecord | null> {
    const details: Record<string, unknown> = {
      url: cookieUrl(cookie),
      name: cookie.name,
      value: cookie.value,
      path: cookie.path,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite === 'unspecified' ? 'lax' : cookie.sameSite,
    };
    if (cookie.domain.startsWith('.')) details.domain = cookie.domain;
    if (!cookie.session && cookie.expirationDate) details.expirationDate = cookie.expirationDate;
    if (cookie.storeId) details.storeId = cookie.storeId;
    return chrome.cookies.set(details);
  }

  public async get(cookie: Pick<EditableCookie, 'name' | 'domain' | 'path' | 'secure' | 'storeId'>): Promise<CookieRecord | null> {
    return chrome.cookies.get({ url: cookieUrl(cookie), name: cookie.name, storeId: cookie.storeId });
  }

  public async remove(cookie: Pick<EditableCookie, 'name' | 'domain' | 'path' | 'secure' | 'storeId'>): Promise<boolean> {
    const result = await chrome.cookies.remove({ url: cookieUrl(cookie), name: cookie.name, storeId: cookie.storeId });
    return result !== null;
  }
}

function deduplicate(cookies: readonly CookieRecord[]): CookieRecord[] {
  const map = new Map<string, CookieRecord>();
  for (const cookie of cookies) {
    const partition = cookie.partitionKey?.topLevelSite ?? '';
    const key = `${cookie.storeId ?? ''}\u0000${partition}\u0000${cookie.domain}\u0000${cookie.path}\u0000${cookie.name}`;
    map.set(key, cookie);
  }
  return Array.from(map.values());
}

function compareCookies(left: CookieRecord, right: CookieRecord): number {
  return left.domain.localeCompare(right.domain) || left.path.localeCompare(right.path) || left.name.localeCompare(right.name);
}
