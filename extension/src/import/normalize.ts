import { normalizeSameSite } from '../core/validation.js';
import type { EditableCookie } from '../core/types.js';

export function normalizeImportedCookie(input: Record<string, unknown>, fallbackDomain = ''): EditableCookie {
  const rawExpiration = input.expirationDate ?? input.expires ?? input.expiry;
  let expirationDate: number | undefined;
  if (typeof rawExpiration === 'number' && Number.isFinite(rawExpiration)) {
    expirationDate = rawExpiration > 1_000_000_000_000 ? Math.floor(rawExpiration / 1000) : Math.floor(rawExpiration);
  } else if (typeof rawExpiration === 'string' && rawExpiration.trim()) {
    const numeric = Number(rawExpiration);
    if (Number.isFinite(numeric)) expirationDate = numeric > 1_000_000_000_000 ? Math.floor(numeric / 1000) : Math.floor(numeric);
    else {
      const parsed = Date.parse(rawExpiration);
      if (Number.isFinite(parsed)) expirationDate = Math.floor(parsed / 1000);
    }
  }
  const sessionFlag = input.session === true || rawExpiration === undefined || rawExpiration === null || rawExpiration === -1;
  return {
    name: String(input.name ?? '').trim(),
    value: String(input.value ?? ''),
    domain: String(input.domain ?? fallbackDomain).trim(),
    path: String(input.path ?? '/').trim() || '/',
    secure: Boolean(input.secure),
    httpOnly: Boolean(input.httpOnly ?? input.http_only),
    sameSite: normalizeSameSite(input.sameSite ?? input.same_site),
    session: sessionFlag,
    expirationDate: sessionFlag ? undefined : expirationDate,
    storeId: typeof input.storeId === 'string' ? input.storeId : undefined,
  };
}
