import { LuckError } from './errors.js';
import { originPatternForUrl } from './url.js';

export async function hasOriginPermission(url: URL): Promise<boolean> {
  return chrome.permissions.contains({ origins: [originPatternForUrl(url)] });
}

export async function requestOriginPermission(url: URL): Promise<boolean> {
  const origin = originPatternForUrl(url);
  const granted = await chrome.permissions.request({ origins: [origin] });
  if (!granted) return false;
  return chrome.permissions.contains({ origins: [origin] });
}

export async function requestAllWebPermissions(): Promise<boolean> {
  const origins = ['http://*/*', 'https://*/*'];
  const granted = await chrome.permissions.request({ origins });
  if (!granted) return false;
  return chrome.permissions.contains({ origins });
}

export async function revokeAllWebPermissions(): Promise<boolean> {
  return chrome.permissions.remove({ origins: ['http://*/*', 'https://*/*'] });
}

export async function ensureOriginPermission(url: URL): Promise<void> {
  if (await hasOriginPermission(url)) return;
  const granted = await requestOriginPermission(url);
  if (!granted) throw new LuckError('PERMISSION_DENIED', `Permission was not granted for ${url.origin}.`);
}
