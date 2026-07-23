export const APP_NAME = 'Luck Editor';
export const APP_VERSION = '5.0.0';

export const LIMITS = Object.freeze({
  cookieNameBytes: 256,
  cookieValueBytes: 4096,
  domainBytes: 253,
  pathBytes: 1024,
  importBytes: 2 * 1024 * 1024,
  importCookies: 5000,
  snapshotCount: 20,
  snapshotCookies: 2000,
  snapshotNameBytes: 80,
  searchBytes: 256,
  toastBytes: 500,
});

export const STORAGE_KEYS = Object.freeze({
  settings: 'luck.settings.v1',
  snapshots: 'luck.snapshots.session.v1',
  audit: 'luck.audit.session.v1',
});

export const DEFAULT_SETTINGS = Object.freeze({
  confirmSingleDelete: true,
  confirmBulkDelete: true,
  maskValues: true,
  autoRefreshAfterMutation: false,
  includeHttpOnlyInExport: false,
  includeSecureValuesInSnapshot: false,
});

export const COOKIE_PREFIXES = Object.freeze({
  host: '__Host-',
  secure: '__Secure-',
});

export const SUPPORTED_PROTOCOLS = new Set(['http:', 'https:']);
export const SAFE_SAME_SITE = new Set(['no_restriction', 'lax', 'strict', 'unspecified']);
