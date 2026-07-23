import { DEFAULT_SETTINGS, STORAGE_KEYS } from './constants.js';
import type { AppSettings } from './types.js';

export async function loadSettings(): Promise<AppSettings> {
  const data = await chrome.storage.local.get(STORAGE_KEYS.settings);
  const stored = data[STORAGE_KEYS.settings];
  if (!stored || typeof stored !== 'object') return { ...DEFAULT_SETTINGS };
  return sanitizeSettings(stored as Partial<AppSettings>);
}

export async function saveSettings(settings: AppSettings): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEYS.settings]: sanitizeSettings(settings) });
}

export function sanitizeSettings(input: Partial<AppSettings>): AppSettings {
  return {
    confirmSingleDelete: input.confirmSingleDelete ?? DEFAULT_SETTINGS.confirmSingleDelete,
    confirmBulkDelete: input.confirmBulkDelete ?? DEFAULT_SETTINGS.confirmBulkDelete,
    maskValues: input.maskValues ?? DEFAULT_SETTINGS.maskValues,
    autoRefreshAfterMutation: input.autoRefreshAfterMutation ?? DEFAULT_SETTINGS.autoRefreshAfterMutation,
    includeHttpOnlyInExport: input.includeHttpOnlyInExport ?? DEFAULT_SETTINGS.includeHttpOnlyInExport,
    includeSecureValuesInSnapshot: input.includeSecureValuesInSnapshot ?? DEFAULT_SETTINGS.includeSecureValuesInSnapshot,
  };
}
