import { LIMITS, STORAGE_KEYS } from './constants.js';
import { stableId, truncateByCodePoints } from './text.js';
import type { AuditEvent } from './types.js';

const MAX_EVENTS = 200;

export async function recordAudit(event: Omit<AuditEvent, 'id' | 'timestamp'>): Promise<void> {
  const entry: AuditEvent = {
    ...event,
    id: stableId('audit'),
    timestamp: Date.now(),
    detail: event.detail ? truncateByCodePoints(event.detail, LIMITS.toastBytes) : undefined,
  };
  try {
    const data = await chrome.storage.session.get(STORAGE_KEYS.audit);
    const existing = Array.isArray(data[STORAGE_KEYS.audit]) ? data[STORAGE_KEYS.audit] as AuditEvent[] : [];
    await chrome.storage.session.set({ [STORAGE_KEYS.audit]: [entry, ...existing].slice(0, MAX_EVENTS) });
  } catch {
    // Audit logging must never prevent the requested operation.
  }
}

export async function readAudit(): Promise<readonly AuditEvent[]> {
  const data = await chrome.storage.session.get(STORAGE_KEYS.audit);
  return Array.isArray(data[STORAGE_KEYS.audit]) ? data[STORAGE_KEYS.audit] as AuditEvent[] : [];
}

export async function clearAudit(): Promise<void> {
  await chrome.storage.session.remove(STORAGE_KEYS.audit);
}
