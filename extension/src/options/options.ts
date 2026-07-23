import { APP_NAME, APP_VERSION, DEFAULT_SETTINGS, STORAGE_KEYS } from '../core/constants.js';
import { errorMessage } from '../core/errors.js';
import { clearAudit, readAudit } from '../core/logger.js';
import { revokeAllWebPermissions } from '../core/permissions.js';
import { loadSettings, saveSettings } from '../core/settings.js';
import type { AppSettings, AuditEvent } from '../core/types.js';
import { all, byId, clear, element, setHidden } from '../ui/dom.js';
import { toast } from '../ui/toast.js';

const SETTING_IDS: Readonly<Record<keyof AppSettings, string>> = Object.freeze({
  confirmSingleDelete: 'confirm-single',
  confirmBulkDelete: 'confirm-bulk',
  maskValues: 'mask-values',
  autoRefreshAfterMutation: 'auto-refresh',
  includeHttpOnlyInExport: 'export-http-only',
  includeSecureValuesInSnapshot: 'snapshot-values',
});

void initialize();

async function initialize(): Promise<void> {
  byId('app-name').textContent = APP_NAME;
  byId('app-version').textContent = APP_VERSION;
  bindNavigation();
  bindSettings();
  bindPermissions();
  bindDataControls();
  bindAuditControls();
  await Promise.all([renderSettings(), renderPermissions(), renderStorage(), renderAudit()]);
}

function bindNavigation(): void {
  for (const button of all<HTMLButtonElement>('[data-section]')) {
    button.addEventListener('click', () => showSection(button.dataset.section ?? 'settings'));
  }
}

function showSection(name: string): void {
  for (const button of all<HTMLButtonElement>('[data-section]')) {
    const active = button.dataset.section === name;
    button.classList.toggle('is-active', active);
    button.setAttribute('aria-selected', String(active));
  }
  for (const section of all<HTMLElement>('[data-section-view]')) {
    section.hidden = section.dataset.sectionView !== name;
  }
  if (name === 'audit') void renderAudit();
  if (name === 'storage') void renderStorage();
  if (name === 'permissions') void renderPermissions();
}

function bindSettings(): void {
  byId<HTMLButtonElement>('save-settings').addEventListener('click', () => void persistSettings());
  byId<HTMLButtonElement>('reset-settings').addEventListener('click', () => void resetSettings());
}

async function renderSettings(): Promise<void> {
  const settings = await loadSettings();
  for (const [key, id] of Object.entries(SETTING_IDS) as Array<[keyof AppSettings, string]>) {
    byId<HTMLInputElement>(id).checked = settings[key];
  }
}

async function persistSettings(): Promise<void> {
  const settings = Object.fromEntries(
    (Object.entries(SETTING_IDS) as Array<[keyof AppSettings, string]>).map(([key, id]) => [key, byId<HTMLInputElement>(id).checked]),
  ) as unknown as AppSettings;
  await saveSettings(settings);
  toast('Settings saved.', 'success');
  await renderStorage();
}

async function resetSettings(): Promise<void> {
  if (!window.confirm('Reset all Luck Editor settings to their secure defaults?')) return;
  await saveSettings({ ...DEFAULT_SETTINGS });
  await renderSettings();
  toast('Settings reset.', 'success');
}

function bindPermissions(): void {
  byId<HTMLButtonElement>('refresh-permissions').addEventListener('click', () => void renderPermissions());
  byId<HTMLButtonElement>('revoke-all-sites').addEventListener('click', () => void revokeBroadPermission());
}

async function renderPermissions(): Promise<void> {
  const permissions = await chrome.permissions.getAll();
  const origins = permissions.origins ?? [];
  const broad = origins.includes('http://*/*') || origins.includes('https://*/*');
  byId('permission-mode').textContent = broad ? 'All-sites access is currently granted.' : 'All-sites access is not granted.';
  byId('permission-count').textContent = `${origins.length} optional origins granted`;
  byId<HTMLButtonElement>('revoke-all-sites').disabled = !broad;
  const list = byId<HTMLUListElement>('origin-list');
  clear(list);
  for (const origin of origins.sort()) list.append(element('li', { text: origin }));
  setHidden(byId('origin-empty'), origins.length !== 0);
}

async function revokeBroadPermission(): Promise<void> {
  try {
    const removed = await revokeAllWebPermissions();
    toast(removed ? 'All-sites permission revoked.' : 'No broad permission was active.', removed ? 'success' : 'info');
    await renderPermissions();
  } catch (error) {
    toast(errorMessage(error), 'error');
  }
}

function bindDataControls(): void {
  byId<HTMLButtonElement>('refresh-storage').addEventListener('click', () => void renderStorage());
  byId<HTMLButtonElement>('clear-session').addEventListener('click', () => void clearSessionData());
  byId<HTMLButtonElement>('clear-settings').addEventListener('click', () => void clearLocalSettings());
}

async function renderStorage(): Promise<void> {
  const [local, session] = await Promise.all([chrome.storage.local.get(null), chrome.storage.session.get(null)]);
  renderStorageArea('local-storage-list', local);
  renderStorageArea('session-storage-list', session);
  byId('local-storage-count').textContent = `${Object.keys(local).length} keys`;
  byId('session-storage-count').textContent = `${Object.keys(session).length} keys`;
}

function renderStorageArea(id: string, data: Record<string, unknown>): void {
  const list = byId<HTMLDivElement>(id);
  clear(list);
  for (const [key, value] of Object.entries(data).sort(([left], [right]) => left.localeCompare(right))) {
    const row = element('article', { className: 'storage-row' });
    row.append(
      element('strong', { text: key }),
      element('span', { text: describeStoredValue(value) }),
    );
    list.append(row);
  }
  if (list.childElementCount === 0) list.append(element('p', { className: 'empty-note', text: 'No keys stored.' }));
}

function describeStoredValue(value: unknown): string {
  if (Array.isArray(value)) return `Array with ${value.length} entries`;
  if (value && typeof value === 'object') return `Object with ${Object.keys(value as Record<string, unknown>).length} fields`;
  return typeof value;
}

async function clearSessionData(): Promise<void> {
  if (!window.confirm('Clear temporary snapshots and audit events from this browser session?')) return;
  await chrome.storage.session.clear();
  toast('Temporary session data cleared.', 'success');
  await Promise.all([renderStorage(), renderAudit()]);
}

async function clearLocalSettings(): Promise<void> {
  if (!window.confirm('Delete locally stored Luck Editor settings?')) return;
  await chrome.storage.local.remove(STORAGE_KEYS.settings);
  await renderSettings();
  toast('Local settings removed and defaults restored.', 'success');
  await renderStorage();
}

function bindAuditControls(): void {
  byId<HTMLButtonElement>('refresh-audit').addEventListener('click', () => void renderAudit());
  byId<HTMLButtonElement>('clear-audit').addEventListener('click', () => void clearAuditEvents());
}

async function renderAudit(): Promise<void> {
  const events = await readAudit();
  const list = byId<HTMLDivElement>('audit-list');
  clear(list);
  for (const event of events) list.append(createAuditRow(event));
  setHidden(byId('audit-empty'), events.length !== 0);
  byId('audit-count').textContent = `${events.length} events`;
}

function createAuditRow(event: AuditEvent): HTMLElement {
  const row = element('article', { className: 'audit-row' });
  const heading = element('div', { className: 'audit-heading' });
  heading.append(
    element('strong', { text: event.operation }),
    element('span', { text: event.success ? 'Success' : 'Failed' }),
  );
  const detail = element('p', {
    text: [
      new Date(event.timestamp).toLocaleString(),
      event.domain ? `Domain: ${event.domain}` : '',
      event.count !== undefined ? `Count: ${event.count}` : '',
      event.detail ?? '',
    ].filter(Boolean).join(' · '),
  });
  row.append(heading, detail);
  return row;
}

async function clearAuditEvents(): Promise<void> {
  if (!window.confirm('Clear the temporary audit log?')) return;
  await clearAudit();
  await renderAudit();
  toast('Audit log cleared.', 'success');
}
