import { LIMITS } from '../core/constants.js';
import { errorMessage, LuckError } from '../core/errors.js';
import { loadSettings, saveSettings } from '../core/settings.js';
import { byteLength, maskSecret, safeFilename, truncateByCodePoints } from '../core/text.js';
import { activeContext } from '../core/url.js';
import { requestAllWebPermissions, revokeAllWebPermissions } from '../core/permissions.js';
import { validateCookie } from '../core/validation.js';
import type { ActiveContext, AppSettings, CookieRecord, EditableCookie, ExportFormat, ParseResult, Snapshot } from '../core/types.js';
import { CookieService } from '../cookies/service.js';
import { serializeCookies } from '../export/serializers.js';
import { parseCookieInput } from '../import/index.js';
import { SnapshotRepository } from '../snapshots/repository.js';
import { all, button, byId, clear, element, setHidden } from '../ui/dom.js';
import { toast } from '../ui/toast.js';

interface State {
  context?: ActiveContext;
  cookies: readonly CookieRecord[];
  filtered: readonly CookieRecord[];
  selected: Set<string>;
  allDomains: boolean;
  revealValues: boolean;
  settings: AppSettings;
  parseResult?: ParseResult;
  editing?: CookieRecord;
}

const cookieService = new CookieService();
const snapshotRepository = new SnapshotRepository();
const state: State = {
  cookies: [],
  filtered: [],
  selected: new Set(),
  allDomains: false,
  revealValues: false,
  settings: await loadSettings(),
};

void initialize();

async function initialize(): Promise<void> {
  bindNavigation();
  bindCookieActions();
  bindImport();
  bindExport();
  bindSnapshots();
  bindSettings();
  bindDialog();
  await resolveContext();
  await refresh();
  await renderSnapshots();
}

async function resolveContext(): Promise<void> {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];
    if (!tab) throw new LuckError('TAB_MISSING', 'No active tab found.');
    state.context = activeContext(tab);
    byId('current-domain').textContent = state.context.hostname;
    byId('permission-note').textContent = `Temporary access: ${state.context.url.origin}`;
  } catch (error) {
    state.context = undefined;
    byId('current-domain').textContent = 'Unavailable page';
    byId('permission-note').textContent = errorMessage(error);
  }
}

function bindNavigation(): void {
  for (const tab of all<HTMLButtonElement>('[data-panel]')) {
    tab.addEventListener('click', () => showPanel(tab.dataset.panel ?? 'cookies'));
  }
}

function showPanel(name: string): void {
  for (const tab of all<HTMLButtonElement>('[data-panel]')) {
    const active = tab.dataset.panel === name;
    tab.classList.toggle('is-active', active);
    tab.setAttribute('aria-selected', String(active));
  }
  for (const panel of all<HTMLElement>('[data-panel-view]')) {
    panel.hidden = panel.dataset.panelView !== name;
  }
  if (name === 'snapshots') void renderSnapshots();
}

function bindCookieActions(): void {
  byId<HTMLButtonElement>('refresh').addEventListener('click', () => void refresh());
  byId<HTMLButtonElement>('add-cookie').addEventListener('click', () => openEditor());
  byId<HTMLButtonElement>('delete-selected').addEventListener('click', () => void deleteSelected());
  byId<HTMLButtonElement>('select-all').addEventListener('click', toggleSelectAll);
  byId<HTMLButtonElement>('toggle-values').addEventListener('click', toggleValues);
  byId<HTMLButtonElement>('all-domains').addEventListener('click', () => void enableAllDomains());
  byId<HTMLInputElement>('search').addEventListener('input', applyFilter);
}

async function refresh(): Promise<void> {
  if (!state.context) {
    state.cookies = [];
    applyFilter();
    return;
  }
  setBusy(true);
  try {
    state.cookies = await cookieService.list(state.context, state.allDomains);
    state.selected.clear();
    applyFilter();
    toast(`Loaded ${state.cookies.length} cookies.`, 'success');
  } catch (error) {
    state.cookies = [];
    applyFilter();
    toast(errorMessage(error), 'error');
  } finally {
    setBusy(false);
  }
}

function applyFilter(): void {
  const input = byId<HTMLInputElement>('search');
  if (byteLength(input.value) > LIMITS.searchBytes) input.value = input.value.slice(0, LIMITS.searchBytes);
  const query = input.value.trim().toLocaleLowerCase();
  state.filtered = query ? state.cookies.filter((cookie) => [cookie.name, cookie.domain, cookie.path, cookie.value].some((value) => value.toLocaleLowerCase().includes(query))) : state.cookies;
  renderCookies();
}

function renderCookies(): void {
  const list = byId<HTMLDivElement>('cookie-list');
  clear(list);
  byId('cookie-count').textContent = `${state.filtered.length} of ${state.cookies.length}`;
  setHidden(byId('empty-state'), state.filtered.length !== 0);
  for (const cookie of state.filtered) list.append(createCookieRow(cookie));
  updateSelectionControls();
}

function createCookieRow(cookie: CookieRecord): HTMLElement {
  const key = cookieKey(cookie);
  const row = element('article', { className: 'cookie-row' });
  const select = element('input', { attributes: { type: 'checkbox', 'aria-label': `Select ${cookie.name}` } });
  select.checked = state.selected.has(key);
  select.addEventListener('change', () => {
    if (select.checked) state.selected.add(key); else state.selected.delete(key);
    updateSelectionControls();
  });
  const identity = element('div', { className: 'cookie-identity' });
  identity.append(
    element('strong', { text: cookie.name || '(empty name)', title: cookie.name }),
    element('span', { text: `${cookie.domain}${cookie.path}` }),
  );
  const value = element('code', { className: 'cookie-value', text: state.revealValues || !state.settings.maskValues ? truncateByCodePoints(cookie.value, 160) : maskSecret(cookie.value) });
  value.title = state.revealValues ? cookie.value : 'Value hidden';
  const flags = element('div', { className: 'cookie-flags' });
  if (cookie.secure) flags.append(element('span', { text: 'Secure' }));
  if (cookie.httpOnly) flags.append(element('span', { text: 'HttpOnly' }));
  flags.append(element('span', { text: cookie.expirationDate ? 'Persistent' : 'Session' }));
  flags.append(element('span', { text: cookie.sameSite === 'no_restriction' ? 'SameSite=None' : `SameSite=${cookie.sameSite}` }));
  const actions = element('div', { className: 'row-actions' });
  actions.append(
    button('Copy', 'button button-small', async () => { await navigator.clipboard.writeText(cookie.value); toast('Cookie value copied.', 'success'); }),
    button('Edit', 'button button-small', () => openEditor(cookie)),
    button('Delete', 'button button-small button-danger', () => void deleteOne(cookie)),
  );
  row.append(select, identity, value, flags, actions);
  return row;
}

function cookieKey(cookie: CookieRecord): string {
  return `${cookie.storeId ?? ''}\u0000${cookie.partitionKey?.topLevelSite ?? ''}\u0000${cookie.domain}\u0000${cookie.path}\u0000${cookie.name}`;
}

function toggleSelectAll(): void {
  const allSelected = state.filtered.length > 0 && state.filtered.every((cookie) => state.selected.has(cookieKey(cookie)));
  for (const cookie of state.filtered) {
    const key = cookieKey(cookie);
    if (allSelected) state.selected.delete(key); else state.selected.add(key);
  }
  renderCookies();
}

function toggleValues(): void {
  state.revealValues = !state.revealValues;
  byId('toggle-values').textContent = state.revealValues ? 'Hide values' : 'Reveal values';
  renderCookies();
}

async function enableAllDomains(): Promise<void> {
  if (state.allDomains) {
    await revokeAllWebPermissions();
    state.allDomains = false;
    byId('all-domains').textContent = 'All domains';
    await refresh();
    toast('All-sites permission was released.', 'success');
    return;
  }
  const granted = await requestAllWebPermissions();
  if (!granted) {
    toast('All-sites permission was not granted.', 'error');
    return;
  }
  state.allDomains = true;
  byId('all-domains').textContent = 'Current site only';
  await refresh();
}

async function deleteOne(cookie: CookieRecord): Promise<void> {
  if (state.settings.confirmSingleDelete && !window.confirm(`Delete cookie “${cookie.name}” from ${cookie.domain}?`)) return;
  try {
    const removed = await cookieService.remove(cookie);
    toast(removed ? 'Cookie deleted.' : 'Cookie was not found.', removed ? 'success' : 'error');
    await refresh();
  } catch (error) {
    toast(errorMessage(error), 'error');
  }
}

async function deleteSelected(): Promise<void> {
  const targets = state.cookies.filter((cookie) => state.selected.has(cookieKey(cookie)));
  if (!targets.length) return;
  if (state.settings.confirmBulkDelete && !window.confirm(`Delete ${targets.length} selected cookies? This cannot be undone.`)) return;
  const report = await cookieService.removeMany(targets);
  toast(`Deleted ${report.succeeded}; failed ${report.failed}.`, report.failed ? 'error' : 'success');
  await refresh();
}

function updateSelectionControls(): void {
  const count = state.selected.size;
  byId<HTMLButtonElement>('delete-selected').disabled = count === 0;
  byId('selection-count').textContent = count ? `${count} selected` : 'None selected';
}

function bindImport(): void {
  const input = byId<HTMLTextAreaElement>('import-input');
  input.addEventListener('input', previewImport);
  byId<HTMLButtonElement>('import-file').addEventListener('click', () => byId<HTMLInputElement>('file-input').click());
  byId<HTMLInputElement>('file-input').addEventListener('change', (event) => void readImportFile(event));
  byId<HTMLButtonElement>('run-import').addEventListener('click', () => void runImport());
}

function previewImport(): void {
  const raw = byId<HTMLTextAreaElement>('import-input').value;
  try {
    state.parseResult = parseCookieInput(raw, state.context?.hostname ?? '');
    const errors = state.parseResult.issues.filter((entry) => entry.severity === 'error').length;
    const warnings = state.parseResult.issues.length - errors;
    byId('import-status').textContent = `${state.parseResult.cookies.length} valid cookies; ${errors} errors; ${warnings} warnings; format ${state.parseResult.format}.`;
    byId<HTMLButtonElement>('run-import').disabled = state.parseResult.cookies.length === 0;
  } catch (error) {
    state.parseResult = undefined;
    byId('import-status').textContent = errorMessage(error);
    byId<HTMLButtonElement>('run-import').disabled = true;
  }
}

async function readImportFile(event: Event): Promise<void> {
  const input = event.currentTarget as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  if (file.size > LIMITS.importBytes) {
    toast(`File exceeds ${LIMITS.importBytes} bytes.`, 'error');
    return;
  }
  byId<HTMLTextAreaElement>('import-input').value = await file.text();
  previewImport();
}

async function runImport(): Promise<void> {
  if (!state.context || !state.parseResult) return;
  const report = await cookieService.import(state.context, state.parseResult.cookies, {
    forceSecure: byId<HTMLInputElement>('import-secure').checked,
    forceHttpOnly: byId<HTMLInputElement>('import-http-only').checked,
    overwrite: byId<HTMLInputElement>('import-overwrite').checked,
    preserveSession: byId<HTMLInputElement>('import-session').checked,
  });
  toast(`Imported ${report.succeeded}; skipped ${report.skipped}; failed ${report.failed}.`, report.failed ? 'error' : 'success');
  if (state.settings.autoRefreshAfterMutation) await chrome.tabs.reload(state.context.tabId);
  await refresh();
}

function bindExport(): void {
  byId<HTMLButtonElement>('run-export').addEventListener('click', runExport);
  byId<HTMLButtonElement>('copy-export').addEventListener('click', () => void copyExport());
  byId<HTMLButtonElement>('download-export').addEventListener('click', downloadExport);
}

function runExport(): void {
  if (!state.context) return;
  const format = byId<HTMLSelectElement>('export-format').value as ExportFormat;
  const selected = state.cookies.filter((cookie) => state.selected.has(cookieKey(cookie)));
  const source = selected.length ? selected : state.cookies;
  const output = serializeCookies(source, { format, hostname: state.context.hostname, includeHttpOnly: state.settings.includeHttpOnlyInExport });
  byId<HTMLTextAreaElement>('export-output').value = output;
  byId('export-warning').textContent = format === 'redacted-json' ? 'Values are redacted.' : 'This output may contain authentication secrets. Keep it private.';
  toast(`Prepared ${source.length} cookies for export.`, 'success');
}

async function copyExport(): Promise<void> {
  const output = byId<HTMLTextAreaElement>('export-output').value;
  if (!output) return toast('Generate an export first.', 'error');
  await navigator.clipboard.writeText(output);
  toast('Export copied.', 'success');
}

function downloadExport(): void {
  const output = byId<HTMLTextAreaElement>('export-output').value;
  if (!output) return toast('Generate an export first.', 'error');
  const format = byId<HTMLSelectElement>('export-format').value;
  const blob = new Blob([output], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${safeFilename(state.context?.hostname ?? 'all')}-${format}-${Date.now()}.${format.includes('json') ? 'json' : 'txt'}`;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function bindSnapshots(): void {
  byId<HTMLButtonElement>('save-snapshot').addEventListener('click', () => void saveSnapshot());
  byId<HTMLButtonElement>('clear-snapshots').addEventListener('click', () => void clearSnapshots());
}

async function saveSnapshot(): Promise<void> {
  if (!state.context) return;
  const name = byId<HTMLInputElement>('snapshot-name').value;
  try {
    const snapshot = await snapshotRepository.create(name, state.context.hostname, state.cookies, state.settings);
    byId<HTMLInputElement>('snapshot-name').value = '';
    toast(snapshot.redacted ? 'Temporary redacted snapshot saved.' : 'Temporary snapshot saved with values.', 'success');
    await renderSnapshots();
  } catch (error) {
    toast(errorMessage(error), 'error');
  }
}

async function renderSnapshots(): Promise<void> {
  const snapshots = await snapshotRepository.list();
  const list = byId<HTMLDivElement>('snapshot-list');
  clear(list);
  setHidden(byId('snapshot-empty'), snapshots.length !== 0);
  for (const snapshot of snapshots) list.append(createSnapshotRow(snapshot));
}

function createSnapshotRow(snapshot: Snapshot): HTMLElement {
  const row = element('article', { className: 'snapshot-row' });
  const meta = element('div');
  meta.append(
    element('strong', { text: snapshot.name }),
    element('span', { text: `${snapshot.cookies.length} cookies · ${snapshot.domain} · ${new Date(snapshot.createdAt).toLocaleString()}` }),
    element('span', { text: snapshot.redacted ? 'Values redacted' : 'Contains values' }),
  );
  const actions = element('div', { className: 'row-actions' });
  actions.append(
    button('Load into import', 'button button-small', () => {
      byId<HTMLTextAreaElement>('import-input').value = JSON.stringify(snapshot.cookies, null, 2);
      previewImport();
      showPanel('import');
    }),
    button('Delete', 'button button-small button-danger', async () => { await snapshotRepository.remove(snapshot.id); await renderSnapshots(); }),
  );
  row.append(meta, actions);
  return row;
}

async function clearSnapshots(): Promise<void> {
  if (!window.confirm('Clear all temporary snapshots?')) return;
  await snapshotRepository.clear();
  await renderSnapshots();
}

function bindSettings(): void {
  setCheckbox('setting-confirm-single', state.settings.confirmSingleDelete);
  setCheckbox('setting-confirm-bulk', state.settings.confirmBulkDelete);
  setCheckbox('setting-mask-values', state.settings.maskValues);
  setCheckbox('setting-auto-refresh', state.settings.autoRefreshAfterMutation);
  setCheckbox('setting-export-http-only', state.settings.includeHttpOnlyInExport);
  setCheckbox('setting-snapshot-values', state.settings.includeSecureValuesInSnapshot);
  byId<HTMLButtonElement>('save-settings').addEventListener('click', () => void persistSettings());
  byId<HTMLButtonElement>('open-options').addEventListener('click', () => void chrome.runtime.openOptionsPage());
}

async function persistSettings(): Promise<void> {
  state.settings = {
    confirmSingleDelete: checked('setting-confirm-single'),
    confirmBulkDelete: checked('setting-confirm-bulk'),
    maskValues: checked('setting-mask-values'),
    autoRefreshAfterMutation: checked('setting-auto-refresh'),
    includeHttpOnlyInExport: checked('setting-export-http-only'),
    includeSecureValuesInSnapshot: checked('setting-snapshot-values'),
  };
  await saveSettings(state.settings);
  renderCookies();
  toast('Settings saved.', 'success');
}

function checked(id: string): boolean { return byId<HTMLInputElement>(id).checked; }
function setCheckbox(id: string, value: boolean): void { byId<HTMLInputElement>(id).checked = value; }

function bindDialog(): void {
  const dialog = byId<HTMLDialogElement>('cookie-dialog');
  byId<HTMLButtonElement>('close-editor').addEventListener('click', () => dialog.close());
  byId<HTMLButtonElement>('cancel-editor').addEventListener('click', () => dialog.close());
  byId<HTMLFormElement>('cookie-form').addEventListener('submit', (event) => void submitEditor(event));
  byId<HTMLSelectElement>('edit-same-site').addEventListener('change', () => {
    if (byId<HTMLSelectElement>('edit-same-site').value === 'no_restriction') byId<HTMLInputElement>('edit-secure').checked = true;
  });
}

function openEditor(cookie?: CookieRecord): void {
  if (!state.context) return toast('Open an HTTP or HTTPS page first.', 'error');
  state.editing = cookie;
  byId('editor-title').textContent = cookie ? 'Edit cookie' : 'Add cookie';
  byId<HTMLInputElement>('edit-name').value = cookie?.name ?? '';
  byId<HTMLTextAreaElement>('edit-value').value = cookie?.value ?? '';
  byId<HTMLInputElement>('edit-domain').value = cookie?.domain ?? state.context.hostname;
  byId<HTMLInputElement>('edit-path').value = cookie?.path ?? '/';
  byId<HTMLInputElement>('edit-secure').checked = cookie?.secure ?? state.context.url.protocol === 'https:';
  byId<HTMLInputElement>('edit-http-only').checked = cookie?.httpOnly ?? false;
  byId<HTMLSelectElement>('edit-same-site').value = cookie?.sameSite === 'unspecified' ? 'lax' : cookie?.sameSite ?? 'lax';
  byId<HTMLInputElement>('edit-session').checked = !cookie?.expirationDate;
  byId<HTMLInputElement>('edit-expiration').value = cookie?.expirationDate ? toLocalInput(cookie.expirationDate) : toLocalInput(Math.floor(Date.now() / 1000) + 31_536_000);
  byId('editor-errors').textContent = '';
  byId<HTMLDialogElement>('cookie-dialog').showModal();
}

async function submitEditor(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  if (!state.context) return;
  const session = checked('edit-session');
  const expirationInput = byId<HTMLInputElement>('edit-expiration').value;
  const candidate: EditableCookie = {
    name: byId<HTMLInputElement>('edit-name').value,
    value: byId<HTMLTextAreaElement>('edit-value').value,
    domain: byId<HTMLInputElement>('edit-domain').value,
    path: byId<HTMLInputElement>('edit-path').value,
    secure: checked('edit-secure'),
    httpOnly: checked('edit-http-only'),
    sameSite: byId<HTMLSelectElement>('edit-same-site').value as EditableCookie['sameSite'],
    session,
    expirationDate: session || !expirationInput ? undefined : Math.floor(new Date(expirationInput).getTime() / 1000),
    storeId: state.editing?.storeId,
  };
  const validation = validateCookie(candidate);
  if (!validation.ok || !validation.value) {
    byId('editor-errors').textContent = validation.issues.map((entry) => entry.message).join(' ');
    return;
  }
  try {
    await cookieService.save(state.context, validation.value, state.editing);
    byId<HTMLDialogElement>('cookie-dialog').close();
    toast('Cookie saved.', 'success');
    await refresh();
  } catch (error) {
    byId('editor-errors').textContent = errorMessage(error);
  }
}

function toLocalInput(unixSeconds: number): string {
  const date = new Date(unixSeconds * 1000);
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

function setBusy(busy: boolean): void {
  document.body.toggleAttribute('data-busy', busy);
  document.body.setAttribute('aria-busy', String(busy));
  const actionIds = ['refresh', 'add-cookie', 'select-all', 'delete-selected', 'all-domains'];
  for (const id of actionIds) {
    const node = byId<HTMLButtonElement>(id);
    if (busy) {
      node.dataset.disabledBeforeBusy = String(node.disabled);
      node.disabled = true;
    } else {
      node.disabled = node.dataset.disabledBeforeBusy === 'true';
      delete node.dataset.disabledBeforeBusy;
    }
  }
  if (!busy) updateSelectionControls();
}
