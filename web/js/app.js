import { canonicalizeCookie, cookieKey } from './model.js';
import { parseCookies } from './parser.js';
import { downloadText, serializeCookies } from './serializer.js';
import { CookieLabStore } from './store.js';
import { summarizeSecurity, validateCollection, validateCookie } from './validator.js';

const store = new CookieLabStore();
const elements = bindElements();
let revealValues = false;
let lastParse = null;

initialize();

function initialize() {
  bindEvents();
  store.addEventListener('change', render);
  elements.input.value = sampleInput();
  parseInput();
}

function bindEvents() {
  elements.parse.addEventListener('click', parseInput);
  elements.input.addEventListener('input', updateInputSize);
  elements.file.addEventListener('change', readFile);
  elements.openFile.addEventListener('click', () => elements.file.click());
  elements.search.addEventListener('input', () => store.setFilter(elements.search.value));
  elements.selectAll.addEventListener('click', () => store.toggleVisibleSelection());
  elements.deleteSelected.addEventListener('click', deleteSelected);
  elements.undo.addEventListener('click', () => store.undo());
  elements.redo.addEventListener('click', () => store.redo());
  elements.reveal.addEventListener('click', () => { revealValues = !revealValues; render(); });
  elements.generate.addEventListener('click', generateOutput);
  elements.copy.addEventListener('click', copyOutput);
  elements.download.addEventListener('click', downloadOutput);
  elements.canonicalize.addEventListener('click', canonicalizeAll);
  elements.clear.addEventListener('click', clearAll);
  elements.tabs.forEach((tab) => tab.addEventListener('click', () => showPanel(tab.dataset.panel)));
  elements.closeDialog.addEventListener('click', () => elements.dialog.close());
  elements.cancelDialog.addEventListener('click', () => elements.dialog.close());
  elements.form.addEventListener('submit', saveEditor);
}

function parseInput() {
  try {
    lastParse = parseCookies(elements.input.value, {
      format: elements.inputFormat.value,
      fallbackDomain: elements.fallbackDomain.value,
    });
    store.replace(lastParse.cookies, 'parse');
    elements.parseStatus.textContent = `${lastParse.cookies.length} cookies parsed as ${lastParse.format}; ${lastParse.warnings.length} warnings; ${lastParse.duplicatesRemoved} duplicates removed.`;
    renderWarnings(lastParse.warnings);
  } catch (error) {
    elements.parseStatus.textContent = error instanceof Error ? error.message : String(error);
    renderWarnings([]);
  }
  updateInputSize();
}

async function readFile() {
  const file = elements.file.files?.[0];
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) {
    elements.parseStatus.textContent = 'File exceeds the 2 MiB limit.';
    return;
  }
  elements.input.value = await file.text();
  updateInputSize();
  parseInput();
}

function render() {
  renderCookies();
  renderSummary();
  elements.search.value = store.filter;
  elements.undo.disabled = !store.canUndo;
  elements.redo.disabled = !store.canRedo;
  elements.deleteSelected.disabled = store.selectedKeys.size === 0;
  elements.selection.textContent = `${store.selectedKeys.size} selected`;
  elements.reveal.textContent = revealValues ? 'Hide values' : 'Reveal values';
}

function renderCookies() {
  elements.cookieList.replaceChildren();
  const cookies = store.visibleCookies;
  elements.cookieCount.textContent = `${cookies.length} of ${store.cookies.length}`;
  elements.empty.hidden = cookies.length > 0;
  for (const cookie of cookies) elements.cookieList.append(createCookieRow(cookie));
}

function createCookieRow(cookie) {
  const report = validateCookie(cookie);
  const row = document.createElement('article');
  row.className = `cookie-row${report.valid ? '' : ' is-invalid'}`;
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.checked = store.selectedKeys.has(cookieKey(cookie));
  checkbox.setAttribute('aria-label', `Select ${cookie.name}`);
  checkbox.addEventListener('change', () => store.setSelected(cookieKey(cookie), checkbox.checked));

  const identity = document.createElement('div');
  identity.className = 'cookie-identity';
  identity.append(textElement('strong', cookie.name || '(empty name)'), textElement('span', `${cookie.domain}${cookie.path}`));

  const value = document.createElement('code');
  value.className = 'cookie-value';
  value.textContent = revealValues ? cookie.value : mask(cookie.value);
  value.title = revealValues ? cookie.value : 'Value hidden';

  const flags = document.createElement('div');
  flags.className = 'cookie-flags';
  for (const flag of cookieFlags(cookie)) flags.append(textElement('span', flag));
  if (!report.valid) flags.append(textElement('span', `${report.errors.length} errors`));

  const actions = document.createElement('div');
  actions.className = 'row-actions';
  actions.append(
    actionButton('Inspect', () => openEditor(cookie)),
    actionButton('Copy', () => navigator.clipboard.writeText(cookie.value)),
    actionButton('Delete', () => store.remove(cookieKey(cookie)), 'danger'),
  );
  row.append(checkbox, identity, value, flags, actions);
  return row;
}

function renderSummary() {
  const cookies = store.cookies;
  const validation = validateCollection(cookies);
  const security = summarizeSecurity(cookies);
  elements.summary.replaceChildren(
    metric('Cookies', cookies.length),
    metric('Errors', validation.errors),
    metric('Warnings', validation.warnings),
    metric('Security findings', security.total),
    metric('High risk', security.high + security.critical),
    metric('Duplicates', validation.duplicates.length),
  );
  elements.validationTable.replaceChildren();
  for (const report of validation.reports.filter((entry) => entry.issues.length > 0)) {
    for (const item of report.issues) {
      const row = document.createElement('tr');
      row.append(
        textElement('td', report.cookie.name),
        textElement('td', item.field),
        textElement('td', item.severity),
        textElement('td', item.message),
      );
      elements.validationTable.append(row);
    }
  }
  elements.validationEmpty.hidden = elements.validationTable.childElementCount > 0;
}

function renderWarnings(warnings) {
  elements.warningList.replaceChildren();
  for (const warning of warnings) {
    const item = document.createElement('li');
    item.textContent = `${warning.line ? `Line ${warning.line}: ` : ''}${warning.message}`;
    elements.warningList.append(item);
  }
  elements.warningEmpty.hidden = warnings.length > 0;
}

function generateOutput() {
  try {
    elements.output.value = serializeCookies(store.cookies, {
      format: elements.outputFormat.value,
      hostname: elements.fallbackDomain.value,
      includeHttpOnly: elements.includeHttpOnly.checked,
      pretty: true,
    });
    elements.outputStatus.textContent = `Generated ${elements.outputFormat.value} from ${store.cookies.length} cookies.`;
  } catch (error) {
    elements.outputStatus.textContent = error instanceof Error ? error.message : String(error);
  }
}

async function copyOutput() {
  if (!elements.output.value) generateOutput();
  await navigator.clipboard.writeText(elements.output.value);
  elements.outputStatus.textContent = 'Output copied.';
}

function downloadOutput() {
  if (!elements.output.value) generateOutput();
  const extension = elements.outputFormat.value.includes('json') ? 'json' : 'txt';
  downloadText(`luck-editor-export.${extension}`, elements.output.value);
}

function canonicalizeAll() {
  const canonicalized = store.cookies.map((cookie) => canonicalizeCookie(cookie).cookie);
  store.replace(canonicalized, 'canonicalize');
  elements.parseStatus.textContent = 'All cookies were canonicalized and deduplicated.';
}

function clearAll() {
  if (store.cookies.length > 0 && window.confirm('Clear all cookies from this local workspace?')) store.clear();
}

function deleteSelected() {
  const count = store.selectedKeys.size;
  if (count > 0 && window.confirm(`Delete ${count} selected cookies from this local workspace?`)) store.removeSelected();
}

function openEditor(cookie) {
  const report = validateCookie(cookie);
  elements.editorTitle.textContent = `Inspect ${cookie.name || '(empty name)'}`;
  elements.editorName.value = cookie.name;
  elements.editorValue.value = cookie.value;
  elements.editorDomain.value = cookie.domain;
  elements.editorPath.value = cookie.path;
  elements.editorSecure.checked = cookie.secure;
  elements.editorHttpOnly.checked = cookie.httpOnly;
  elements.editorSameSite.value = cookie.sameSite;
  elements.editorSession.checked = cookie.session;
  elements.editorExpiration.value = cookie.expirationDate ? toLocalInput(cookie.expirationDate) : '';
  elements.editorKey.value = cookieKey(cookie);
  elements.editorIssues.textContent = report.issues.map((issue) => issue.message).join(' ');
  elements.dialog.showModal();
}

function saveEditor(event) {
  event.preventDefault();
  const session = elements.editorSession.checked;
  const candidate = canonicalizeCookie({
    name: elements.editorName.value,
    value: elements.editorValue.value,
    domain: elements.editorDomain.value,
    path: elements.editorPath.value,
    secure: elements.editorSecure.checked,
    httpOnly: elements.editorHttpOnly.checked,
    sameSite: elements.editorSameSite.value,
    session,
    expirationDate: session || !elements.editorExpiration.value ? undefined : Math.floor(new Date(elements.editorExpiration.value).getTime() / 1000),
  }).cookie;
  const report = validateCookie(candidate);
  if (!report.valid) {
    elements.editorIssues.textContent = report.errors.map((issue) => issue.message).join(' ');
    return;
  }
  const oldKey = elements.editorKey.value;
  if (oldKey && oldKey !== cookieKey(candidate)) store.remove(oldKey);
  store.add(candidate);
  elements.dialog.close();
}

function showPanel(name) {
  for (const tab of elements.tabs) {
    const active = tab.dataset.panel === name;
    tab.classList.toggle('is-active', active);
    tab.setAttribute('aria-selected', String(active));
  }
  for (const panel of elements.panels) panel.hidden = panel.dataset.panelView !== name;
}

function updateInputSize() {
  const bytes = new TextEncoder().encode(elements.input.value).byteLength;
  elements.inputSize.textContent = `${bytes.toLocaleString()} bytes`;
}

function cookieFlags(cookie) {
  return [
    cookie.secure ? 'Secure' : 'Not Secure',
    cookie.httpOnly ? 'HttpOnly' : 'Script readable',
    cookie.session ? 'Session' : 'Persistent',
    `SameSite=${cookie.sameSite}`,
  ];
}

function mask(value) {
  const chars = [...value];
  if (chars.length === 0) return '(empty)';
  if (chars.length <= 6) return '•'.repeat(Math.max(4, chars.length));
  return `${chars.slice(0, 3).join('')}${'•'.repeat(Math.min(24, chars.length - 6))}${chars.slice(-3).join('')}`;
}

function metric(label, value) {
  const node = document.createElement('div');
  node.className = 'metric';
  node.append(textElement('span', label), textElement('strong', String(value)));
  return node;
}

function actionButton(label, handler, variant = '') {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `button button-small${variant ? ` button-${variant}` : ''}`;
  button.textContent = label;
  button.addEventListener('click', () => void handler());
  return button;
}

function textElement(tag, text) {
  const node = document.createElement(tag);
  node.textContent = text;
  return node;
}

function toLocalInput(unixSeconds) {
  const date = new Date(unixSeconds * 1000);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

function sampleInput() {
  return JSON.stringify([
    { name: 'session', value: 'replace-with-a-test-value', domain: 'example.com', path: '/', secure: true, httpOnly: true, sameSite: 'lax', session: true },
    { name: 'theme', value: 'monochrome', domain: 'example.com', path: '/', secure: true, httpOnly: false, sameSite: 'strict', session: true },
  ], null, 2);
}

function bindElements() {
  const byId = (id) => {
    const element = document.getElementById(id);
    if (!element) throw new Error(`Missing element #${id}`);
    return element;
  };
  return {
    input: byId('input'), inputFormat: byId('input-format'), fallbackDomain: byId('fallback-domain'),
    parse: byId('parse'), parseStatus: byId('parse-status'), inputSize: byId('input-size'),
    file: byId('file'), openFile: byId('open-file'), warningList: byId('warning-list'), warningEmpty: byId('warning-empty'),
    search: byId('search'), selectAll: byId('select-all'), deleteSelected: byId('delete-selected'),
    undo: byId('undo'), redo: byId('redo'), reveal: byId('reveal'), selection: byId('selection'),
    cookieList: byId('cookie-list'), cookieCount: byId('cookie-count'), empty: byId('empty'),
    summary: byId('summary'), validationTable: byId('validation-table'), validationEmpty: byId('validation-empty'),
    output: byId('output'), outputFormat: byId('output-format'), includeHttpOnly: byId('include-http-only'),
    generate: byId('generate'), copy: byId('copy'), download: byId('download'), outputStatus: byId('output-status'),
    canonicalize: byId('canonicalize'), clear: byId('clear'), tabs: [...document.querySelectorAll('[data-panel]')],
    panels: [...document.querySelectorAll('[data-panel-view]')], dialog: byId('editor-dialog'), form: byId('editor-form'),
    closeDialog: byId('close-dialog'), cancelDialog: byId('cancel-dialog'), editorTitle: byId('editor-title'),
    editorName: byId('editor-name'), editorValue: byId('editor-value'), editorDomain: byId('editor-domain'),
    editorPath: byId('editor-path'), editorSecure: byId('editor-secure'), editorHttpOnly: byId('editor-http-only'),
    editorSameSite: byId('editor-same-site'), editorSession: byId('editor-session'), editorExpiration: byId('editor-expiration'),
    editorIssues: byId('editor-issues'), editorKey: byId('editor-key'),
  };
}
