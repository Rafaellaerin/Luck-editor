import { cloneCookie, cookieKey, sortCookies } from './model.js';

export class CookieLabStore extends EventTarget {
  #cookies = [];
  #selected = new Set();
  #history = [];
  #future = [];
  #maximumHistory;
  #filter = '';

  constructor({ maximumHistory = 50 } = {}) {
    super();
    this.#maximumHistory = Math.max(1, Number(maximumHistory) || 50);
  }

  get cookies() {
    return this.#cookies.map(cloneCookie);
  }

  get selectedKeys() {
    return new Set(this.#selected);
  }

  get filter() {
    return this.#filter;
  }

  get canUndo() {
    return this.#history.length > 0;
  }

  get canRedo() {
    return this.#future.length > 0;
  }

  get visibleCookies() {
    const query = this.#filter.trim().toLowerCase();
    const source = query
      ? this.#cookies.filter((cookie) => [cookie.name, cookie.value, cookie.domain, cookie.path].some((field) => field.toLowerCase().includes(query)))
      : this.#cookies;
    return source.map(cloneCookie);
  }

  replace(cookies, reason = 'replace') {
    this.#checkpoint(reason);
    this.#cookies = sortCookies(cookies.map(cloneCookie));
    this.#selected.clear();
    this.#future.length = 0;
    this.#emit(reason);
  }

  add(cookie) {
    this.#checkpoint('add');
    const key = cookieKey(cookie);
    this.#cookies = this.#cookies.filter((entry) => cookieKey(entry) !== key);
    this.#cookies.push(cloneCookie(cookie));
    this.#cookies = sortCookies(this.#cookies);
    this.#future.length = 0;
    this.#emit('add');
  }

  remove(key) {
    const before = this.#cookies.length;
    const next = this.#cookies.filter((cookie) => cookieKey(cookie) !== key);
    if (next.length === before) return false;
    this.#checkpoint('remove');
    this.#cookies = next;
    this.#selected.delete(key);
    this.#future.length = 0;
    this.#emit('remove');
    return true;
  }

  removeSelected() {
    if (this.#selected.size === 0) return 0;
    this.#checkpoint('remove-selected');
    const before = this.#cookies.length;
    this.#cookies = this.#cookies.filter((cookie) => !this.#selected.has(cookieKey(cookie)));
    const removed = before - this.#cookies.length;
    this.#selected.clear();
    this.#future.length = 0;
    this.#emit('remove-selected');
    return removed;
  }

  clear() {
    if (this.#cookies.length === 0) return;
    this.#checkpoint('clear');
    this.#cookies = [];
    this.#selected.clear();
    this.#future.length = 0;
    this.#emit('clear');
  }

  setFilter(value) {
    this.#filter = String(value).slice(0, 256);
    this.#emit('filter');
  }

  setSelected(key, selected) {
    if (selected) this.#selected.add(key);
    else this.#selected.delete(key);
    this.#emit('selection');
  }

  toggleVisibleSelection() {
    const visibleKeys = this.visibleCookies.map(cookieKey);
    const allSelected = visibleKeys.length > 0 && visibleKeys.every((key) => this.#selected.has(key));
    for (const key of visibleKeys) {
      if (allSelected) this.#selected.delete(key);
      else this.#selected.add(key);
    }
    this.#emit('selection');
  }

  undo() {
    const checkpoint = this.#history.pop();
    if (!checkpoint) return false;
    this.#future.push(this.#capture(`redo:${checkpoint.reason}`));
    this.#restore(checkpoint);
    this.#emit('undo');
    return true;
  }

  redo() {
    const checkpoint = this.#future.pop();
    if (!checkpoint) return false;
    this.#history.push(this.#capture(`undo:${checkpoint.reason}`));
    this.#restore(checkpoint);
    this.#emit('redo');
    return true;
  }

  exportState() {
    return {
      version: 1,
      cookies: this.cookies,
      selected: [...this.#selected],
      filter: this.#filter,
    };
  }

  importState(value) {
    if (!value || typeof value !== 'object' || value.version !== 1 || !Array.isArray(value.cookies)) {
      throw new TypeError('Unsupported Cookie Lab state.');
    }
    this.#checkpoint('import-state');
    this.#cookies = sortCookies(value.cookies.map(cloneCookie));
    this.#selected = new Set(Array.isArray(value.selected) ? value.selected.map(String) : []);
    this.#filter = String(value.filter ?? '').slice(0, 256);
    this.#future.length = 0;
    this.#emit('import-state');
  }

  #checkpoint(reason) {
    this.#history.push(this.#capture(reason));
    while (this.#history.length > this.#maximumHistory) this.#history.shift();
  }

  #capture(reason) {
    return {
      reason,
      cookies: this.#cookies.map(cloneCookie),
      selected: new Set(this.#selected),
      filter: this.#filter,
    };
  }

  #restore(checkpoint) {
    this.#cookies = checkpoint.cookies.map(cloneCookie);
    this.#selected = new Set(checkpoint.selected);
    this.#filter = checkpoint.filter;
  }

  #emit(reason) {
    this.dispatchEvent(new CustomEvent('change', { detail: { reason, state: this.exportState() } }));
  }
}
