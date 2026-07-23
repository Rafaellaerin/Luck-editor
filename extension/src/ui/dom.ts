import { LuckError } from '../core/errors.js';

export function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new LuckError('DOM_MISSING', `Missing required element #${id}.`);
  return element as T;
}

export function all<T extends Element>(selector: string, parent: ParentNode = document): T[] {
  return Array.from(parent.querySelectorAll<T>(selector));
}

export function clear(element: Element): void {
  element.replaceChildren();
}

export function element<K extends keyof HTMLElementTagNameMap>(tag: K, options: {
  className?: string;
  text?: string;
  title?: string;
  attributes?: Readonly<Record<string, string>>;
} = {}): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined) node.textContent = options.text;
  if (options.title) node.title = options.title;
  for (const [name, value] of Object.entries(options.attributes ?? {})) node.setAttribute(name, value);
  return node;
}

export function button(text: string, className: string, onClick: () => void | Promise<void>): HTMLButtonElement {
  const node = element('button', { text, className, attributes: { type: 'button' } });
  node.addEventListener('click', () => void onClick());
  return node;
}

export function setHidden(element: HTMLElement, hidden: boolean): void {
  element.hidden = hidden;
}
