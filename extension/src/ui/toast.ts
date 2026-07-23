import { LIMITS } from '../core/constants.js';
import { truncateByCodePoints } from '../core/text.js';
import { byId } from './dom.js';

let timer: number | undefined;

export function toast(message: string, kind: 'info' | 'success' | 'error' = 'info'): void {
  const node = byId<HTMLDivElement>('toast');
  node.textContent = truncateByCodePoints(message, LIMITS.toastBytes);
  node.dataset.kind = kind;
  node.hidden = false;
  window.clearTimeout(timer);
  timer = window.setTimeout(() => {
    node.hidden = true;
    node.textContent = '';
  }, kind === 'error' ? 5000 : 2800);
}
