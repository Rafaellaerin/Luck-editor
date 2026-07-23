import { errorMessage } from '../core/errors.js';

void hardenStorage();

chrome.runtime.onInstalled.addListener(() => {
  void chrome.action.setBadgeBackgroundColor({ color: '#000000' });
  void chrome.action.setBadgeTextColor?.({ color: '#FFFFFF' });
});

chrome.tabs.onActivated.addListener(({ tabId }) => void updateBadge(tabId));
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'complete') void updateBadge(tabId);
});
chrome.cookies.onChanged.addListener(() => void updateActiveBadge());

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || typeof message !== 'object') return false;
  const type = (message as { type?: unknown }).type;
  if (type === 'luck.health') {
    sendResponse({ ok: true, version: chrome.runtime.getManifest().version });
    return false;
  }
  return false;
});

async function hardenStorage(): Promise<void> {
  try {
    await chrome.storage.local.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' });
    await chrome.storage.session.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' });
  } catch (error) {
    console.warn('Luck Editor could not restrict storage access:', errorMessage(error));
  }
}

async function updateActiveBadge(): Promise<void> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabId = tabs[0]?.id;
  if (typeof tabId === 'number') await updateBadge(tabId);
}

async function updateBadge(tabId: number): Promise<void> {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab.url || (!tab.url.startsWith('http://') && !tab.url.startsWith('https://'))) {
      await chrome.action.setBadgeText({ text: '', tabId });
      await chrome.action.setTitle({ title: 'Luck Editor: unsupported page', tabId });
      return;
    }
    const cookies = await chrome.cookies.getAll({ url: tab.url });
    await chrome.action.setBadgeText({ text: cookies.length ? compactCount(cookies.length) : '', tabId });
    await chrome.action.setTitle({ title: `Luck Editor: ${cookies.length} cookies on this page`, tabId });
  } catch {
    await chrome.action.setBadgeText({ text: '', tabId });
  }
}

function compactCount(value: number): string {
  if (value < 1000) return String(value);
  if (value < 10_000) return `${Math.floor(value / 1000)}k`;
  return '9k+';
}
