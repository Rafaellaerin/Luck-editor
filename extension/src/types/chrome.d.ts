declare const chrome: {
  runtime: {
    lastError?: { message?: string };
    onInstalled: { addListener(callback: (details: unknown) => void): void };
    onMessage: { addListener(callback: (message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => boolean | void): void };
    sendMessage<T = unknown>(message: unknown): Promise<T>;
    getManifest(): { version: string; name: string };
    openOptionsPage(): Promise<void>;
  };
  action: {
    setBadgeBackgroundColor(details: { color: string | [number, number, number, number] }): Promise<void>;
    setBadgeTextColor?(details: { color: string | [number, number, number, number] }): Promise<void>;
    setBadgeText(details: { text: string; tabId?: number }): Promise<void>;
    setTitle(details: { title: string; tabId?: number }): Promise<void>;
  };
  tabs: {
    query(queryInfo: Record<string, unknown>): Promise<Array<{ id?: number; url?: string; title?: string }>>;
    get(tabId: number): Promise<{ id?: number; url?: string; title?: string }>;
    reload(tabId?: number): Promise<void>;
    onActivated: { addListener(callback: (activeInfo: { tabId: number }) => void): void };
    onUpdated: { addListener(callback: (tabId: number, changeInfo: { status?: string }, tab: unknown) => void): void };
  };
  cookies: {
    getAll(details: Record<string, unknown>): Promise<ChromeCookie[]>;
    get(details: { url: string; name: string; storeId?: string }): Promise<ChromeCookie | null>;
    set(details: Record<string, unknown>): Promise<ChromeCookie | null>;
    remove(details: { url: string; name: string; storeId?: string }): Promise<{ url: string; name: string; storeId: string } | null>;
    onChanged: { addListener(callback: (changeInfo: unknown) => void): void };
  };
  permissions: {
    contains(permissions: { origins?: string[]; permissions?: string[] }): Promise<boolean>;
    request(permissions: { origins?: string[]; permissions?: string[] }): Promise<boolean>;
    remove(permissions: { origins?: string[]; permissions?: string[] }): Promise<boolean>;
    getAll(): Promise<{ origins?: string[]; permissions?: string[] }>;
  };
  storage: {
    local: StorageArea;
    session: StorageArea;
  };
};

interface StorageArea {
  get(keys?: string | string[] | Record<string, unknown> | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
  clear(): Promise<void>;
  setAccessLevel?(options: { accessLevel: 'TRUSTED_CONTEXTS' | 'TRUSTED_AND_UNTRUSTED_CONTEXTS' }): Promise<void>;
}

interface ChromeCookie {
  domain: string;
  expirationDate?: number;
  hostOnly: boolean;
  httpOnly: boolean;
  name: string;
  partitionKey?: { topLevelSite?: string; hasCrossSiteAncestor?: boolean };
  path: string;
  sameSite: 'no_restriction' | 'lax' | 'strict' | 'unspecified';
  secure: boolean;
  session: boolean;
  storeId: string;
  value: string;
}
