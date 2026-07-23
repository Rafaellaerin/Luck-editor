export type SameSite = 'no_restriction' | 'lax' | 'strict' | 'unspecified';

export interface CookieRecord {
  readonly name: string;
  readonly value: string;
  readonly domain: string;
  readonly path: string;
  readonly secure: boolean;
  readonly httpOnly: boolean;
  readonly sameSite: SameSite;
  readonly expirationDate?: number;
  readonly storeId?: string;
  readonly hostOnly?: boolean;
  readonly session?: boolean;
  readonly partitionKey?: Readonly<{ topLevelSite?: string; hasCrossSiteAncestor?: boolean }>;
}

export interface EditableCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: SameSite;
  expirationDate?: number;
  session: boolean;
  storeId?: string;
}

export interface ParseIssue {
  readonly line?: number;
  readonly code: string;
  readonly message: string;
  readonly severity: 'warning' | 'error';
}

export interface ParseResult {
  readonly format: ImportFormat;
  readonly cookies: readonly EditableCookie[];
  readonly issues: readonly ParseIssue[];
}

export type ImportFormat = 'json' | 'netscape' | 'cookie-header' | 'set-cookie' | 'lines' | 'unknown';
export type ExportFormat = 'json' | 'netscape' | 'cookie-header' | 'set-cookie' | 'curl' | 'redacted-json';

export interface AppSettings {
  confirmSingleDelete: boolean;
  confirmBulkDelete: boolean;
  maskValues: boolean;
  autoRefreshAfterMutation: boolean;
  includeHttpOnlyInExport: boolean;
  includeSecureValuesInSnapshot: boolean;
}

export interface Snapshot {
  readonly id: string;
  readonly name: string;
  readonly domain: string;
  readonly createdAt: number;
  readonly cookies: readonly EditableCookie[];
  readonly redacted: boolean;
}

export interface AuditEvent {
  readonly id: string;
  readonly timestamp: number;
  readonly operation: string;
  readonly domain?: string;
  readonly count?: number;
  readonly success: boolean;
  readonly detail?: string;
}

export interface ActiveContext {
  readonly tabId: number;
  readonly url: URL;
  readonly originPattern: string;
  readonly hostname: string;
}

export interface ImportOptions {
  readonly forceSecure: boolean;
  readonly forceHttpOnly: boolean;
  readonly overwrite: boolean;
  readonly preserveSession: boolean;
}

export interface MutationReport {
  readonly attempted: number;
  readonly succeeded: number;
  readonly skipped: number;
  readonly failed: number;
  readonly messages: readonly string[];
}
