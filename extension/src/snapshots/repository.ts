import { LIMITS, STORAGE_KEYS } from '../core/constants.js';
import { byteLength, stableId } from '../core/text.js';
import type { AppSettings, CookieRecord, EditableCookie, Snapshot } from '../core/types.js';
import { LuckError } from '../core/errors.js';

export class SnapshotRepository {
  public async list(): Promise<readonly Snapshot[]> {
    const data = await chrome.storage.session.get(STORAGE_KEYS.snapshots);
    const snapshots = data[STORAGE_KEYS.snapshots];
    return Array.isArray(snapshots) ? snapshots as Snapshot[] : [];
  }

  public async create(name: string, domain: string, cookies: readonly CookieRecord[], settings: AppSettings): Promise<Snapshot> {
    const normalizedName = name.trim();
    if (!normalizedName) throw new LuckError('SNAPSHOT_NAME', 'Snapshot name is required.');
    if (byteLength(normalizedName) > LIMITS.snapshotNameBytes) throw new LuckError('SNAPSHOT_NAME_LONG', `Snapshot name exceeds ${LIMITS.snapshotNameBytes} bytes.`);
    if (cookies.length > LIMITS.snapshotCookies) throw new LuckError('SNAPSHOT_TOO_LARGE', `A snapshot is limited to ${LIMITS.snapshotCookies} cookies.`);
    const redacted = !settings.includeSecureValuesInSnapshot;
    const snapshot: Snapshot = {
      id: stableId('snapshot'),
      name: normalizedName,
      domain,
      createdAt: Date.now(),
      redacted,
      cookies: cookies.map((cookie): EditableCookie => ({
        name: cookie.name,
        value: redacted ? '' : cookie.value,
        domain: cookie.domain,
        path: cookie.path,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite: cookie.sameSite,
        session: !cookie.expirationDate,
        expirationDate: cookie.expirationDate,
        storeId: cookie.storeId,
      })),
    };
    const current = await this.list();
    await chrome.storage.session.set({ [STORAGE_KEYS.snapshots]: [snapshot, ...current].slice(0, LIMITS.snapshotCount) });
    return snapshot;
  }

  public async remove(id: string): Promise<void> {
    const current = await this.list();
    await chrome.storage.session.set({ [STORAGE_KEYS.snapshots]: current.filter((snapshot) => snapshot.id !== id) });
  }

  public async clear(): Promise<void> {
    await chrome.storage.session.remove(STORAGE_KEYS.snapshots);
  }
}
