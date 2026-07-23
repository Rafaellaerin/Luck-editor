import { errorMessage, LuckError } from '../core/errors.js';
import { recordAudit } from '../core/logger.js';
import { isDomainWithinHost, requireValidCookie } from '../core/validation.js';
import type { ActiveContext, CookieRecord, EditableCookie, ImportOptions, MutationReport } from '../core/types.js';
import { CookieRepository } from './repository.js';

export class CookieService {
  public constructor(private readonly repository = new CookieRepository()) {}

  public list(context: ActiveContext, allDomains = false): Promise<readonly CookieRecord[]> {
    return allDomains ? this.repository.listAll() : this.repository.listForContext(context);
  }

  public async save(context: ActiveContext, cookie: EditableCookie, previous?: CookieRecord): Promise<CookieRecord> {
    const valid = requireValidCookie(cookie);
    if (!isDomainWithinHost(valid.domain, context.hostname)) {
      throw new LuckError('DOMAIN_SCOPE', `Domain ${valid.domain} is outside the active host ${context.hostname}.`);
    }
    const keyChanged = previous !== undefined
      && (previous.name !== valid.name || previous.domain !== valid.domain || previous.path !== valid.path);
    const result = await this.repository.set(valid);
    const success = result !== null;
    if (result && keyChanged && previous) {
      await this.repository.remove(previous);
    }
    await recordAudit({ operation: 'cookie.save', domain: valid.domain, count: 1, success, detail: success ? undefined : 'Browser rejected cookie.' });
    if (!result) throw new LuckError('COOKIE_REJECTED', 'The browser rejected this cookie.');
    return result;
  }

  public async remove(cookie: CookieRecord): Promise<boolean> {
    const success = await this.repository.remove(cookie);
    await recordAudit({ operation: 'cookie.remove', domain: cookie.domain, count: 1, success });
    return success;
  }

  public async removeMany(cookies: readonly CookieRecord[]): Promise<MutationReport> {
    let succeeded = 0;
    let failed = 0;
    const messages: string[] = [];
    for (const cookie of cookies) {
      try {
        if (await this.repository.remove(cookie)) succeeded += 1;
        else failed += 1;
      } catch (error) {
        failed += 1;
        messages.push(`${cookie.name}: ${errorMessage(error)}`);
      }
    }
    const report = { attempted: cookies.length, succeeded, skipped: 0, failed, messages };
    await recordAudit({ operation: 'cookie.removeMany', count: cookies.length, success: failed === 0, detail: messages.slice(0, 5).join(' | ') || undefined });
    return report;
  }

  public async import(context: ActiveContext, cookies: readonly EditableCookie[], options: ImportOptions): Promise<MutationReport> {
    let succeeded = 0;
    let skipped = 0;
    let failed = 0;
    const messages: string[] = [];
    for (const raw of cookies) {
      try {
        const candidate = requireValidCookie({
          ...raw,
          secure: options.forceSecure || raw.secure,
          httpOnly: options.forceHttpOnly || raw.httpOnly,
          session: options.preserveSession ? raw.session : false,
          expirationDate: options.preserveSession && raw.session ? undefined : raw.expirationDate ?? Math.floor(Date.now() / 1000) + 31_536_000,
        });
        if (!isDomainWithinHost(candidate.domain, context.hostname)) {
          failed += 1;
          messages.push(`${candidate.name}: domain outside active host`);
          continue;
        }
        if (!options.overwrite && await this.repository.get(candidate)) {
          skipped += 1;
          continue;
        }
        const result = await this.repository.set(candidate);
        if (result) succeeded += 1;
        else failed += 1;
      } catch (error) {
        failed += 1;
        messages.push(errorMessage(error));
      }
    }
    const report = { attempted: cookies.length, succeeded, skipped, failed, messages };
    await recordAudit({ operation: 'cookie.import', domain: context.hostname, count: cookies.length, success: failed === 0, detail: messages.slice(0, 5).join(' | ') || undefined });
    return report;
  }
}
