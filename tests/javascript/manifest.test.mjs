import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const manifest = JSON.parse(await readFile(new URL('../../extension/manifest.json', import.meta.url), 'utf8'));

test('manifest uses the Luck Editor identity', () => {
  assert.equal(manifest.name, 'Luck Editor');
  assert.equal(manifest.manifest_version, 3);
});

test('options page is packaged as an extension page', () => {
  assert.deepEqual(manifest.options_ui, { page: 'options/options.html', open_in_tab: true });
});

test('host access is optional', () => {
  assert.equal(manifest.host_permissions, undefined);
  assert.deepEqual(manifest.optional_host_permissions, ['http://*/*', 'https://*/*']);
});

test('manifest has a restrictive content security policy', () => {
  const policy = manifest.content_security_policy.extension_pages;
  assert.match(policy, /default-src 'self'/);
  assert.match(policy, /object-src 'none'/);
  assert.match(policy, /frame-ancestors 'none'/);
});
