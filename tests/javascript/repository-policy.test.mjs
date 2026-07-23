import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(new URL('../..', import.meta.url).pathname);
const checkedRoots = ['extension', 'web', 'scripts'];

test('browser-facing source has no remote resources or dynamic execution', async () => {
  for (const directory of checkedRoots) {
    for (const file of await walk(path.join(root, directory))) {
      if (!/\.(?:ts|js|mjs|html|css)$/.test(file)) continue;
      const content = await readFile(file, 'utf8');
      assert.doesNotMatch(content, /\beval\s*\(|new\s+Function\s*\(/, file);
      assert.doesNotMatch(content, /(?:src|href)=["']https?:\/\//i, file);
      assert.doesNotMatch(content, /(?:import|export)\s+(?:[^;]*?from\s*)?["']https?:\/\//i, file);
    }
  }
});

test('all CSS source remains strictly monochrome', async () => {
  for (const directory of ['extension', 'web']) {
    for (const file of await walk(path.join(root, directory))) {
      if (!file.endsWith('.css')) continue;
      const content = await readFile(file, 'utf8');
      for (const match of content.matchAll(/#[0-9a-fA-F]{6}\b/g)) {
        assert.ok(['#000000', '#ffffff'].includes(match[0].toLowerCase()), `${file}: ${match[0]}`);
      }
      for (const match of content.matchAll(/rgb\(\s*(\d+)\s+(\d+)\s+(\d+)/g)) {
        const channels = match.slice(1, 4).map(Number);
        assert.ok(channels.every((channel) => channel === 0) || channels.every((channel) => channel === 255), `${file}: ${match[0]}`);
      }
    }
  }
});

test('README contains no emoji characters', async () => {
  const readme = await readFile(path.join(root, 'README.md'), 'utf8');
  const emoji = [...readme].filter((character) => {
    const code = character.codePointAt(0);
    return (code >= 0x1f000 && code <= 0x1faff) || (code >= 0x2600 && code <= 0x27bf);
  });
  assert.deepEqual(emoji, []);
});

async function walk(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (['node_modules', 'dist', 'build', 'target'].includes(entry.name) || entry.name.startsWith('build-')) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(full));
    else files.push(full);
  }
  return files;
}
