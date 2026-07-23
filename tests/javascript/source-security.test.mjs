import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const sourceRoot = new URL('../../extension/src/', import.meta.url);

test('extension source does not execute dynamic strings', async () => {
  const files = await walk(sourceRoot);
  for (const file of files.filter((entry) => /\.(?:ts|html)$/.test(entry.pathname))) {
    const content = await readFile(file, 'utf8');
    assert.doesNotMatch(content, /\beval\s*\(|new\s+Function\s*\(/, file.pathname);
  }
});

test('dynamic user data is not assigned through innerHTML', async () => {
  const files = await walk(sourceRoot);
  for (const file of files.filter((entry) => entry.pathname.endsWith('.ts'))) {
    const content = await readFile(file, 'utf8');
    assert.doesNotMatch(content, /\.innerHTML\s*=/, file.pathname);
  }
});

async function walk(url) {
  const files = [];
  for (const entry of await readdir(url, { withFileTypes: true })) {
    const child = new URL(entry.name + (entry.isDirectory() ? '/' : ''), url);
    if (entry.isDirectory()) files.push(...await walk(child)); else files.push(child);
  }
  return files;
}
