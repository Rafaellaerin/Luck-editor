import { access, readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const root = path.join(process.cwd(), 'dist', 'extension');
const failures = [];
const required = [
  'manifest.json',
  'background/service-worker.js',
  'popup/popup.html',
  'popup/popup.js',
  'options/options.html',
  'options/options.js',
  'styles/tokens.css',
  'styles/base.css',
  'styles/components.css',
  'styles/popup.css',
  'assets/icons/icon16.png',
  'assets/icons/icon32.png',
  'assets/icons/icon48.png',
  'assets/icons/icon128.png',
];
for (const relative of required) {
  try { await access(path.join(root, relative)); } catch { failures.push(`Missing ${relative}`); }
}
const manifest = JSON.parse(await readFile(path.join(root, 'manifest.json'), 'utf8'));
if (manifest.name !== 'Luck Editor') failures.push('Manifest name must be Luck Editor.');
if (manifest.manifest_version !== 3) failures.push('Manifest must use version 3.');
if (manifest.host_permissions) failures.push('Required host_permissions are forbidden; use optional_host_permissions.');
if (!manifest.optional_host_permissions?.length) failures.push('Optional host permissions are missing.');
if (!manifest.content_security_policy?.extension_pages) failures.push('Explicit extension CSP is missing.');

for (const file of await walk(root)) {
  if (!/\.(?:js|html|css|json)$/.test(file)) continue;
  const content = await readFile(file, 'utf8');
  if (/\beval\s*\(|new\s+Function\s*\(/.test(content)) failures.push(`Dynamic code execution found in ${path.relative(root, file)}`);
  const remoteResourcePatterns = [
    /(?:src|href)=[\"']https?:\/\//i,
    /(?:import|export)\s+(?:[^;]*?from\s*)?[\"']https?:\/\//i,
    /import\s*\(\s*[\"']https?:\/\//i,
    /fetch\s*\(\s*[\"']https?:\/\//i,
    /new\s+WebSocket\s*\(\s*[\"']wss?:\/\//i,
  ];
  if (remoteResourcePatterns.some((pattern) => pattern.test(content))) failures.push(`Unexpected remote resource found in ${path.relative(root, file)}`);
  for (const match of content.matchAll(/#[0-9a-fA-F]{6}\b/g)) {
    const color = match[0].toLowerCase();
    if (color !== '#000000' && color !== '#ffffff') failures.push(`Non-monochrome hex color ${match[0]} found in ${path.relative(root, file)}`);
  }
}
if (failures.length) {
  console.error(failures.join('\n'));
  process.exit(1);
}
console.log('Extension validation passed.');

async function walk(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(full));
    else if ((await stat(full)).isFile()) files.push(full);
  }
  return files;
}
