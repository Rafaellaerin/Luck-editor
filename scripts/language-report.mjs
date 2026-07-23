import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const extensions = new Map([
  ['.rs', 'Rust'], ['.c', 'C'], ['.h', 'C'], ['.cpp', 'C++'], ['.hpp', 'C++'],
  ['.ts', 'TypeScript'], ['.js', 'JavaScript'], ['.mjs', 'JavaScript'], ['.html', 'HTML'], ['.css', 'CSS'],
  ['.md', 'Markdown'], ['.yml', 'YAML'], ['.yaml', 'YAML'], ['.json', 'JSON'], ['.toml', 'TOML'],
]);
const ignored = new Set(['.git', 'node_modules', 'dist', 'build', 'target']);
const totals = new Map();
for (const file of await walk(process.cwd())) {
  const language = extensions.get(path.extname(file));
  if (!language) continue;
  const content = await readFile(file, 'utf8');
  const lines = content === '' ? 0 : content.split(/\r?\n/).length;
  totals.set(language, (totals.get(language) ?? 0) + lines);
}
for (const [language, lines] of [...totals.entries()].sort((a, b) => b[1] - a[1])) console.log(`${language.padEnd(15)} ${String(lines).padStart(8)} lines`);

async function walk(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (ignored.has(entry.name) || entry.name.startsWith('build-') || entry.name.startsWith('cmake-build-')) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(full)); else files.push(full);
  }
  return files;
}
