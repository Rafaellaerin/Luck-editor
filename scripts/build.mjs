import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const root = process.cwd();
const buildJs = path.join(root, 'build', 'extension-js');
const output = path.join(root, 'dist', 'extension');
await rm(path.join(root, 'build'), { recursive: true, force: true });
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });

const compiler = process.platform === 'win32' ? 'tsc.cmd' : 'tsc';
const result = spawnSync(compiler, ['--pretty', 'false'], { stdio: 'inherit' });
if (result.status !== 0) process.exit(result.status ?? 1);

await cp(buildJs, output, { recursive: true });
await cp(path.join(root, 'extension', 'manifest.json'), path.join(output, 'manifest.json'));
await cp(path.join(root, 'extension', 'assets'), path.join(output, 'assets'), { recursive: true });
await cp(path.join(root, 'extension', 'src', 'styles'), path.join(output, 'styles'), { recursive: true });
await cp(path.join(root, 'extension', 'src', 'popup', 'popup.html'), path.join(output, 'popup', 'popup.html'));
await cp(path.join(root, 'extension', 'src', 'options', 'options.html'), path.join(output, 'options', 'options.html'));

const manifest = JSON.parse(await readFile(path.join(output, 'manifest.json'), 'utf8'));
manifest.version = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8')).version;
await writeFile(path.join(output, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Built ${output}`);
