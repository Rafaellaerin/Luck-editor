import { mkdir, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const dist = path.join(process.cwd(), 'dist');
const source = path.join(dist, 'extension');
const target = path.join(dist, 'luck-editor-extension.zip');
await mkdir(dist, { recursive: true });
await rm(target, { force: true });
const result = spawnSync('zip', ['-qr', target, '.'], { cwd: source, stdio: 'inherit' });
if (result.status !== 0) process.exit(result.status ?? 1);
console.log(`Packaged ${target}`);
