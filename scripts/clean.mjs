import { rm } from 'node:fs/promises';
for (const target of ['build', 'dist']) await rm(target, { recursive: true, force: true });
