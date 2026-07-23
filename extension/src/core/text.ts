const encoder = new TextEncoder();

export function byteLength(value: string): number {
  return encoder.encode(value).byteLength;
}

export function truncateByCodePoints(value: string, maximum: number): string {
  if (maximum <= 0) return '';
  const points = Array.from(value);
  if (points.length <= maximum) return value;
  return `${points.slice(0, Math.max(0, maximum - 1)).join('')}…`;
}

export function normalizeLineEndings(value: string): string {
  return value.replace(/\r\n?/g, '\n');
}

export function splitNonEmptyLines(value: string): string[] {
  return normalizeLineEndings(value)
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

export function maskSecret(value: string, visible = 3): string {
  const chars = Array.from(value);
  if (chars.length === 0) return '(empty)';
  if (chars.length <= visible * 2) return '•'.repeat(Math.max(4, chars.length));
  return `${chars.slice(0, visible).join('')}${'•'.repeat(Math.min(24, chars.length - visible * 2))}${chars.slice(-visible).join('')}`;
}

export function stableId(prefix = 'id'): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  const token = Array.from(bytes, (part) => part.toString(16).padStart(2, '0')).join('');
  return `${prefix}_${token}`;
}

export function safeFilename(value: string, fallback = 'cookies'): string {
  const normalized = value.normalize('NFKD').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '');
  return (normalized || fallback).slice(0, 120);
}

export function constantTimeEqual(left: string, right: string): boolean {
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  const length = Math.max(a.length, b.length);
  let difference = a.length ^ b.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return difference === 0;
}
