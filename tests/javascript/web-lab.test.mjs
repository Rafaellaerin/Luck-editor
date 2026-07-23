import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalizeCookie, cookieKey } from '../../web/js/model.js';
import { detectFormat, parseCookies } from '../../web/js/parser.js';
import { serializeCookies } from '../../web/js/serializer.js';
import { validateCookie } from '../../web/js/validator.js';

test('web parser detects supported formats', () => {
  assert.equal(detectFormat('[{"name":"a"}]'), 'json');
  assert.equal(detectFormat('Cookie: a=1; b=2'), 'cookie-header');
  assert.equal(detectFormat('Set-Cookie: a=1; Secure'), 'set-cookie');
});

test('web parser deduplicates with last value winning', () => {
  const report = parseCookies('a=1\na=2', { fallbackDomain: 'example.com' });
  assert.equal(report.cookies.length, 1);
  assert.equal(report.cookies[0].value, '2');
  assert.equal(report.duplicatesRemoved, 1);
});

test('canonicalizer enforces host prefix rules', () => {
  const result = canonicalizeCookie({ name: '__Host-session', value: 'x', domain: '.Example.com.', path: '/admin', secure: false });
  assert.equal(result.cookie.domain, 'example.com');
  assert.equal(result.cookie.path, '/');
  assert.equal(result.cookie.secure, true);
  assert.equal(result.cookie.hostOnly, true);
});

test('validator rejects line breaks in values', () => {
  const result = validateCookie(canonicalizeCookie({ name: 'a', value: 'x\ny', domain: 'example.com', path: '/' }).cookie);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((entry) => entry.code === 'value.control'));
});

test('redacted serializer never includes secret values', () => {
  const cookie = canonicalizeCookie({ name: 'session', value: 'secret', domain: 'example.com', path: '/', secure: true, httpOnly: true }).cookie;
  const output = serializeCookies([cookie], { format: 'redacted-json', includeHttpOnly: true });
  assert.match(output, /REDACTED/);
  assert.doesNotMatch(output, /secret/);
});

test('cookie key separates path and domain', () => {
  const left = canonicalizeCookie({ name: 'a', value: '1', domain: 'example.com', path: '/' }).cookie;
  const right = canonicalizeCookie({ name: 'a', value: '1', domain: 'example.com', path: '/admin' }).cookie;
  assert.notEqual(cookieKey(left), cookieKey(right));
});
