import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCookieInput } from '../../dist/extension/import/index.js';
import { validateCookie } from '../../dist/extension/core/validation.js';

test('compiled Set-Cookie parser handles Expires followed by attributes', () => {
  const report = parseCookieInput(
    'Set-Cookie: session=abc; Expires=Wed, 21 Oct 2030 07:28:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax',
    'example.com',
  );
  assert.equal(report.cookies.length, 1);
  assert.equal(report.cookies[0].secure, true);
  assert.equal(report.cookies[0].httpOnly, true);
  assert.equal(report.cookies[0].path, '/');
  assert.equal(report.cookies[0].sameSite, 'lax');
  assert.ok(report.cookies[0].expirationDate > 0);
});

test('compiled validator rejects paths unsafe for cookie URL construction', () => {
  const result = validateCookie({
    name: 'a', value: 'b', domain: 'example.com', path: '/a?b', secure: true,
    httpOnly: true, sameSite: 'lax', session: true,
  });
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.code === 'PATH_UNSAFE'));
});
