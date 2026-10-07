// Black-box tests: boot server.js against a throwaway DATA_DIR and talk to it over HTTP.
// Run with `npm test` (node:test, no extra dependencies).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const PORT = 3900 + Math.floor(Math.random() * 90);
const BASE = `http://127.0.0.1:${PORT}`;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opengym-api-'));
const ADMIN = 'adminuid';
const ALICE = 'aliceuid';
const BOB = 'bobuid';
let server, secret;

// Mint a cookie the same way server.js does (HMAC over `<uid>:<exp>:<version>`).
const mac = payload => crypto.createHmac('sha256', secret).update(payload).digest('base64url');
const cookie = (uid, exp = Date.now() + 3600e3, ver = 0) => {
  const p = `${uid}:${exp}:${ver}`;
  return `gymsid=${p}.${mac(p)}`;
};
const call = (method, url, { cookie: c, body, type = 'application/json' } = {}) => fetch(BASE + url, {
  method,
  headers: { ...(c ? { cookie: c } : {}), ...(body !== undefined ? { 'content-type': type } : {}) },
  body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body)
});

before(async () => {
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify({
    users: [{ id: ADMIN, name: 'Admin' }, { id: ALICE, name: 'Alice' }, { id: BOB, name: 'Bob' }],
    creds: [], subs: [], invites: []
  }));
  server = spawn(process.execPath, [path.join(import.meta.dirname, 'server.js')], {
    env: { ...process.env, PORT: String(PORT), DATA_DIR: dir, ADMIN_UIDS: ADMIN, ORIGIN: `http://localhost:${PORT}` },
    stdio: 'ignore'
  });
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(BASE + '/api/health')).ok) break; } catch { /* not up yet */ }
    await new Promise(r => setTimeout(r, 100));
  }
  secret = fs.readFileSync(path.join(dir, 'secret'), 'utf8').trim();
});
after(() => { server?.kill(); fs.rmSync(dir, { recursive: true, force: true }); });

test('no cookie → 401', async () => {
  assert.equal((await call('GET', '/api/me')).status, 401);
  assert.equal((await call('GET', '/api/data')).status, 401);
});

test('valid cookie → /api/me', async () => {
  const r = await call('GET', '/api/me', { cookie: cookie(ALICE) });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).user.id, ALICE);
});

test('tampered or wrongly signed cookie is rejected', async () => {
  const good = cookie(ALICE);
  assert.equal((await call('GET', '/api/me', { cookie: good.replace(ALICE, ADMIN) })).status, 401);
  assert.equal((await call('GET', '/api/me', { cookie: good.slice(0, -2) + 'xx' })).status, 401);
  assert.equal((await call('GET', '/api/me', { cookie: 'gymsid=garbage' })).status, 401);
});

test('expired cookie is rejected', async () => {
  assert.equal((await call('GET', '/api/me', { cookie: cookie(ALICE, Date.now() - 1000) })).status, 401);
});

test('logout/all invalidates every earlier cookie', async () => {
  const old = cookie(BOB);
  assert.equal((await call('GET', '/api/me', { cookie: old })).status, 200);
  assert.equal((await call('POST', '/api/logout/all', { cookie: old, body: {} })).status, 200);
  assert.equal((await call('GET', '/api/me', { cookie: old })).status, 401);
  assert.equal((await call('GET', '/api/me', { cookie: cookie(BOB, undefined, 1) })).status, 200);
});

test('non-admin gets 403 on every admin route', async () => {
  const c = cookie(ALICE);
  for (const [m, u] of [['GET', '/api/admin/users'], ['GET', '/api/admin/user?id=' + BOB], ['GET', '/api/admin/invites'],
    ['POST', '/api/admin/user/disable'], ['POST', '/api/admin/invites/new'], ['POST', '/api/admin/invites/revoke']]) {
    assert.equal((await call(m, u, { cookie: c, body: m === 'POST' ? {} : undefined })).status, 403, u);
  }
  assert.equal((await call('GET', '/api/admin/users')).status, 401);
  assert.equal((await call('GET', '/api/admin/users', { cookie: cookie(ADMIN) })).status, 200);
});

test('users only ever read their own state', async () => {
  const put = await call('PUT', '/api/data', { cookie: cookie(ALICE), body: { state: { workouts: [{ d: '2026-01-01' }], marker: 'alice' } } });
  assert.equal(put.status, 200);
  assert.equal((await (await call('GET', '/api/data', { cookie: cookie(ALICE) })).json()).state.marker, 'alice');
  assert.equal((await (await call('GET', '/api/data', { cookie: cookie(ADMIN) })).json()).state, null);
});

test('state writes require a JSON content type', async () => {
  const body = JSON.stringify({ state: { marker: 'csrf' } });
  const r = await call('PUT', '/api/data', { cookie: cookie(ALICE), body, type: 'text/plain' });
  assert.equal(r.status, 415);
  const after = (await (await call('GET', '/api/data', { cookie: cookie(ALICE) })).json()).state;
  assert.equal(after.marker, 'alice');
});

test('disabled account is locked out at once', async () => {
  const dis = await call('POST', '/api/admin/user/disable', { cookie: cookie(ADMIN), body: { id: ALICE, disabled: true } });
  assert.equal(dis.status, 200);
  assert.equal((await call('GET', '/api/me', { cookie: cookie(ALICE) })).status, 401);
});
