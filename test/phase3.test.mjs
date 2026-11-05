import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, test } from 'node:test';
import { parseKey } from '../src/crypto.mjs';
import { assertPassphrase, isWrappedEnvelope, unwrapKey, wrapKey } from '../src/passphrase.mjs';
import { parseDuration, sessionEndpoint, sessionRequest } from '../src/session.mjs';
import { initHome, POSIX, skv, tmpDir } from './helpers.mjs';

const SECRET = 'S3cr3t-phase3-do-not-leak';
const PASS = 'correct horse battery';
const ok = (r) => assert.equal(r.status, 0, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const printLen = [process.execPath, '-e', 'process.stdout.write(String((process.env.K || "").length))'];

// Every session process a test starts, so none is left running whatever happens.
const pids = new Set();
const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
};
after(() => {
  for (const pid of pids) {
    try {
      process.kill(pid, 'SIGTERM');
    } catch {}
  }
});

const readSession = (home) => JSON.parse(fs.readFileSync(path.join(home, 'session.json'), 'utf8'));
const logEntries = (home) => fs.readFileSync(path.join(home, 'log.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));

/** An initialized home with g/K = SECRET and a passphrase set via stdin. Returns { home, rawKey }. */
function protectedHome() {
  const home = initHome();
  ok(skv(home, ['set', 'g', 'K'], { input: SECRET }));
  const rawKey = fs.readFileSync(path.join(home, 'key'), 'utf8').trim();
  ok(skv(home, ['passphrase', 'set'], { input: `${PASS}\n` }));
  return { home, rawKey };
}

function unlock(home, args = []) {
  const r = skv(home, ['unlock', ...args], { input: `${PASS}\n` });
  ok(r);
  const s = readSession(home);
  pids.add(s.pid);
  return s;
}

async function waitGone(pid, ms = 3000) {
  for (let t = 0; t < ms && alive(pid); t += 50) await sleep(50);
  return !alive(pid);
}

test('wrapKey / unwrapKey: round trip, wrong passphrase, stored params, fresh salt', () => {
  const key = Buffer.alloc(32, 7);
  const env = wrapKey(key, PASS);
  assert.ok(isWrappedEnvelope(env));
  assert.deepEqual(env.params, { N: 2 ** 17, r: 8, p: 1, keylen: 32 });
  assert.equal(Buffer.from(env.salt, 'base64').length, 16);
  for (const f of ['v', 'kdf', 'params', 'salt', 'iv', 'tag', 'data']) assert.ok(f in env, f);
  assert.deepEqual(unwrapKey(env, PASS), key);
  assert.throws(() => unwrapKey(env, 'wrong passphrase'), { code: 'bad-passphrase' });
  assert.throws(() => unwrapKey({ ...env, data: Buffer.alloc(32).toString('base64') }, PASS), { code: 'bad-passphrase' });
  assert.notEqual(wrapKey(key, PASS).salt, env.salt);
  assert.throws(() => assertPassphrase('short'), { code: 'weak-passphrase' });
});

test('parseDuration and the socket path fallback', () => {
  assert.equal(parseDuration('30m'), 30 * 60e3);
  assert.equal(parseDuration('8h'), 8 * 3600e3);
  assert.equal(parseDuration('1d'), 86400e3);
  assert.equal(parseDuration('2s'), 2000);
  for (const bad of ['', '8', 'h', '0h', '1y', '31d']) assert.throws(() => parseDuration(bad), { code: 'usage' }, bad);
  assert.equal(sessionEndpoint('/tmp/x', { platform: 'linux' }).socket, '/tmp/x/session.sock');
  const long = sessionEndpoint(`/tmp/${'a'.repeat(120)}`, { platform: 'darwin', tmpdir: '/tmp' });
  assert.match(long.socket, /^\/tmp\/skv-[0-9a-f]{16}\/s\.sock$/);
  assert.equal(long.dir, path.dirname(long.socket));
  assert.match(sessionEndpoint('C:\\Users\\me\\.skv', { platform: 'win32' }).socket, /^\\\\\.\\pipe\\skv-[0-9a-f]{16}$/);
});

test('passphrase set wraps the key file; the vault is unchanged; raw SKV_KEY still opens it; locked otherwise', () => {
  const { home, rawKey } = protectedHome();
  const env = JSON.parse(fs.readFileSync(path.join(home, 'key'), 'utf8'));
  assert.ok(isWrappedEnvelope(env));
  if (POSIX) assert.equal(fs.statSync(path.join(home, 'key')).mode & 0o777, 0o600);
  assert.deepEqual(unwrapKey(env, PASS), parseKey(rawKey));

  const locked = skv(home, ['run', 'g', '--', ...printLen]);
  assert.equal(locked.status, 1);
  assert.match(locked.stderr, /the vault is locked: run `skv unlock`/);
  assert.equal(skv(home, ['ls']).status, 1);

  const withKey = skv(home, ['run', 'g', '--', ...printLen], { env: { SKV_KEY: rawKey } });
  ok(withKey);
  assert.equal(withKey.stdout, String(SECRET.length));

  // log, links, doctor and status work while locked
  ok(skv(home, ['log']));
  ok(skv(home, ['links']));
  const doc = JSON.parse(skv(home, ['doctor', '--json']).stdout);
  assert.equal(doc.ok, true, JSON.stringify(doc.results));
  assert.ok(doc.results.some((r) => r.check === 'key' && r.level === 'warn' && /locked/.test(r.message)));
  assert.ok(doc.results.some((r) => r.check === 'passphrase' && /^on/.test(r.message)));
  const st = JSON.parse(skv(home, ['status', '--json']).stdout);
  assert.equal(st.state, 'locked');
  assert.equal(st.source, 'locked');

  assert.equal(skv(home, ['passphrase', 'set'], { input: `${PASS}\n` }).status, 1, 'already set');
  assert.equal(skv(home, ['unlock'], { input: 'wrong passphrase\n' }).status, 1);
  assert.equal(fs.existsSync(path.join(home, 'session.json')), false);
});

test('passphrase change and remove; short passphrases are refused', () => {
  const { home, rawKey } = protectedHome();
  assert.equal(skv(home, ['passphrase', 'change'], { input: `wrong passphrase\nnew passphrase 2\n` }).status, 1);
  assert.equal(skv(home, ['passphrase', 'change'], { input: `${PASS}\nshort\n` }).status, 1);
  ok(skv(home, ['passphrase', 'change'], { input: `${PASS}\nnew passphrase 2\n` }));
  const env = JSON.parse(fs.readFileSync(path.join(home, 'key'), 'utf8'));
  assert.throws(() => unwrapKey(env, PASS), { code: 'bad-passphrase' });
  assert.deepEqual(unwrapKey(env, 'new passphrase 2'), parseKey(rawKey));
  assert.equal(skv(home, ['passphrase', 'remove'], { input: `${PASS}\n` }).status, 1);
  ok(skv(home, ['passphrase', 'remove'], { input: 'new passphrase 2\n' }));
  assert.equal(fs.readFileSync(path.join(home, 'key'), 'utf8').trim(), rawKey);
  ok(skv(home, ['run', 'g', '--', ...printLen]));
  assert.equal(JSON.parse(skv(home, ['status', '--json']).stdout).state, 'no passphrase');

  const other = initHome();
  assert.equal(skv(other, ['passphrase', 'set'], { input: 'short\n' }).status, 1);
  assert.doesNotMatch(fs.readFileSync(path.join(other, 'key'), 'utf8'), /^\{/);

  const actions = logEntries(home).map((e) => e.action);
  for (const a of ['passphrase-set', 'passphrase-change', 'passphrase-remove']) assert.ok(actions.includes(a), a);
  const log = fs.readFileSync(path.join(home, 'log.jsonl'), 'utf8');
  assert.doesNotMatch(log, new RegExp(`${SECRET}|${PASS}|new passphrase 2|${rawKey.replace(/[+/=]/g, '.')}`));
});

test('unlock -> run -> lock -> run fails with locked; the session cleans up after itself', async () => {
  const { home } = protectedHome();
  const s = unlock(home, ['--for', '1h']);
  if (POSIX) {
    assert.equal(fs.statSync(path.join(home, 'session.json')).mode & 0o777, 0o600);
    assert.equal(fs.statSync(s.socket).mode & 0o777, 0o600);
  }
  assert.ok(Date.parse(s.expiresAt) - Date.now() > 55 * 60e3);
  assert.doesNotMatch(fs.readFileSync(path.join(home, 'session.json'), 'utf8'), new RegExp(SECRET));

  const r = skv(home, ['run', 'g', '--', ...printLen]);
  ok(r);
  assert.equal(r.stdout, String(SECRET.length));
  const st = JSON.parse(skv(home, ['status', '--json']).stdout);
  assert.equal(st.state, 'unlocked');
  assert.equal(st.source, 'session');
  assert.equal(st.session.pid, s.pid);
  const doc = JSON.parse(skv(home, ['doctor', '--json']).stdout);
  assert.ok(doc.results.some((x) => x.check === 'decrypt' && x.level === 'ok'));
  assert.ok(doc.results.some((x) => x.check === 'session' && /unlocked until/.test(x.message)));

  ok(skv(home, ['lock']));
  assert.ok(await waitGone(s.pid), 'session process exits');
  assert.equal(fs.existsSync(path.join(home, 'session.json')), false);
  if (POSIX) assert.equal(fs.existsSync(s.socket), false);
  const after = skv(home, ['run', 'g', '--', ...printLen]);
  assert.equal(after.status, 1);
  assert.match(after.stderr, /locked/);
  assert.deepEqual(
    logEntries(home).filter((e) => ['unlock', 'lock'].includes(e.action)).map((e) => e.action),
    ['unlock', 'lock'],
  );
  assert.match(skv(home, ['lock']).stdout, /no unlock session/);
});

test('a session expires on its own (--for 2s)', async () => {
  const { home } = protectedHome();
  const s = unlock(home, ['--for', '2s']);
  ok(skv(home, ['run', 'g', '--', ...printLen]));
  await sleep(2500);
  assert.ok(await waitGone(s.pid), 'session process exits on expiry');
  assert.equal(fs.existsSync(path.join(home, 'session.json')), false);
  const r = skv(home, ['run', 'g', '--', ...printLen]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /locked/);
});

test('the session socket requires the token from session.json', async () => {
  const { home } = protectedHome();
  const s = unlock(home);
  try {
    for (const bad of [{ op: 'key' }, { token: 'nope', op: 'key' }, { token: s.token.slice(0, -1), op: 'key' }]) {
      const r = await sessionRequest(s.socket, bad);
      assert.equal(r.ok, false);
      assert.equal(r.key, undefined);
    }
    const good = await sessionRequest(s.socket, { token: s.token, op: 'status' });
    assert.equal(good.ok, true);
    assert.equal(good.key, undefined, 'status never returns the key');
    // A replaced session.json token (e.g. another user guessing) is refused too; the real one still works.
    fs.writeFileSync(path.join(home, 'session.json'), JSON.stringify({ ...s, token: 'forged' }));
    assert.equal(skv(home, ['run', 'g', '--', ...printLen]).status, 1);
    fs.writeFileSync(path.join(home, 'session.json'), JSON.stringify(s));
    ok(skv(home, ['run', 'g', '--', ...printLen]));
  } finally {
    ok(skv(home, ['lock']));
    await waitGone(s.pid);
  }
});

test('a SKV_HOME too long for a Unix socket uses a private folder in the temp dir', { skip: !POSIX }, async () => {
  const home = path.join(tmpDir(), 'x'.repeat(60), 'y'.repeat(30), 'skv');
  fs.mkdirSync(path.dirname(home), { recursive: true });
  ok(skv(home, ['init']));
  ok(skv(home, ['set', 'g', 'K'], { input: SECRET }));
  ok(skv(home, ['passphrase', 'set'], { input: `${PASS}\n` }));
  const s = unlock(home);
  assert.ok(!s.socket.startsWith(home), s.socket);
  assert.equal(fs.statSync(path.dirname(s.socket)).mode & 0o777, 0o700);
  ok(skv(home, ['run', 'g', '--', ...printLen]));
  ok(skv(home, ['lock']));
  await waitGone(s.pid);
  assert.equal(fs.existsSync(path.dirname(s.socket)), false);
});

test('agent read policy: get refused and logged, export to stdout refused, -o allowed, run ok', () => {
  const home = initHome();
  ok(skv(home, ['set', 'g', 'K'], { input: SECRET }));
  const agent = { env: { SKV_ACTOR: 'agent' } };

  const get = skv(home, ['get', 'g', 'K'], agent);
  assert.equal(get.status, 1);
  assert.match(get.stderr, /skv run <group> -- <cmd>/);
  assert.doesNotMatch(get.stdout + get.stderr, new RegExp(SECRET));

  const exp = skv(home, ['export', 'g'], agent);
  assert.equal(exp.status, 1);
  assert.equal(exp.stdout, '');
  const out = path.join(tmpDir(), 'app.env');
  ok(skv(home, ['export', 'g', '-o', out], agent));
  assert.equal(fs.readFileSync(out, 'utf8'), `K=${SECRET}\n`);

  const run = skv(home, ['run', 'g', '--', ...printLen], agent);
  ok(run);
  assert.equal(run.stdout, String(SECRET.length));

  const denied = logEntries(home).filter((e) => e.denied);
  assert.deepEqual(denied.map((e) => [e.action, e.actor, e.group]), [['get', 'agent', 'g'], ['export', 'agent', 'g']]);
  assert.equal(denied[0].key, 'K');
  assert.doesNotMatch(fs.readFileSync(path.join(home, 'log.jsonl'), 'utf8'), new RegExp(SECRET));
  assert.match(skv(home, ['log']).stdout, /DENIED/);

  // CLAUDECODE alone is detected as an agent too
  assert.equal(skv(home, ['get', 'g', 'K'], { env: { SKV_ACTOR: '', CLAUDECODE: '1' } }).status, 1);
});

test('agentRead allow lets agents read; only users can change it; users are never affected', () => {
  const home = initHome();
  ok(skv(home, ['set', 'g', 'K'], { input: SECRET }));
  const agent = { env: { SKV_ACTOR: 'agent' } };

  const user = skv(home, ['get', 'g', 'K']);
  ok(user);
  assert.equal(user.stdout, SECRET);
  ok(skv(home, ['export', 'g']));

  assert.deepEqual(JSON.parse(skv(home, ['config', '--json']).stdout), { 'agent-read': 'deny' });
  assert.match(skv(home, ['config']).stdout, /agent-read\s+deny/);
  const byAgent = skv(home, ['config', 'set', 'agent-read', 'allow'], agent);
  assert.equal(byAgent.status, 1);
  assert.match(byAgent.stderr, /only the user can allow agent reads, from their own terminal/);
  assert.equal(skv(home, ['config', 'set', 'agent-read', 'allow'], { env: { SKV_ACTOR: '', CLAUDECODE: '1' } }).status, 1);
  assert.equal(JSON.parse(skv(home, ['config', '--json']).stdout)['agent-read'], 'deny', 'unchanged');
  ok(skv(home, ['config', 'set', 'agent-read', 'deny'], agent)); // tightening is fine for agents
  const deniedCfg = logEntries(home).filter((e) => e.action === 'config' && e.denied);
  assert.deepEqual(deniedCfg.map((e) => [e.actor, e.setting, e.setTo]), [['agent', 'agent-read', 'allow'], ['agent', 'agent-read', 'allow']]);
  assert.equal(skv(home, ['config', 'set', 'agent-read', 'maybe']).status, 2);
  assert.equal(skv(home, ['config', 'set', 'nope', 'x']).status, 2);

  ok(skv(home, ['config', 'set', 'agent-read', 'allow']));
  assert.equal(JSON.parse(fs.readFileSync(path.join(home, 'config.json'), 'utf8')).settings.agentRead, 'allow');
  const g = skv(home, ['get', 'g', 'K'], agent);
  ok(g);
  assert.equal(g.stdout, SECRET);
  ok(skv(home, ['export', 'g'], agent));

  ok(skv(home, ['config', 'set', 'agent-read', 'deny']));
  assert.equal(skv(home, ['get', 'g', 'K'], agent).status, 1);
  ok(skv(home, ['get', 'g', 'K']));
  const cfg = logEntries(home).filter((e) => e.action === 'config' && !e.denied && e.actor === 'user');
  assert.deepEqual(cfg.map((e) => [e.setting, e.previous, e.setTo]), [['agent-read', 'deny', 'allow'], ['agent-read', 'allow', 'deny']]);
});
