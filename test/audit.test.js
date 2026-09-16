// Run with: npm test
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { findAnomalies } = require("../cli.js");

const CLI = path.join(__dirname, "..", "cli.js");
const SECRET = "sk-live-NEVER-IN-THE-LOG-1234567890";

function sandbox() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "tv-audit-"));
  fs.mkdirSync(path.join(home, ".config", "tokenvault"), { recursive: true });
  fs.writeFileSync(path.join(home, ".config", "tokenvault", "master.key"), "test-master-key\n");
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    TOKENVAULT_DIR: path.join(home, "vault"),
    TOKENVAULT_AUDIT_LOG: path.join(home, "state", "audit.log"),
    CLAUDE_CODE_SESSION_ID: "sess-abc123",
  };
  fs.mkdirSync(env.TOKENVAULT_DIR);
  const tv = (args, extra = {}) =>
    spawnSync(process.execPath, [CLI, ...args], { env: { ...env, ...extra }, cwd: home, encoding: "utf8" });
  return { home, env, tv, log: () => fs.readFileSync(env.TOKENVAULT_AUDIT_LOG, "utf8") };
}

test("tv get logs the entry name and caller, never the value", () => {
  const { home, env, tv, log } = sandbox();
  assert.strictEqual(tv(["add", "stripe", SECRET, "secret key"]).status, 0);
  assert.strictEqual(tv(["add", "stripe", "whsec-OTHER-SECRET", "webhook"]).status, 0);

  const got = tv(["get", "stripe", "secret key"]);
  assert.strictEqual(got.status, 0);
  assert.strictEqual(got.stdout.trim(), SECRET);
  assert.strictEqual(tv(["get", "stripe"]).status, 0);
  assert.strictEqual(tv(["dump"]).status, 0);

  const raw = log();
  assert.ok(!raw.includes(SECRET), "value written to audit log");
  assert.ok(!raw.includes("whsec-OTHER-SECRET"), "value written to audit log");

  const [one, all, dump] = raw.trim().split("\n").map((l) => JSON.parse(l));
  assert.deepStrictEqual(one.entries, ["stripe/secret key"]);
  assert.strictEqual(one.cmd, "get");
  assert.strictEqual(one.found, true);
  for (const k of ["ts", "pid", "ppid", "parents", "cwd", "claude_session"]) assert.ok(k in one, `missing ${k}`);
  assert.ok(!Number.isNaN(Date.parse(one.ts)));
  assert.strictEqual(typeof one.pid, "number");
  assert.strictEqual(one.ppid, process.pid);
  assert.ok(Array.isArray(one.parents) && one.parents.length > 0);
  assert.strictEqual(fs.realpathSync(one.cwd), fs.realpathSync(home));
  assert.strictEqual(one.claude_session, "sess-abc123");

  assert.deepStrictEqual(all.entries, ["stripe/secret key", "stripe/webhook"]);
  assert.strictEqual(dump.cmd, "dump");
  assert.strictEqual(dump.count, 2);
  assert.strictEqual(fs.statSync(env.TOKENVAULT_AUDIT_LOG).mode & 0o777, 0o600);
});

test("a missing entry is logged as found:false", () => {
  const { tv, log } = sandbox();
  tv(["add", "stripe", SECRET, "secret key"]);
  assert.strictEqual(tv(["get", "nope"]).status, 1);
  assert.strictEqual(tv(["get", "stripe", "nope"]).status, 1);
  const rs = log().trim().split("\n").map((l) => JSON.parse(l));
  assert.deepStrictEqual(rs.map((r) => [r.entries[0], r.found]), [["nope", false], ["stripe/nope", false]]);
});

test("a secret-shaped description is logged as a hash, not as written", () => {
  const { tv, log } = sandbox();
  const keyDesc = "-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAABG5vbmU";
  const tokenDesc = "ghp_abcdefghijklmnopqrstuvwxyz0123";
  tv(["add", "github", SECRET, keyDesc]);
  tv(["add", "github", "other", tokenDesc]);
  tv(["get", "github"]);
  tv(["get", "github", tokenDesc]);
  const raw = log();
  assert.ok(!raw.includes("OPENSSH") && !raw.includes("b3BlbnNzaC1rZXkt"), "key-shaped description written to audit log");
  assert.ok(!raw.includes(tokenDesc), "token-shaped description written to audit log");
  const [all, one] = raw.trim().split("\n").map((l) => JSON.parse(l));
  for (const e of [...all.entries, ...one.entries]) assert.match(e, /^github\/#[0-9a-f]{8}$/);
  assert.ok(all.entries.includes(one.entries[0]), "hash is stable across reads");
});

test("claude_session is null outside Claude Code", () => {
  const { tv, log } = sandbox();
  tv(["add", "a", SECRET]);
  tv(["get", "a"], { CLAUDE_CODE_SESSION_ID: "" });
  assert.strictEqual(JSON.parse(log().trim()).claude_session, null);
});

test("a broken audit log never breaks tv get or tv dump", () => {
  const { home, tv } = sandbox();
  tv(["add", "a", SECRET]);
  const blocker = path.join(home, "not-a-dir");
  fs.writeFileSync(blocker, "");
  const extra = { TOKENVAULT_AUDIT_LOG: path.join(blocker, "audit.log") };
  const got = tv(["get", "a"], extra);
  assert.strictEqual(got.status, 0);
  assert.strictEqual(got.stdout.trim(), SECRET);
  assert.strictEqual(got.stderr, "");
  assert.strictEqual(tv(["dump"], extra).status, 0);
});

// ── anomaly checker ──

const at = (sec) => new Date(Date.UTC(2026, 8, 16, 12, 0, 0) + sec * 1000).toISOString();
const get = (sec, name, extra = {}) => ({ ts: at(sec), cmd: "get", entries: [name], found: true, pid: 1, cwd: "/x", ...extra });

test("quiet reads are not anomalies", () => {
  const rs = [0, 30, 50, 70, 90, 110].map((s, i) => get(s, `p/${i}`));
  assert.deepStrictEqual(findAnomalies(rs), []);
  // the same entry many times is not a burst of distinct entries
  assert.deepStrictEqual(findAnomalies([...Array(20)].map((_, i) => get(i, "p/same"))), []);
});

test("more than 5 distinct entries inside a minute is a burst, reported once", () => {
  const rs = [...Array(12)].map((_, i) => get(i * 2, `p/${i}`));
  const f = findAnomalies(rs);
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].kind, "burst");
  assert.strictEqual(f[0].ts, at(10));
  assert.match(f[0].text, /6 distinct entries/);
  // exactly 5 is fine
  assert.deepStrictEqual(findAnomalies(rs.slice(0, 5)), []);
});

test("any dump is flagged", () => {
  const f = findAnomalies([{ ts: at(0), cmd: "dump", entries: [], count: 40, pid: 9, cwd: "/y", agent: "task-x" }]);
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].kind, "dump");
  assert.match(f[0].text, /40 entries.*task-x/);
});

test("repeated reads of missing entries are flagged as probing", () => {
  const rs = [0, 5, 10].map((s, i) => get(s, `guess/${i}`, { found: false }));
  const f = findAnomalies(rs);
  assert.deepStrictEqual(f.map((x) => x.kind), ["misses"]);
  assert.deepStrictEqual(findAnomalies(rs.slice(0, 2)), []);
});

test("since suppresses findings already reported", () => {
  const rs = [{ ts: at(0), cmd: "dump", count: 1 }, ...[...Array(6)].map((_, i) => get(i, `p/${i}`))];
  assert.strictEqual(findAnomalies(rs).length, 2);
  assert.deepStrictEqual(findAnomalies(rs, { since: at(5) }), []);
  assert.deepStrictEqual(findAnomalies([...rs, { ts: at(100), cmd: "dump", count: 1 }], { since: at(5) }).map((f) => f.kind), ["dump"]);
});

test("tv audit check --post sends findings to wire once and advances its cursor", () => {
  const { home, env, tv } = sandbox();
  const posts = path.join(home, "posts.txt");
  const fakeWire = path.join(home, "wire");
  fs.writeFileSync(fakeWire, `#!/bin/sh\necho "$WIRE_AGENT|$@" >> "${posts}"\n`, { mode: 0o755 });
  const extra = { TOKENVAULT_WIRE: fakeWire };
  tv(["add", "a", SECRET]);
  tv(["dump"]);

  const human = tv(["audit", "check"], extra);
  assert.strictEqual(human.status, 3);
  assert.ok(!fs.existsSync(posts), "posted without --post");

  assert.strictEqual(tv(["audit", "check", "--post"], extra).status, 0);
  const sent = fs.readFileSync(posts, "utf8");
  assert.match(sent, /^tokenvault-audit\|post tokenvault-audit tokenvault audit on .*1 anomaly/);
  assert.ok(!sent.includes(SECRET));

  assert.strictEqual(tv(["audit", "check", "--post"], extra).status, 0);
  assert.strictEqual(fs.readFileSync(posts, "utf8"), sent, "re-posted an old finding");
  assert.ok(fs.existsSync(env.TOKENVAULT_AUDIT_LOG + ".state.json"));
});

test("a failed wire post keeps the cursor so the next run retries", () => {
  const { home, env, tv } = sandbox();
  const fakeWire = path.join(home, "wire");
  fs.writeFileSync(fakeWire, "#!/bin/sh\nexit 1\n", { mode: 0o755 });
  tv(["add", "a", SECRET]);
  tv(["dump"]);
  const r = tv(["audit", "check", "--post"], { TOKENVAULT_WIRE: fakeWire });
  assert.strictEqual(r.status, 1);
  assert.ok(!fs.existsSync(env.TOKENVAULT_AUDIT_LOG + ".state.json"));
});
