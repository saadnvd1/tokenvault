#!/usr/bin/env node
// tokenvault - Encrypted CLI token store. Zero deps, git-synced.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFileSync } = require("child_process");

// ── Paths ───────────────────────────────────────────────────────────

const DATA_DIR = process.env.TOKENVAULT_DIR || path.join(os.homedir(), ".tokenvault");
const KEY_DIR = path.join(os.homedir(), ".config", "tokenvault");
const KEY_FILE = path.join(KEY_DIR, "master.key");
const ENC_FILE = path.join(DATA_DIR, "tokens.enc");

// ── Colors (extractable: mini-ansi) ─────────────────────────────────
//
// TTY-aware ANSI styling. No deps. Could be its own package.
//
//   const c = colors(stream)
//   c.green("text")
//   c.bold.cyan("text")

function colors(stream = process.stdout) {
  const enabled = stream.isTTY || false;
  const wrap = (code) => (text) =>
    enabled ? `\x1b[${code}m${text}\x1b[0m` : String(text);

  return {
    green: wrap("32"),
    red: wrap("31"),
    yellow: wrap("33"),
    cyan: wrap("36"),
    bold: Object.assign(wrap("1"), {
      cyan: wrap("1;36"),
      green: wrap("1;32"),
      yellow: wrap("1;33"),
    }),
    dim: wrap("2"),
  };
}

const c = colors(process.stdout);
const ce = colors(process.stderr);

// ── CLI Router (extractable: mini-cli) ──────────────────────────────
//
// Minimal command router with fuzzy suggestions. No deps.
//
//   const cli = router({ commands, help, name })
//   cli.run(process.argv.slice(2))

function router({ commands, help, name }) {
  function closest(input) {
    let best = null,
      bestScore = 0;
    for (const cmd of Object.keys(commands)) {
      let score = 0;
      for (let i = 0; i < Math.min(input.length, cmd.length); i++) {
        if (input[i] === cmd[i]) score++;
        else break;
      }
      // also check if input is substring
      if (cmd.includes(input)) score = Math.max(score, input.length);
      if (score > bestScore && score >= 2) {
        best = cmd;
        bestScore = score;
      }
    }
    return best;
  }

  return {
    run(args) {
      if (!args.length || ["-h", "--help", "help"].includes(args[0])) {
        console.log(help);
        process.exit(0);
      }
      const cmd = args[0];
      const handler = commands[cmd];
      if (!handler) {
        const match = closest(cmd);
        const hint = match
          ? ` Did you mean ${ce.yellow(match)}?`
          : "";
        die(
          `Unknown command: ${ce.yellow(cmd)}.${hint}\n       Run ${ce.yellow(`${name} help`)} for usage.`
        );
      }
      handler(args.slice(1));
    },
  };
}

// ── Helpers ──────────────────────────────────────────────────────────

function die(msg) {
  console.error(`${ce.bold("error:")} ${msg}`);
  process.exit(1);
}

function pluralize(n, word = "token") {
  return `${n} ${word}${n !== 1 ? "s" : ""}`;
}

function projectLabel(project, desc = "") {
  let label = c.bold.cyan(project);
  if (desc) label += ` ${c.dim(`(${desc})`)}`;
  return label;
}

function maskToken(token) {
  if (token.length > 12)
    return token.slice(0, 4) + c.dim("........") + token.slice(-4);
  return c.yellow("****");
}

function printTokenTable(entries, valueFn) {
  const descs = entries.map((e) => e.desc || "(no desc)");
  const maxW = Math.max(...descs.map((d) => d.length));
  for (let i = 0; i < entries.length; i++) {
    console.log(`  ${descs[i].padEnd(maxW)}  ${valueFn(entries[i])}`);
  }
}

// ── Crypto (openssl-compatible) ─────────────────────────────────────
//
// Matches: openssl enc -aes-256-cbc -salt -pbkdf2 -pass file:KEY
// Format:  "Salted__" (8) + salt (8) + ciphertext
// KDF:     PBKDF2-HMAC-SHA256, 10000 iterations

const MAGIC = Buffer.from("Salted__");
const PBKDF2_ITER = 10000;
const KEY_LEN = 32;
const IV_LEN = 16;

function ensureKey() {
  if (!fs.existsSync(KEY_FILE))
    die(`No master key. Run ${ce.yellow("tv init")} first.`);
}

function deriveKeyIv(password, salt) {
  const derived = crypto.pbkdf2Sync(
    password,
    salt,
    PBKDF2_ITER,
    KEY_LEN + IV_LEN,
    "sha256"
  );
  return {
    key: derived.subarray(0, KEY_LEN),
    iv: derived.subarray(KEY_LEN),
  };
}

function encrypt(plaintext) {
  const password = fs.readFileSync(KEY_FILE, "utf8").trim();
  const salt = crypto.randomBytes(8);
  const { key, iv } = deriveKeyIv(password, salt);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([MAGIC, salt, encrypted]);
}

function decrypt(ciphertext) {
  const password = fs.readFileSync(KEY_FILE, "utf8").trim();
  if (
    ciphertext.length < 16 ||
    ciphertext.subarray(0, 8).toString() !== "Salted__"
  )
    die("Decryption failed. Corrupted file.");
  const salt = ciphertext.subarray(8, 16);
  const data = ciphertext.subarray(16);
  const { key, iv } = deriveKeyIv(password, salt);
  try {
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  } catch {
    die("Decryption failed. Wrong key or corrupted file.");
  }
}

function load() {
  ensureKey();
  if (!fs.existsSync(ENC_FILE)) return {};
  const ciphertext = fs.readFileSync(ENC_FILE);
  const plaintext = decrypt(ciphertext);
  return JSON.parse(plaintext.toString());
}

function save(data) {
  ensureKey();
  const plaintext = Buffer.from(JSON.stringify(data, null, 2));
  fs.writeFileSync(ENC_FILE, encrypt(plaintext));
  autoCommit();
}



// ── Audit log ───────────────────────────────────────────────────────
//
// Every read of a secret (`tv get`, `tv dump`) appends one JSON line: when,
// which entry, and who asked. NEVER the value. The log lives outside DATA_DIR
// because DATA_DIR is a git repo that syncs to a remote. Logging is
// best-effort: a failure here must never stop `tv get` from printing.

const STATE_HOME = process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state");
const AUDIT_LOG = process.env.TOKENVAULT_AUDIT_LOG || path.join(STATE_HOME, "tokenvault", "audit.log");
const AUDIT_STATE = `${AUDIT_LOG}.state.json`;

// Executable names only, walking up from our parent: "zsh < claude < tmux".
// Full command lines are not logged — a parent's argv can hold another secret.
function processAncestry(startPid, depth = 4) {
  try {
    const table = new Map();
    const out = execFileSync("ps", ["-A", "-o", "pid=,ppid=,comm="], {
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 1000,
    }).toString();
    for (const line of out.split("\n")) {
      const m = line.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/);
      if (m) table.set(Number(m[1]), { ppid: Number(m[2]), comm: path.basename(m[3]) });
    }
    const chain = [];
    let pid = startPid;
    while (pid > 1 && chain.length < depth && table.has(pid)) {
      chain.push(table.get(pid).comm);
      pid = table.get(pid).ppid;
    }
    return chain;
  } catch {
    return [];
  }
}

function auditRecord(cmd, fields) {
  const env = process.env;
  return {
    ts: new Date().toISOString(),
    cmd,
    ...fields,
    pid: process.pid,
    ppid: process.ppid,
    parents: processAncestry(process.ppid),
    cwd: process.cwd(),
    claude_session: env.CLAUDE_CODE_SESSION_ID || env.CLAUDE_SESSION_ID || null,
    agent: env.WIRE_AGENT || null,
  };
}

function audit(cmd, fields) {
  try {
    fs.mkdirSync(path.dirname(AUDIT_LOG), { recursive: true, mode: 0o700 });
    fs.appendFileSync(AUDIT_LOG, JSON.stringify(auditRecord(cmd, fields)) + "\n", { mode: 0o600 });
  } catch {
    // best-effort: never break the read
  }
}

function entryName(project, desc) {
  return desc ? `${project}/${desc}` : project;
}

function readAudit(file = AUDIT_LOG) {
  let raw;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch {
    return [];
  }
  const records = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      records.push(JSON.parse(line));
    } catch {
      // a torn line from a concurrent append; skip it
    }
  }
  return records;
}

function who(r) {
  const bits = [];
  if (r.agent) bits.push(r.agent);
  if (r.claude_session) bits.push(`session ${r.claude_session.slice(0, 8)}`);
  bits.push(`pid ${r.pid}`);
  if (r.parents && r.parents.length) bits.push(r.parents.join("<"));
  bits.push(r.cwd);
  return bits.join(", ");
}

// Pure: records in, findings out. A finding is only reported when the record
// that triggers it is newer than `since`, so a cron run never repeats one.
//   - any dump
//   - more than `maxDistinct` distinct entries read inside `windowSec`
//   - `maxMisses` or more reads of entries that do not exist inside `windowSec`
function findAnomalies(records, { since = null, windowSec = 60, maxDistinct = 5, maxMisses = 3 } = {}) {
  const sinceMs = since ? Date.parse(since) : -Infinity;
  const rs = records
    .filter((r) => r && r.ts && !Number.isNaN(Date.parse(r.ts)))
    .map((r) => ({ ...r, t: Date.parse(r.ts) }))
    // anything older than one window before the cursor cannot trigger a new finding
    .filter((r) => r.t > sinceMs - windowSec * 1000)
    .sort((a, b) => a.t - b.t);
  const findings = [];
  const winMs = windowSec * 1000;

  for (const r of rs) {
    if (r.cmd === "dump" && r.t > sinceMs)
      findings.push({ kind: "dump", ts: r.ts, text: `tv dump (${r.count ?? "?"} entries) by ${who(r)}` });
  }

  const sweep = (kind, pick, over, describe) => {
    let quietUntil = -Infinity;
    for (let i = 0; i < rs.length; i++) {
      const r = rs[i];
      if (!pick(r) || r.t < quietUntil) continue;
      const inWindow = rs.filter((x) => pick(x) && x.t <= r.t && x.t > r.t - winMs);
      const names = new Set(inWindow.flatMap((x) => x.entries || []));
      if (!over(names, inWindow)) continue;
      quietUntil = r.t + winMs;
      if (r.t <= sinceMs) continue;
      findings.push({ kind, ts: r.ts, text: describe(names, inWindow, r) });
    }
  };

  sweep(
    "burst",
    (r) => r.cmd === "get" && r.found !== false,
    (names) => names.size > maxDistinct,
    (names, win, r) =>
      `${names.size} distinct entries read within ${windowSec}s (${[...names].slice(0, 12).join(", ")}) by ${[...new Set(win.map(who))].join(" | ")}`
  );
  sweep(
    "misses",
    (r) => r.cmd === "get" && r.found === false,
    (_names, win) => win.length >= maxMisses,
    (names, win) =>
      `${win.length} reads of missing entries within ${windowSec}s (${[...names].slice(0, 12).join(", ")}) by ${[...new Set(win.map(who))].join(" | ")}`
  );

  return findings.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
}

function wirePost(channel, text) {
  const wire = process.env.TOKENVAULT_WIRE || "wire";
  const env = { ...process.env, WIRE_AGENT: process.env.WIRE_AGENT || "tokenvault-audit" };
  const post = () =>
    execFileSync(wire, ["post", channel, text], { env, stdio: ["ignore", "pipe", "pipe"], timeout: 30000 });
  try {
    post();
  } catch {
    // the channel may not exist yet on a fresh store
    execFileSync(wire, ["new", channel], { env, stdio: ["ignore", "pipe", "pipe"], timeout: 30000 });
    post();
  }
}

// ── Git helpers ─────────────────────────────────────────────────────

function git(...args) {
  return execFileSync("git", args, { cwd: DATA_DIR, stdio: "pipe" })
    .toString()
    .trim();
}

function gitOk(...args) {
  try {
    git(...args);
    return true;
  } catch {
    return false;
  }
}

function isGitRepo() {
  return gitOk("rev-parse", "--git-dir");
}

function hasRemote() {
  try {
    const remotes = git("remote");
    return remotes.length > 0;
  } catch {
    return false;
  }
}

function autoCommit() {
  if (!isGitRepo()) return;
  try {
    git("add", "tokens.enc");
    git("commit", "-m", "update tokens");
  } catch {
    // nothing to commit
  }
}

// ── Commands ────────────────────────────────────────────────────────

function cmdInit() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
  // init git repo if not already one
  if (!isGitRepo()) {
    git("init");
    // gitignore everything except tokens.enc
    fs.writeFileSync(path.join(DATA_DIR, ".gitignore"), "*\n!tokens.enc\n!.gitignore\n");
    git("add", ".gitignore");
    git("commit", "-m", "init tokenvault");
    console.log(`${c.bold.green("\u2713")} Initialized vault: ${c.dim(DATA_DIR)}`);
  }
  if (fs.existsSync(KEY_FILE)) {
    console.log(`${c.yellow("!")} Master key already exists: ${c.dim(KEY_FILE)}`);
    return;
  }
  const key = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(KEY_FILE, key, { mode: 0o600 });
  console.log(`${c.bold.green("\u2713")} Master key generated: ${c.dim(KEY_FILE)}`);
  console.log(`  ${c.dim("Copy this file to other machines at the same path.")}`);
}

function cmdAdd(args) {
  if (args.length < 2)
    die(`Usage: tv add ${ce.yellow("<project> <token>")} [description]`);
  const [project, token, ...rest] = args;
  const desc = rest.join(" ");
  const data = load();
  if (!data[project]) data[project] = [];
  const existing = data[project].find((e) => (e.desc || "") === desc);
  if (existing) {
    existing.token = token;
    save(data);
    console.log(`${c.bold.yellow("~")} Updated ${projectLabel(project, desc)}`);
  } else {
    data[project].push({ token, desc });
    save(data);
    console.log(`${c.bold.green("+")} Added ${projectLabel(project, desc)}`);
  }
}

function cmdGet(args) {
  if (!args.length)
    die(`Usage: tv get ${ce.yellow("<project>")} [description]`);
  const [project, ...rest] = args;
  const descFilter = rest.length ? rest.join(" ") : null;
  const data = load();
  if (!data[project]) {
    audit("get", { entries: [entryName(project, descFilter)], found: false });
    die(`No tokens for ${ce.yellow(project)}`);
  }
  const entries = data[project];
  if (descFilter) {
    const match = entries.find((e) => (e.desc || "") === descFilter);
    audit("get", { entries: [entryName(project, descFilter)], found: !!match });
    if (!match) die(`No token ${ce.yellow(descFilter)} in ${ce.yellow(project)}`);
    console.log(match.token);
    return;
  }
  audit("get", { entries: entries.map((e) => entryName(project, e.desc)), found: true });
  if (entries.length === 1) {
    console.log(entries[0].token);
  } else {
    console.log(`${c.bold.cyan(project)} ${c.dim("\u2014")} ${pluralize(entries.length)}`);
    console.log();
    printTokenTable(entries, (e) => c.green(e.token));
  }
}

function cmdList(args) {
  const data = load();
  if (!Object.keys(data).length) {
    console.log(c.dim("No tokens stored."));
    return;
  }
  if (args.length) {
    const project = args[0];
    if (!data[project]) die(`No tokens for ${ce.yellow(project)}`);
    const entries = data[project];
    console.log(`${c.bold.cyan(project)} ${c.dim("\u2014")} ${pluralize(entries.length)}`);
    console.log();
    printTokenTable(entries, (e) => c.yellow(maskToken(e.token)));
    return;
  }
  const projects = Object.keys(data).sort();
  const nTok = Object.values(data).reduce((s, v) => s + v.length, 0);
  console.log(
    `${c.bold("TokenVault")} ${c.dim("\u2014")} ${c.cyan(String(projects.length))} project${projects.length !== 1 ? "s" : ""}, ${c.cyan(String(nTok))} token${nTok !== 1 ? "s" : ""}`
  );
  console.log();
  for (const project of projects) {
    const entries = data[project];
    const descs = entries.filter((e) => e.desc).map((e) => e.desc);
    const descStr = descs.length ? `  ${c.dim(descs.join(", "))}` : "";
    console.log(`  ${c.bold.cyan(project)} ${c.dim(`(${entries.length})`)}${descStr}`);
  }
}

function cmdRemove(args) {
  if (!args.length)
    die(`Usage: tv remove ${ce.yellow("<project>")} [description]`);
  const [project, ...rest] = args;
  const descFilter = rest.length ? rest.join(" ") : null;
  const data = load();
  if (!data[project]) die(`No tokens for ${ce.yellow(project)}`);
  if (descFilter) {
    const before = data[project].length;
    data[project] = data[project].filter((e) => (e.desc || "") !== descFilter);
    if (data[project].length === before)
      die(`No token ${ce.yellow(descFilter)} in ${ce.yellow(project)}`);
    if (!data[project].length) delete data[project];
    save(data);
    console.log(`${c.red("\u2212")} Removed ${projectLabel(project, descFilter)}`);
  } else {
    const count = data[project].length;
    delete data[project];
    save(data);
    console.log(`${c.red("\u2212")} Removed ${projectLabel(project, pluralize(count))}`);
  }
}

function cmdDump() {
  const data = load();
  audit("dump", {
    entries: [],
    count: Object.values(data).reduce((n, list) => n + list.length, 0),
  });
  if (!Object.keys(data).length) {
    console.log(c.dim("No tokens stored."));
    return;
  }
  const raw = JSON.stringify(data, null, 2);
  if (!process.stdout.isTTY) {
    console.log(raw);
    return;
  }
  for (const line of raw.split("\n")) {
    const stripped = line.trimStart();
    const indent = line.slice(0, line.length - stripped.length);
    if (stripped.startsWith('"') && stripped.includes('": ')) {
      const idx = stripped.indexOf('": ');
      console.log(`${indent}${c.cyan(stripped.slice(0, idx + 1))}: ${c.green(stripped.slice(idx + 3))}`);
    } else if (stripped.startsWith('"')) {
      console.log(`${indent}${c.green(stripped)}`);
    } else if ("{[]}".includes(stripped.replace(/,$/,""))) {
      console.log(`${indent}${c.dim(stripped)}`);
    } else {
      console.log(line);
    }
  }
}

function cmdRemote(args) {
  if (!isGitRepo()) die(`Not a git repo. Run ${ce.yellow("tv init")} first.`);
  if (!args.length) {
    if (!hasRemote()) {
      console.log(c.dim("No remote set."));
      console.log(`  ${c.dim("Run:")} ${c.cyan("tv remote <url>")}`);
    } else {
      console.log(git("remote", "-v"));
    }
    return;
  }
  const url = args[0];
  if (hasRemote()) {
    git("remote", "set-url", "origin", url);
  } else {
    git("remote", "add", "origin", url);
  }
  console.log(`${c.bold.green("\u2713")} Remote set: ${c.dim(url)}`);
}

function cmdPush() {
  if (!isGitRepo()) die(`Not a git repo. Run ${ce.yellow("tv init")} first.`);
  if (!hasRemote()) die(`No remote set. Run ${ce.yellow("tv remote <url>")} first.`);
  try {
    // set upstream on first push
    git("push", "-u", "origin", "HEAD");
    console.log(`${c.bold.green("\u2713")} Pushed tokens`);
  } catch (e) {
    die(`Push failed: ${e.stderr?.toString().trim() || e.message}`);
  }
}

function cmdPull() {
  if (!isGitRepo()) die(`Not a git repo. Run ${ce.yellow("tv init")} first.`);
  if (!hasRemote()) die(`No remote set. Run ${ce.yellow("tv remote <url>")} first.`);
  try {
    git("pull", "--rebase", "origin", "HEAD");
    console.log(`${c.bold.green("\u2713")} Pulled tokens`);
  } catch (e) {
    die(`Pull failed: ${e.stderr?.toString().trim() || e.message}`);
  }
}

function cmdAudit(args) {
  const flag = (name, dflt) => {
    const i = args.indexOf(name);
    return i === -1 ? dflt : args[i + 1];
  };
  if (args[0] !== "check") {
    const n = Number(flag("-n", 20));
    for (const r of readAudit().slice(-n))
      console.log(`${c.dim(r.ts)} ${c.cyan(r.cmd)} ${r.cmd === "dump" ? `(${r.count})` : (r.entries || []).join(", ")}${r.found === false ? c.yellow(" (missing)") : ""} ${c.dim(who(r))}`);
    return;
  }

  const post = args.includes("--post");
  const channel = flag("--channel", process.env.TOKENVAULT_AUDIT_CHANNEL || "tokenvault-audit");
  let state = {};
  if (post) {
    try {
      state = JSON.parse(fs.readFileSync(AUDIT_STATE, "utf8"));
    } catch {}
  }
  const records = readAudit();
  const findings = findAnomalies(records, {
    since: post ? state.lastTs || null : null,
    windowSec: Number(flag("--window", 60)),
    maxDistinct: Number(flag("--max", 5)),
    maxMisses: Number(flag("--max-misses", 3)),
  });
  const lastTs = records.reduce((m, r) => (r.ts && (!m || r.ts > m) ? r.ts : m), state.lastTs || null);

  for (const f of findings) console.log(`${f.ts} ${f.kind}: ${f.text}`);
  if (!findings.length) console.log(c.dim("No anomalies."));

  if (post) {
    if (findings.length) {
      const text = [`tokenvault audit on ${os.hostname()}: ${findings.length} anomal${findings.length === 1 ? "y" : "ies"}`]
        .concat(findings.slice(0, 20).map((f) => `- ${f.ts} ${f.kind}: ${f.text}`))
        .join("\n");
      try {
        wirePost(channel, text);
      } catch (err) {
        // leave the cursor where it was so the next run tries again
        die(`wire post to ${channel} failed: ${err.message}`);
      }
    }
    try {
      fs.mkdirSync(path.dirname(AUDIT_STATE), { recursive: true, mode: 0o700 });
      fs.writeFileSync(AUDIT_STATE, JSON.stringify({ lastTs }), { mode: 0o600 });
    } catch (err) {
      die(`could not save ${AUDIT_STATE}: ${err.message}`);
    }
  }
  // exit 3 flags findings for a human run; a --post run that delivered them succeeded
  process.exitCode = findings.length && !post ? 3 : 0;
}

function cmdKeyPath() {
  console.log(KEY_FILE);
}

// ── Help ────────────────────────────────────────────────────────────

const HELP = `${c.bold("TokenVault")} ${c.dim("\u2014 encrypted CLI token store")}

${c.bold("Setup")}
  ${c.cyan("tv init")}                          Generate master key (once per machine)

${c.bold("Store")}
  ${c.cyan("tv add")} ${c.dim("<project> <token>")} [desc]   Add or update a token
  ${c.cyan("tv remove")} ${c.dim("<project>")} [desc]        Remove token(s)

${c.bold("Retrieve")}
  ${c.cyan("tv get")} ${c.dim("<project>")} [desc]           Print token value (pipe-safe)
  ${c.cyan("tv list")}                          All projects overview
  ${c.cyan("tv list")} ${c.dim("<project>")}                 Tokens for a project (masked)
  ${c.cyan("tv dump")}                          Print all decrypted JSON

${c.bold("Sync")}
  ${c.cyan("tv remote")} ${c.dim("<url>")}                  Set git remote for syncing
  ${c.cyan("tv push")}                          Push tokens to remote
  ${c.cyan("tv pull")}                          Pull tokens from remote

${c.bold("Info")}
  ${c.cyan("tv key-path")}                      Print master key location

${c.bold("Audit")}
  ${c.cyan("tv audit")} [-n 20]                   Recent gets/dumps (names, never values)
  ${c.cyan("tv audit check")} [--post]            Flag dumps, bursts, probing; --post sends to wire

${c.dim("Aliases: ls=list, rm=remove")}
${c.dim("Data: ~/.tokenvault/ | Key: ~/.config/tokenvault/master.key | Audit: ~/.local/state/tokenvault/audit.log")}`;

// ── Main ────────────────────────────────────────────────────────────

const cli = router({
  name: "tv",
  help: HELP,
  commands: {
    init: cmdInit,
    add: cmdAdd,
    get: cmdGet,
    list: cmdList,
    ls: cmdList,
    remove: cmdRemove,
    rm: cmdRemove,
    dump: cmdDump,
    remote: cmdRemote,
    push: cmdPush,
    pull: cmdPull,
    "key-path": cmdKeyPath,
    audit: cmdAudit,
  },
});

if (require.main === module) cli.run(process.argv.slice(2));

module.exports = { findAnomalies, auditRecord, readAudit };
