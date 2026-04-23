#!/usr/bin/env node
// tokenvault - Encrypted CLI token store. Zero deps, git-synced.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");

// ── Paths ───────────────────────────────────────────────────────────

const KEY_DIR = path.join(os.homedir(), ".config", "tokenvault");
const KEY_FILE = path.join(KEY_DIR, "master.key");
const REPO_DIR = path.resolve(__dirname);
const ENC_FILE = path.join(REPO_DIR, "tokens.enc");

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
}

// ── Commands ────────────────────────────────────────────────────────

function cmdInit() {
  fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
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
  if (!data[project]) die(`No tokens for ${ce.yellow(project)}`);
  const entries = data[project];
  if (descFilter) {
    const match = entries.find((e) => (e.desc || "") === descFilter);
    if (!match) die(`No token ${ce.yellow(descFilter)} in ${ce.yellow(project)}`);
    console.log(match.token);
    return;
  }
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

${c.bold("Info")}
  ${c.cyan("tv key-path")}                      Print master key location

${c.dim("Aliases: ls=list, rm=remove")}
${c.dim("Encrypted with AES-256-CBC. Master key at ~/.config/tokenvault/master.key")}`;

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
    "key-path": cmdKeyPath,
  },
});

cli.run(process.argv.slice(2));
