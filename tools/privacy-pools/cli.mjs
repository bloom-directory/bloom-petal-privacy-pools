#!/usr/bin/env node

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import {
  link,
  mkdir,
  open,
  readFile,
  rename,
  stat,
  unlink,
} from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import {
  PrivacyPoolSDK,
  calculateContext,
  generateMerkleProof,
  getCommitment,
} from "@0xbow/privacy-pools-core-sdk";
import { poseidon } from "maci-crypto/build/ts/hashing.js";
import {
  createPublicClient,
  decodeAbiParameters,
  encodeFunctionData,
  http,
  keccak256,
  toHex,
} from "viem";
import { mainnet } from "viem/chains";

const POOL = "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb";
const ENTRYPOINT = "0x6818809eefce719e480a7526d76bd3e561526b46";
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DEFAULT_RPC = "https://ethereum-rpc.publicnode.com";
const ASP_LEAVES = "https://api.0xbow.io/1/public/mt-leaves";
const NATIVE_ASSET = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
const ARTIFACT_HASHES = Object.freeze({
  "withdraw.wasm": "36cda22791def3d520a55c0fc808369cd5849532a75fab65686e666ed3d55c10",
  "withdraw.vkey": "666bd0983b20c1611543b04f7712e067fbe8cad69f07ada8a310837ff398d21e",
  "withdraw.zkey": "2a893b42174c813566e5c40c715a8b90cd49fc4ecf384e3a6024158c3d6de677",
});

const poolAbi = [
  { type: "function", name: "SCOPE", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "nullifierHashes", stateMutability: "view", inputs: [{ type: "uint256" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "currentRoot", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "currentTreeDepth", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  {
    type: "function",
    name: "withdraw",
    stateMutability: "nonpayable",
    inputs: [
      { type: "tuple", components: [{ name: "processooor", type: "address" }, { name: "data", type: "bytes" }] },
      {
        type: "tuple",
        components: [
          { name: "pA", type: "uint256[2]" },
          { name: "pB", type: "uint256[2][2]" },
          { name: "pC", type: "uint256[2]" },
          { name: "pubSignals", type: "uint256[8]" },
        ],
      },
    ],
    outputs: [],
  },
];
const entrypointAbi = [
  { type: "function", name: "latestRoot", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "scopeToPool", stateMutability: "view", inputs: [{ type: "uint256" }], outputs: [{ type: "address" }] },
  {
    type: "function",
    name: "relay",
    stateMutability: "nonpayable",
    inputs: [
      { type: "tuple", components: [{ name: "processooor", type: "address" }, { name: "data", type: "bytes" }] },
      {
        type: "tuple",
        components: [
          { name: "pA", type: "uint256[2]" },
          { name: "pB", type: "uint256[2][2]" },
          { name: "pC", type: "uint256[2]" },
          { name: "pubSignals", type: "uint256[8]" },
        ],
      },
      { name: "_scope", type: "uint256" },
    ],
    outputs: [],
  },
];
const WITHDRAWN_TOPIC = keccak256(toHex("Withdrawn(address,uint256,uint256,uint256)"));
const WITHDRAWAL_RELAYED_TOPIC = keccak256(toHex("WithdrawalRelayed(address,address,address,uint256,uint256)"));
const QUOTE_SAFETY_MS = 15_000;
const AMBIGUOUS_RETRY_DELAY_MS = 5 * 60 * 1000;

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function stringify(value) {
  return JSON.stringify(value, (_, item) => typeof item === "bigint" ? item.toString() : item, 2);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    assert(key?.startsWith("--") && rest[index + 1] !== undefined, `invalid argument: ${key ?? "<missing>"}`);
    options[key.slice(2)] = rest[index + 1];
  }
  return { command, options };
}

function required(options, key) {
  const value = options[key];
  assert(value, `missing --${key}`);
  return value;
}

function bloomHome(options) {
  return resolve(options.home ?? process.env.BLOOM_HOME ?? `${homedir()}/.bloom`);
}

async function activeDataRoot(home) {
  const owner = JSON.parse(await readFile(`${home}/petals/store/owners/privacy-pools.json`, "utf8"));
  assert(/^[0-9a-f]{64}$/.test(owner.hash), "invalid active privacy-pools package hash");
  return `${home}/petals/data/${owner.hash}`;
}

function safeSegment(value, label) {
  assert(/^[A-Za-z0-9._-]{1,128}$/.test(value) && value !== "." && value !== "..", `unsafe ${label}`);
  return value;
}

export async function atomicWrite(path, bytes, { exclusive = false, mode = 0o600 } = {}) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
  let file;
  try {
    file = await open(temporary, "wx", mode);
    await file.writeFile(bytes);
    await file.sync();
    await file.chmod(mode);
  } finally {
    await file?.close();
  }
  try {
    if (exclusive) {
      // link() atomically fails with EEXIST if the destination already
      // exists. Unlike the previous access()-then-rename() sequence, there
      // is no window between the check and the act for a second concurrent
      // writer to slip in: the filesystem itself makes EEXIST authoritative,
      // and rename() (used below for the non-exclusive case) would have
      // silently replaced an existing destination instead of failing.
      try {
        await link(temporary, path);
      } catch (error) {
        if (error?.code === "EEXIST") fail(`refusing to overwrite ${path}`);
        throw error;
      }
    } else {
      await rename(temporary, path);
    }
  } finally {
    if (exclusive) {
      // link() leaves the temp file in place on both success and failure
      // (it doesn't consume it the way rename() does); always clean it up.
      await unlink(temporary).catch((error) => {
        if (error?.code !== "ENOENT") throw error;
      });
    }
  }
  const directory = await open(dirname(path), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

async function readJsonIfExists(path) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

export async function writeIdenticalOrCreate(path, value, options = {}) {
  const existing = await readJsonIfExists(path);
  if (existing !== null) {
    assert(JSON.stringify(existing) === JSON.stringify(value), `refusing to replace different durable state at ${path}`);
    return;
  }
  await atomicWrite(path, Buffer.from(`${JSON.stringify(value)}\n`), { ...options, exclusive: true });
}

async function passphrase(path) {
  const metadata = await stat(path);
  assert((metadata.mode & 0o077) === 0, "passphrase file must not be accessible by group or others");
  const value = (await readFile(path, "utf8")).replace(/[\r\n]+$/, "");
  assert(value.length >= 12, "passphrase must contain at least 12 characters");
  return value;
}

const ENVELOPE_SCHEMA_V1 = "bloom.privacy-pools.encrypted-note.v1";
const ENVELOPE_SCHEMA_V2 = "bloom.privacy-pools.encrypted-note.v2";
const ENVELOPE_STRUCTURAL_FIELDS = new Set([
  "schema", "cipher", "kdf", "iv", "tag", "ciphertext", "plaintext_sha256",
]);

// v2 envelopes bind their own routing metadata (kind/wallet/id/parent_id) as
// AES-GCM Additional Authenticated Data. Those fields are stored as plaintext
// JSON alongside the ciphertext (so backups stay inspectable without the
// password), but restore uses them to decide *where on disk to write* — so
// without AAD, anyone with write access to a backup file (no password
// needed) could edit `wallet`/`id`/`kind` and have decryption succeed
// against the unmodified ciphertext, retargeting a restore. Binding them as
// AAD makes any such edit fail GCM authentication before those fields are
// ever trusted.
function envelopeAad(metadata) {
  const keys = Object.keys(metadata).sort();
  return Buffer.from(JSON.stringify(Object.fromEntries(keys.map((key) => [key, metadata[key]]))));
}

function envelopeMetadata(envelope) {
  return Object.fromEntries(
    Object.entries(envelope).filter(([key]) => !ENVELOPE_STRUCTURAL_FIELDS.has(key)),
  );
}

export function encryptEnvelope(plaintext, password, metadata) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(password, salt, 32, { N: 1 << 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(envelopeAad(metadata));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    schema: ENVELOPE_SCHEMA_V2,
    cipher: "aes-256-gcm",
    kdf: { name: "scrypt", N: 131072, r: 8, p: 1, salt: salt.toString("base64") },
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    plaintext_sha256: createHash("sha256").update(plaintext).digest("hex"),
    ...metadata,
  };
}

export function decryptEnvelope(envelope, password) {
  assert(
    envelope.schema === ENVELOPE_SCHEMA_V1 || envelope.schema === ENVELOPE_SCHEMA_V2,
    "unsupported backup schema",
  );
  const salt = Buffer.from(envelope.kdf.salt, "base64");
  const key = scryptSync(password, salt, 32, {
    N: envelope.kdf.N,
    r: envelope.kdf.r,
    p: envelope.kdf.p,
    maxmem: 256 * 1024 * 1024,
  });
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64"));
  if (envelope.schema === ENVELOPE_SCHEMA_V2) {
    decipher.setAAD(envelopeAad(envelopeMetadata(envelope)));
  }
  // v1 envelopes predate AAD binding. They cannot be retroactively
  // authenticated without the password (which is required to re-encrypt,
  // not merely to read), so existing v0.1.3 backups keep decrypting exactly
  // as before — their routing metadata remains unauthenticated. All new
  // backups are v2.
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64")),
    decipher.final(),
  ]);
  const digest = Buffer.from(createHash("sha256").update(plaintext).digest("hex"));
  const expected = Buffer.from(envelope.plaintext_sha256);
  assert(digest.length === expected.length && timingSafeEqual(digest, expected), "backup plaintext hash mismatch");
  return plaintext;
}

export async function verifiedBackup(value, output, password, metadata) {
  const plaintext = Buffer.from(`${JSON.stringify(value)}\n`);
  const existing = await readJsonIfExists(output);
  if (existing !== null) {
    for (const [key, expected] of Object.entries(metadata)) {
      assert(existing[key] === expected, `existing backup has different ${key}`);
    }
    const recovered = decryptEnvelope(existing, password);
    assert(
      plaintext.length === recovered.length && timingSafeEqual(plaintext, recovered),
      "existing backup contains different replacement material",
    );
    return existing.plaintext_sha256;
  }
  const envelope = encryptEnvelope(plaintext, password, metadata);
  const encoded = Buffer.from(`${stringify(envelope)}\n`);
  await atomicWrite(output, encoded, { exclusive: true });
  const reread = JSON.parse(await readFile(output, "utf8"));
  const recovered = decryptEnvelope(reread, password);
  assert(timingSafeEqual(plaintext, recovered), "backup verification failed");
  return envelope.plaintext_sha256;
}

function publicStatus(note) {
  const { nullifier: _nullifier, secret: _secret, ...status } = note;
  return status;
}

async function backupCommand(options) {
  const wallet = safeSegment(required(options, "wallet"), "wallet");
  const id = safeSegment(required(options, "id"), "id");
  const output = resolve(required(options, "out"));
  const password = await passphrase(resolve(required(options, "passphrase-file")));
  const root = await activeDataRoot(bloomHome(options));
  const notePath = `${root}/secrets/privacy-pools/notes/${wallet}/${id}`;
  const statePath = `${root}/state/privacy-pools/deposits/${wallet}/${id}`;
  const note = JSON.parse(await readFile(notePath, "utf8"));
  const digest = await verifiedBackup(note, output, password, { kind: "deposit", wallet, id });
  note.backup_verified = true;
  await atomicWrite(notePath, Buffer.from(`${JSON.stringify(note)}\n`));
  await atomicWrite(statePath, Buffer.from(`${JSON.stringify(publicStatus(note))}\n`));
  console.log(stringify({ backupVerified: true, wallet, id, output, plaintextSha256: digest }));
}

function validateNoteSecrets(note) {
  const nullifier = BigInt(note.nullifier);
  const secret = BigInt(note.secret);
  const precommitment = BigInt(poseidon([nullifier, secret]));
  assert(precommitment === BigInt(note.precommitment), "note secrets do not reproduce precommitment");
}

export async function restoreCommand(options) {
  const input = resolve(required(options, "in"));
  const password = await passphrase(resolve(required(options, "passphrase-file")));
  const envelope = JSON.parse(await readFile(input, "utf8"));
  const plaintext = decryptEnvelope(envelope, password);
  const value = JSON.parse(plaintext.toString("utf8"));
  if (envelope.schema === ENVELOPE_SCHEMA_V1) {
    // v1 envelopes predate AAD binding: their kind/wallet/id fields are
    // plaintext, unauthenticated, and restoreCommand uses exactly those
    // fields to decide where on disk to write. Decryption alone (which
    // still works, for backward compatibility with existing v0.1.3-era
    // backups) proves the password is correct; it proves nothing about
    // whether those routing fields were tampered with after encryption.
    // Require the operator to independently assert, out of band, the
    // wallet/id/kind they actually intend to restore to -- restore then
    // fails closed unless that matches what the envelope claims, rather
    // than silently trusting the file. kind matters as much as wallet/id:
    // it alone selects the destination directory (notes/ vs replacements/)
    // and which validation runs (validateNoteSecrets only applies to
    // "deposit"), so flipping it unauthenticated could route a restore
    // into the wrong secret store or skip a check meant to apply to it.
    const expectedWallet = safeSegment(required(options, "trust-legacy-wallet"), "trust-legacy-wallet");
    const expectedId = safeSegment(required(options, "trust-legacy-id"), "trust-legacy-id");
    const expectedKind = required(options, "trust-legacy-kind");
    assert(
      envelope.wallet === expectedWallet && envelope.id === expectedId && envelope.kind === expectedKind,
      "v1 backup's unauthenticated wallet/id/kind do not match --trust-legacy-wallet/--trust-legacy-id/--trust-legacy-kind; " +
        "refusing to restore without an explicit, matching operator assertion",
    );
  }
  const root = await activeDataRoot(bloomHome(options));
  if (envelope.kind === "deposit") {
    const wallet = safeSegment(envelope.wallet, "wallet");
    const id = safeSegment(envelope.id, "id");
    validateNoteSecrets(value);
    value.backup_verified = true;
    const notePath = `${root}/secrets/privacy-pools/notes/${wallet}/${id}`;
    const statePath = `${root}/state/privacy-pools/deposits/${wallet}/${id}`;
    try {
      const existing = JSON.parse(await readFile(notePath, "utf8"));
      assert(existing.nullifier === value.nullifier && existing.secret === value.secret, "refusing to replace a different existing note");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await atomicWrite(notePath, Buffer.from(`${JSON.stringify(value)}\n`));
    await atomicWrite(statePath, Buffer.from(`${JSON.stringify(publicStatus(value))}\n`));
  } else if (envelope.kind === "replacement") {
    const wallet = safeSegment(envelope.wallet, "wallet");
    const id = safeSegment(envelope.id, "replacement id");
    value.backup_verified = true;
    const replacementPath = `${root}/secrets/privacy-pools/replacements/${wallet}/${id}`;
    try {
      const existing = JSON.parse(await readFile(replacementPath, "utf8"));
      assert(existing.nullifier === value.nullifier && existing.secret === value.secret, "refusing to replace a different existing replacement note");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await atomicWrite(replacementPath, Buffer.from(`${JSON.stringify(value)}\n`));
  } else {
    fail("backup has unknown note kind");
  }
  console.log(stringify({ restored: true, kind: envelope.kind, wallet: envelope.wallet, id: envelope.id }));
}

function fieldElement() {
  let value = 0n;
  while (value === 0n) value = BigInt(`0x${randomBytes(32).toString("hex")}`) % FIELD;
  return value;
}

function treeDepth(length) {
  assert(Number.isSafeInteger(length) && length > 0, "tree must contain leaves");
  return BigInt(Math.ceil(Math.log2(length)));
}

function asHex(value) {
  return `0x${BigInt(value).toString(16).padStart(64, "0")}`;
}

function progress(phase, details = {}) {
  console.error(stringify({
    petal: "privacy-pools",
    command: "prepare",
    phase,
    at: new Date().toISOString(),
    ...details,
  }));
}

function privateProgress(phase, details = {}) {
  const terminal = phase === "complete";
  console.error(stringify({
    petal: "privacy-pools",
    command: "relay-private",
    status: terminal ? "complete" : "working",
  }));
}

function formatProof(withdrawalProof) {
  const { proof, publicSignals } = withdrawalProof;
  return {
    pA: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
    pB: [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ],
    pC: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
    pubSignals: publicSignals.map(BigInt),
  };
}

export function validateRelayQuote(quote, { recipient, amount, maxFeeBPS, now = Date.now() }) {
  const commitment = quote?.feeCommitment;
  assert(commitment?.withdrawalData && commitment?.signedRelayerCommitment, "relayer quote omitted its signed fee commitment");
  assert(Number.isSafeInteger(Number(commitment.expiration)) && Number(commitment.expiration) > now, "relayer quote is already expired");
  assert(commitment.asset?.toLowerCase() === NATIVE_ASSET.toLowerCase(), "relayer fee commitment names another asset");
  assert(BigInt(commitment.amount) === amount, "relayer fee commitment amount mismatch");
  assert(commitment.extraGas === false, "unexpected extra-gas quote");
  const [encodedRecipient, feeRecipient, encodedFeeBPS] = decodeAbiParameters(
    [{ type: "address" }, { type: "address" }, { type: "uint256" }],
    commitment.withdrawalData,
  );
  assert(encodedRecipient.toLowerCase() === recipient.toLowerCase(), "signed withdrawal data contains another recipient");
  assert(!/^0x0{40}$/i.test(feeRecipient), "signed withdrawal data has a zero fee recipient");
  assert(encodedFeeBPS === BigInt(quote.feeBPS), "quoted fee does not match signed withdrawal data");
  assert(encodedFeeBPS <= maxFeeBPS, "relayer fee exceeds max-fee-bps");
  return { feeBPS: encodedFeeBPS, feeRecipient, withdrawalData: commitment.withdrawalData };
}

export function redactPrivateReplacementNote(note) {
  const { nullifier: _nullifier, secret: _secret, tx, ...publicNote } = note;
  const { tx_hash: _txHash, ...publicTx } = tx ?? {};
  return { ...publicNote, tx: publicTx };
}

class LocalWithdrawCircuits {
  constructor(directory) {
    this.directory = directory;
    this.cache = new Map();
  }
  async artifact(name) {
    if (this.cache.has(name)) return this.cache.get(name);
    const data = await readFile(`${this.directory}/${name}`);
    const digest = createHash("sha256").update(data).digest("hex");
    assert(digest === ARTIFACT_HASHES[name], `artifact integrity mismatch: ${name}`);
    const artifact = new Uint8Array(data);
    this.cache.set(name, artifact);
    return artifact;
  }
  async preload() { await Promise.all(Object.keys(ARTIFACT_HASHES).map((name) => this.artifact(name))); }
  async getWasm(name) { assert(name === "withdraw", `unexpected circuit ${name}`); return this.artifact("withdraw.wasm"); }
  async getProvingKey(name) { assert(name === "withdraw", `unexpected circuit ${name}`); return this.artifact("withdraw.zkey"); }
  async getVerificationKey(name) { assert(name === "withdraw", `unexpected circuit ${name}`); return this.artifact("withdraw.vkey"); }
}

async function verifyArtifactsCommand(options) {
  const directory = resolve(required(options, "artifacts"));
  const circuits = new LocalWithdrawCircuits(directory);
  for (const name of Object.keys(ARTIFACT_HASHES)) {
    await circuits.artifact(name);
  }
  console.log(stringify({
    artifactsVerified: true,
    directory,
    sha256: ARTIFACT_HASHES,
    sdkVersion: "1.4.0",
  }));
}

function resolveSigningAddress(wallet, bloomBinary, home) {
  const result = spawnSync(bloomBinary, ["--home", home, "wallet", "address", wallet], { encoding: "utf8" });
  assert(result.status === 0, `could not resolve signing wallet: ${result.stderr.trim()}`);
  const address = result.stdout.trim();
  assert(/^0x[0-9a-fA-F]{40}$/.test(address), "Bloom returned an invalid wallet address");
  return address;
}

async function prepareCommand(options) {
  progress("starting");
  const noteWallet = safeSegment(required(options, "note-wallet"), "note wallet");
  const id = safeSegment(required(options, "id"), "id");
  const signingWallet = safeSegment(required(options, "signing-wallet"), "signing wallet");
  const replacementId = safeSegment(required(options, "replacement-id"), "replacement id");
  assert(id !== replacementId, "replacement id must differ from the existing note id");
  const output = resolve(required(options, "out"));
  const replacementBackup = resolve(required(options, "replacement-backup"));
  const password = await passphrase(resolve(required(options, "passphrase-file")));
  const artifacts = resolve(required(options, "artifacts"));
  const home = bloomHome(options);
  const root = await activeDataRoot(home);
  const note = JSON.parse(await readFile(`${root}/secrets/privacy-pools/notes/${noteWallet}/${id}`, "utf8"));
  const state = JSON.parse(await readFile(`${root}/state/privacy-pools/deposits/${noteWallet}/${id}`, "utf8"));
  Object.assign(note, state);
  validateNoteSecrets(note);
  assert(note.backup_verified === true, "existing note has no verified encrypted backup");
  assert(note.spent !== true, "existing note is already marked spent");
  for (const field of ["value", "label", "commitment"]) assert(note[field], `deposit is missing reconciled ${field}`);
  progress("note-validated");

  const processooor = options.processooor
    ?? resolveSigningAddress(
      signingWallet,
      options["bloom-bin"] ?? process.env.BLOOM_BIN ?? "bloom",
      home,
    );
  assert(/^0x[0-9a-fA-F]{40}$/.test(processooor), "invalid processooor address");
  const rpcUrl = options.rpc ?? DEFAULT_RPC;
  const client = createPublicClient({ chain: mainnet, transport: http(rpcUrl) });
  progress("reading-contract-roots");
  const [scope, currentRoot, currentTreeDepth, latestAspRoot] = await Promise.all([
    client.readContract({ address: POOL, abi: poolAbi, functionName: "SCOPE" }),
    client.readContract({ address: POOL, abi: poolAbi, functionName: "currentRoot" }),
    client.readContract({ address: POOL, abi: poolAbi, functionName: "currentTreeDepth" }),
    client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "latestRoot" }),
  ]);
  const scopePool = await client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "scopeToPool", args: [scope] });
  assert(scopePool.toLowerCase() === POOL, "pool scope resolves to another pool");
  progress("contract-roots-validated");

  progress("fetching-asp-leaves");
  const response = await fetch(ASP_LEAVES, {
    headers: { "X-Pool-Scope": scope.toString() },
    signal: AbortSignal.timeout(120_000),
  });
  assert(response.ok, `ASP leaves request failed: HTTP ${response.status}`);
  const leaves = await response.json();
  const stateLeaves = leaves.stateTreeLeaves.map(BigInt);
  const aspLeaves = leaves.aspLeaves.map(BigInt);
  progress("asp-leaves-loaded", { stateLeaves: stateLeaves.length, aspLeaves: aspLeaves.length });
  const value = BigInt(note.value);
  const withdrawnValue = options.amount ? BigInt(options.amount) : value;
  assert(withdrawnValue > 0n && withdrawnValue <= value, "withdrawal amount is outside the note value");
  const label = BigInt(note.label);
  const nullifier = BigInt(note.nullifier);
  const secret = BigInt(note.secret);
  const commitment = getCommitment(value, label, nullifier, secret);
  assert(commitment.hash === BigInt(note.commitment), "private note does not reproduce commitment");
  const existingNullifierHash = BigInt(poseidon([nullifier]));
  const spent = await client.readContract({ address: POOL, abi: poolAbi, functionName: "nullifierHashes", args: [existingNullifierHash] });
  assert(spent === false, "note nullifier is already spent on-chain");

  const stateMerkleProof = generateMerkleProof(stateLeaves, commitment.hash);
  const aspMerkleProof = generateMerkleProof(aspLeaves, label);
  const stateTreeDepth = treeDepth(stateLeaves.length);
  const aspTreeDepth = treeDepth(aspLeaves.length);
  assert(stateMerkleProof.root === currentRoot, "ASP state leaves are stale versus pool currentRoot");
  assert(stateTreeDepth === currentTreeDepth, "state tree depth mismatch");
  assert(aspMerkleProof.root === latestAspRoot, "ASP approval leaves are stale versus Entrypoint.latestRoot");
  progress("merkle-proofs-validated");

  const withdrawal = { processooor, data: "0x" };
  const context = BigInt(calculateContext(withdrawal, scope));
  const newNullifier = fieldElement();
  let newSecret = fieldElement();
  while (newSecret === newNullifier) newSecret = fieldElement();
  const sdk = new PrivacyPoolSDK(new LocalWithdrawCircuits(artifacts));
  progress("proving");
  const withdrawalProof = await sdk.proveWithdrawal(commitment, {
    context,
    withdrawalAmount: withdrawnValue,
    stateMerkleProof,
    aspMerkleProof,
    stateRoot: currentRoot,
    stateTreeDepth,
    aspRoot: latestAspRoot,
    aspTreeDepth,
    newSecret,
    newNullifier,
  });
  progress("proof-generated");
  assert(await sdk.verifyWithdrawal(withdrawalProof), "local Groth16 verification failed");
  progress("proof-verified");
  const proof = formatProof(withdrawalProof);
  assert(proof.pubSignals.length === 8, "unexpected public signal count");
  assert(proof.pubSignals[1] === existingNullifierHash, "proof nullifier mismatch");
  assert(proof.pubSignals[2] === withdrawnValue, "proof value mismatch");
  assert(proof.pubSignals[3] === currentRoot, "proof state root mismatch");
  assert(proof.pubSignals[5] === latestAspRoot, "proof ASP root mismatch");
  assert(proof.pubSignals[7] === context, "proof context mismatch");
  const calldata = encodeFunctionData({ abi: poolAbi, functionName: "withdraw", args: [withdrawal, proof] });
  await client.call({ account: processooor, to: POOL, data: calldata });
  const estimatedGas = await client.estimateGas({ account: processooor, to: POOL, data: calldata });
  const finalAspRoot = await client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "latestRoot" });
  assert(finalAspRoot === latestAspRoot, "ASP root changed during proving; run prepare again");
  progress("simulation-and-roots-validated", { estimatedGas });

  const remainingValue = value - withdrawnValue;
  const replacement = {
    parent_wallet: noteWallet,
    parent_id: id,
    replacement_id: replacementId,
    remaining_value: remainingValue.toString(),
    label: asHex(label),
    new_commitment: asHex(proof.pubSignals[0]),
    nullifier: asHex(newNullifier),
    secret: asHex(newSecret),
    calldata_hash: keccak256(calldata),
    backup_verified: true,
  };
  await verifiedBackup(replacement, replacementBackup, password, {
    kind: "replacement",
    wallet: noteWallet,
    id: replacementId,
    parent_id: id,
  });
  await atomicWrite(
    `${root}/secrets/privacy-pools/replacements/${noteWallet}/${replacementId}`,
    Buffer.from(`${JSON.stringify(replacement)}\n`),
    { exclusive: true },
  );
  const stageRequest = { signing_wallet: signingWallet, replacement_id: replacementId, calldata };
  await atomicWrite(output, Buffer.from(`${stringify(stageRequest)}\n`), { exclusive: true });
  progress("complete");
  console.log(stringify({
    proofVerified: true,
    simulationSucceeded: true,
    rootsFreshAfterProving: true,
    noteUnspent: true,
    processooor,
    withdrawalValueWei: withdrawnValue,
    remainingValueWei: remainingValue,
    estimatedGas,
    calldataBytes: (calldata.length - 2) / 2,
    stageRequest: output,
    replacementBackup,
  }));
}

async function persistJournal(path, journal) {
  await atomicWrite(path, Buffer.from(`${JSON.stringify(journal)}\n`));
}

function faultAfter(phase) {
  if (process.env.BLOOM_PP_FAULT_AFTER === phase) {
    process.kill(process.pid, "SIGKILL");
  }
}

export function withdrawnEvent(log, expected) {
  if (log.address.toLowerCase() !== POOL || log.topics[0]?.toLowerCase() !== WITHDRAWN_TOPIC.toLowerCase()) return false;
  if (!log.topics[1] || `0x${log.topics[1].slice(-40)}`.toLowerCase() !== ENTRYPOINT) return false;
  const words = log.data.slice(2).match(/.{64}/g)?.map((word) => BigInt(`0x${word}`)) ?? [];
  return words.length === 3
    && words[0] === expected.amount
    && words[1] === expected.nullifierHash
    && words[2] === expected.newCommitment;
}

async function recoverRelayTransaction(client, journal) {
  if (journal.start_block === undefined) return null;
  const logs = await client.getLogs({
    address: POOL,
    fromBlock: BigInt(journal.start_block),
    toBlock: "latest",
  });
  const expected = {
    amount: BigInt(journal.amount_wei),
    nullifierHash: BigInt(journal.existing_nullifier_hash),
    newCommitment: BigInt(journal.new_commitment),
  };
  return logs.find((log) => withdrawnEvent(log, expected))?.transactionHash ?? null;
}

async function waitUntilFinalized(client, receipt, timeoutMs = 20 * 60 * 1000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const finalized = await client.getBlock({ blockTag: "finalized" });
    if (finalized.number >= receipt.blockNumber) return finalized.number;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 12_000));
  }
  fail("settlement was mined but did not finalize before the local timeout; rerun to resume verification");
}

export function verifySettlementReceipt(receipt, journal) {
  assert(receipt.status === "success", "relayed withdrawal transaction reverted");
  const expected = {
    amount: BigInt(journal.amount_wei),
    nullifierHash: BigInt(journal.existing_nullifier_hash),
    newCommitment: BigInt(journal.new_commitment),
  };
  assert(receipt.logs.some((log) => withdrawnEvent(log, expected)), "receipt has no matching Privacy Pool Withdrawn event");

  const relayEvent = receipt.logs.find((log) =>
    log.address.toLowerCase() === ENTRYPOINT
    && log.topics[0]?.toLowerCase() === WITHDRAWAL_RELAYED_TOPIC.toLowerCase()
    && log.topics.length === 4,
  );
  assert(relayEvent, "receipt has no Entrypoint WithdrawalRelayed event");
  assert(`0x${relayEvent.topics[2].slice(-40)}`.toLowerCase() === journal.recipient.toLowerCase(), "WithdrawalRelayed recipient mismatch");
  assert(`0x${relayEvent.topics[3].slice(-40)}`.toLowerCase() === NATIVE_ASSET.toLowerCase(), "WithdrawalRelayed asset mismatch");
  const words = relayEvent.data.slice(2).match(/.{64}/g)?.map((word) => BigInt(`0x${word}`)) ?? [];
  assert(words.length === 2, "WithdrawalRelayed event data has the wrong shape");
  const expectedFee = expected.amount * BigInt(journal.fee_bps) / 10_000n;
  assert(words[0] === expected.amount && words[1] === expectedFee, "WithdrawalRelayed amount or fee mismatch");
}

async function finalizePrivateRelay({ client, journal, journalPath, note, notePath, root, statusPath, recipientPath, resultPath }) {
  journal.phase = "finalizing";
  await persistJournal(journalPath, journal);
  faultAfter("finalizing");
  const receipt = await client.waitForTransactionReceipt({ hash: journal.tx_hash, confirmations: 1, timeout: 180_000 });
  verifySettlementReceipt(receipt, journal);
  const finalizedBlock = await waitUntilFinalized(client, receipt);
  const canonicalBlock = await client.getBlock({ blockNumber: receipt.blockNumber });
  assert(canonicalBlock.hash === receipt.blockHash, "the relayed receipt was reorged before finality");
  assert(await client.readContract({
    address: POOL,
    abi: poolAbi,
    functionName: "nullifierHashes",
    args: [BigInt(journal.existing_nullifier_hash)],
    blockNumber: finalizedBlock,
  }) === true, "finalized pool state does not report the nullifier as spent");

  const result = {
    schema: "bloom.privacy-pools.private-relay-result.v1",
    request_id: journal.request_id,
    tx_hash: journal.tx_hash,
    relay_binding: journal.relay_binding,
  };
  const existingResult = await readJsonIfExists(resultPath);
  if (existingResult !== null) {
    assert(existingResult.tx_hash?.toLowerCase() === journal.tx_hash.toLowerCase(), "a different private relay result already exists");
  } else {
    await atomicWrite(resultPath, Buffer.from(`${JSON.stringify(result)}\n`), { exclusive: true });
  }

  note.spent = true;
  await atomicWrite(notePath, Buffer.from(`${JSON.stringify(note)}\n`));
  const depositStatusPath = `${root}/state/privacy-pools/deposits/${journal.note_wallet}/${journal.note_id}`;
  const depositStatus = JSON.parse(await readFile(depositStatusPath, "utf8"));
  depositStatus.spent = true;
  await atomicWrite(depositStatusPath, Buffer.from(`${JSON.stringify(depositStatus)}\n`), { mode: 0o644 });

  const remainingValue = BigInt(journal.remaining_value_wei);
  if (remainingValue > 0n) {
    const replacementNote = {
      wallet: journal.note_wallet,
      asset: note.asset,
      amount_wei: remainingValue.toString(),
      nullifier: journal.replacement.nullifier,
      secret: journal.replacement.secret,
      precommitment: asHex(BigInt(poseidon([
        BigInt(journal.replacement.nullifier),
        BigInt(journal.replacement.secret),
      ]))),
      status: "confirmed",
      tx: { chain: "mainnet", outbox_id: "private-relay" },
      value: remainingValue.toString(),
      label: journal.replacement.label,
      commitment: journal.new_commitment,
      spent: false,
      backup_verified: true,
    };
    await writeIdenticalOrCreate(
      `${root}/secrets/privacy-pools/notes/${journal.note_wallet}/${journal.replacement_id}`,
      replacementNote,
    );
    await writeIdenticalOrCreate(
      `${root}/state/privacy-pools/deposits/${journal.note_wallet}/${journal.replacement_id}`,
      redactPrivateReplacementNote(replacementNote),
      { mode: 0o644 },
    );
  }

  const publicStatus = JSON.parse(await readFile(statusPath, "utf8"));
  publicStatus.status = "complete";
  publicStatus.ceremony_url = undefined;
  publicStatus.ceremony_expires_ms = undefined;
  publicStatus.next = remainingValue > 0n
    ? "Settlement finalized. The backed-up replacement note is active."
    : "Settlement finalized. The original note is fully spent.";
  await atomicWrite(statusPath, Buffer.from(`${JSON.stringify(publicStatus)}\n`), { mode: 0o644 });
  journal.phase = "complete";
  journal.finalized_block = finalizedBlock.toString();
  await persistJournal(journalPath, journal);
  try {
    await unlink(recipientPath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  privateProgress("complete");
  console.log(stringify({
    complete: true,
    proofVerified: true,
    settlementFinalized: true,
    nullifierSpent: true,
    replacementActive: remainingValue > 0n,
  }));
}

async function relayPrivateCommand(options) {
  privateProgress("starting");
  const noteWallet = safeSegment(required(options, "note-wallet"), "note wallet");
  const id = safeSegment(required(options, "id"), "id");
  const replacementId = safeSegment(required(options, "replacement-id"), "replacement id");
  assert(id !== replacementId, "replacement id must differ from the existing note id");
  const relayer = new URL(required(options, "relayer"));
  assert(
    relayer.protocol === "https:" || (relayer.protocol === "http:" && ["localhost", "127.0.0.1"].includes(relayer.hostname)),
    "relayer must use HTTPS (HTTP is allowed only on loopback)",
  );
  const maxFeeText = required(options, "max-fee-bps");
  assert(/^\d+$/.test(maxFeeText), "max-fee-bps must be a non-negative integer");
  const maxFeeBPS = BigInt(maxFeeText);
  assert(maxFeeBPS <= 10_000n, "max-fee-bps cannot exceed 10000");
  const replacementBackup = resolve(required(options, "replacement-backup"));
  const password = await passphrase(resolve(required(options, "passphrase-file")));
  const artifacts = resolve(required(options, "artifacts"));
  const root = await activeDataRoot(bloomHome(options));
  const notePath = `${root}/secrets/privacy-pools/notes/${noteWallet}/${id}`;
  const recipientPath = `${root}/secrets/privacy-pools/private-inputs/${noteWallet}/${id}`;
  const resultPath = `${root}/secrets/privacy-pools/private-relay-results/${noteWallet}/${id}`;
  const journalPath = `${root}/secrets/privacy-pools/private-relay-attempts/${noteWallet}/${id}`;
  const replacementPath = `${root}/secrets/privacy-pools/replacements/${noteWallet}/${replacementId}`;
  const statusPath = `${root}/state/privacy-pools/private-relays/${noteWallet}/${id}`;
  const note = JSON.parse(await readFile(notePath, "utf8"));
  let journal = await readJsonIfExists(journalPath);

  if (journal?.phase === "complete") {
    try {
      await unlink(recipientPath);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    privateProgress("complete");
    console.log(stringify({ complete: true, settlementFinalized: true, replacementActive: BigInt(journal.remaining_value_wei) > 0n }));
    return;
  }

  if (journal === null) {
    const privateInput = JSON.parse(await readFile(recipientPath, "utf8"));
    assert(privateInput.schema === "bloom.privacy-pools.private-relay-recipient.v1", "invalid private recipient record");
    assert(privateInput.note_wallet === noteWallet && privateInput.note_id === id, "private recipient belongs to another note");
    assert(privateInput.replacement_id === replacementId, "private recipient replacement id mismatch");
    assert(/^0x[0-9a-fA-F]{40}$/.test(privateInput.recipient), "private recipient is not an Ethereum address");
    const value = BigInt(note.value);
    const withdrawnValue = privateInput.amount_wei ? BigInt(privateInput.amount_wei) : value;
    assert(withdrawnValue > 0n && withdrawnValue <= value, "withdrawal amount is outside the note value");
    const newNullifier = fieldElement();
    let newSecret = fieldElement();
    while (newSecret === newNullifier) newSecret = fieldElement();
    const replacement = {
      parent_wallet: noteWallet,
      parent_id: id,
      replacement_id: replacementId,
      remaining_value: (value - withdrawnValue).toString(),
      label: asHex(BigInt(note.label)),
      nullifier: asHex(newNullifier),
      secret: asHex(newSecret),
      backup_verified: true,
    };
    journal = {
      schema: "bloom.privacy-pools.private-relay-attempt.v1",
      phase: "destination-ready",
      note_wallet: noteWallet,
      note_id: id,
      replacement_id: replacementId,
      recipient: privateInput.recipient,
      amount_wei: withdrawnValue.toString(),
      remaining_value_wei: (value - withdrawnValue).toString(),
      replacement,
    };
    await persistJournal(journalPath, journal);
    faultAfter("destination-ready");
    await verifiedBackup(replacement, replacementBackup, password, {
      kind: "replacement",
      wallet: noteWallet,
      id: replacementId,
      parent_id: id,
    });
    await writeIdenticalOrCreate(replacementPath, replacement);
  } else {
    assert(journal.schema === "bloom.privacy-pools.private-relay-attempt.v1", "unsupported private relay journal");
    assert(
      journal.note_wallet === noteWallet && journal.note_id === id && journal.replacement_id === replacementId,
      "private relay journal belongs to another request",
    );
    assert(/^0x[0-9a-fA-F]{40}$/.test(journal.recipient), "private relay journal recipient is invalid");
    await verifiedBackup(journal.replacement, replacementBackup, password, {
      kind: "replacement",
      wallet: noteWallet,
      id: replacementId,
      parent_id: id,
    });
  }

  assert(note.backup_verified === true, "existing note has no verified encrypted backup");
  for (const field of ["value", "label", "commitment"]) assert(note[field], `deposit is missing reconciled ${field}`);
  const rpcUrl = options.rpc ?? DEFAULT_RPC;
  const client = createPublicClient({ chain: mainnet, transport: http(rpcUrl) });
  const existingNullifierHash = BigInt(poseidon([BigInt(note.nullifier)]));

  if (["submitting", "ambiguous"].includes(journal.phase)) {
    const recovered = await recoverRelayTransaction(client, journal);
    if (recovered) {
      journal.tx_hash = recovered;
      journal.phase = "broadcast";
      await persistJournal(journalPath, journal);
    } else {
      const spent = await client.readContract({
        address: POOL,
        abi: poolAbi,
        functionName: "nullifierHashes",
        args: [existingNullifierHash],
      });
      assert(spent === false, "the note is spent but its matching withdrawal event was not recoverable from the journal start block");
      journal.phase = "ambiguous";
      await persistJournal(journalPath, journal);
      const oldEnough = Date.now() - Number(journal.submission_started_ms) >= AMBIGUOUS_RETRY_DELAY_MS;
      assert(options["retry-ambiguous"] === "yes" && oldEnough,
        "relay response was lost and no matching event is visible yet; wait five minutes, then rerun with --retry-ambiguous yes");
      journal.phase = "destination-ready";
      delete journal.start_block;
      delete journal.submission_started_ms;
      delete journal.tx_hash;
      await persistJournal(journalPath, journal);
    }
  }

  if (["broadcast", "finalizing"].includes(journal.phase)) {
    await finalizePrivateRelay({ client, journal, journalPath, note, notePath, root, statusPath, recipientPath, resultPath });
    return;
  }

  assert(note.spent !== true, "existing note is already marked spent");
  validateNoteSecrets(note);
  const value = BigInt(note.value);
  const withdrawnValue = BigInt(journal.amount_wei);
  const label = BigInt(note.label);
  const nullifier = BigInt(note.nullifier);
  const secret = BigInt(note.secret);
  const commitment = getCommitment(value, label, nullifier, secret);
  assert(commitment.hash === BigInt(note.commitment), "private note does not reproduce commitment");
  assert(await client.readContract({ address: POOL, abi: poolAbi, functionName: "nullifierHashes", args: [existingNullifierHash] }) === false,
    "note nullifier is already spent on-chain");

  const [scope, currentRoot, currentTreeDepth, latestAspRoot] = await Promise.all([
    client.readContract({ address: POOL, abi: poolAbi, functionName: "SCOPE" }),
    client.readContract({ address: POOL, abi: poolAbi, functionName: "currentRoot" }),
    client.readContract({ address: POOL, abi: poolAbi, functionName: "currentTreeDepth" }),
    client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "latestRoot" }),
  ]);
  const scopePool = await client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "scopeToPool", args: [scope] });
  assert(scopePool.toLowerCase() === POOL, "pool scope resolves to another pool");
  const circuits = new LocalWithdrawCircuits(artifacts);
  const detailsUrl = new URL("/relayer/details", relayer);
  detailsUrl.searchParams.set("chainId", "1");
  detailsUrl.searchParams.set("assetAddress", NATIVE_ASSET);
  const [leavesResponse, detailsResponse] = await Promise.all([
    fetch(ASP_LEAVES, { headers: { "X-Pool-Scope": scope.toString() }, signal: AbortSignal.timeout(120_000) })
      .catch(() => fail("ASP leaves request failed before an HTTP response")),
    fetch(detailsUrl, { signal: AbortSignal.timeout(30_000) })
      .catch(() => fail("relayer details failed before an HTTP response")),
    circuits.preload(),
  ]);
  assert(leavesResponse.ok, `ASP leaves request failed: HTTP ${leavesResponse.status}`);
  assert(detailsResponse.ok, `relayer details failed: HTTP ${detailsResponse.status}`);
  const detailsEnvelope = await detailsResponse.json();
  const details = detailsEnvelope.data ?? detailsEnvelope;
  assert(Number(details.chainId) === 1, "relayer details returned another chain");
  assert(details.assetAddress?.toLowerCase() === NATIVE_ASSET.toLowerCase(), "relayer details returned another asset");
  assert(BigInt(details.minWithdrawAmount ?? 0) <= withdrawnValue, "withdrawal is below relayer minimum");
  const leaves = await leavesResponse.json();
  const stateLeaves = leaves.stateTreeLeaves.map(BigInt);
  const aspLeaves = leaves.aspLeaves.map(BigInt);
  const stateMerkleProof = generateMerkleProof(stateLeaves, commitment.hash);
  const aspMerkleProof = generateMerkleProof(aspLeaves, label);
  const stateTreeDepth = treeDepth(stateLeaves.length);
  const aspTreeDepth = treeDepth(aspLeaves.length);
  assert(stateMerkleProof.root === currentRoot && stateTreeDepth === currentTreeDepth, "ASP state leaves are stale versus the pool");
  assert(aspMerkleProof.root === latestAspRoot, "ASP approval leaves are stale versus Entrypoint.latestRoot");

  const quoteResponse = await fetch(new URL("/relayer/quote", relayer), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chainId: 1, amount: withdrawnValue.toString(), asset: NATIVE_ASSET, recipient: journal.recipient }),
    signal: AbortSignal.timeout(60_000),
  });
  assert(quoteResponse.ok, `relayer quote failed: HTTP ${quoteResponse.status}`);
  const quote = await quoteResponse.json();
  const validatedQuote = validateRelayQuote(quote, {
    recipient: journal.recipient,
    amount: withdrawnValue,
    maxFeeBPS,
  });
  assert(Number(quote.feeCommitment.expiration) > Date.now() + QUOTE_SAFETY_MS, "relayer quote lifetime is too short for safe proving");
  const withdrawal = { processooor: ENTRYPOINT, data: validatedQuote.withdrawalData };
  const context = BigInt(calculateContext(withdrawal, scope));
  journal.phase = "proving";
  await persistJournal(journalPath, journal);
  faultAfter("proving");
  const sdk = new PrivacyPoolSDK(circuits);
  const withdrawalProof = await sdk.proveWithdrawal(commitment, {
    context,
    withdrawalAmount: withdrawnValue,
    stateMerkleProof,
    aspMerkleProof,
    stateRoot: currentRoot,
    stateTreeDepth,
    aspRoot: latestAspRoot,
    aspTreeDepth,
    newSecret: BigInt(journal.replacement.secret),
    newNullifier: BigInt(journal.replacement.nullifier),
  });
  assert(await sdk.verifyWithdrawal(withdrawalProof), "local Groth16 verification failed");
  const proof = formatProof(withdrawalProof);
  assert(proof.pubSignals[1] === existingNullifierHash, "proof nullifier mismatch");
  assert(proof.pubSignals[2] === withdrawnValue, "proof value mismatch");
  assert(proof.pubSignals[3] === currentRoot && proof.pubSignals[5] === latestAspRoot, "proof roots mismatch");
  assert(proof.pubSignals[7] === context, "proof context mismatch");
  assert(Number(quote.feeCommitment.expiration) > Date.now() + QUOTE_SAFETY_MS, "signed relayer quote expired during proving");
  const relayBinding = keccak256(toHex(JSON.stringify({
    withdrawal,
    publicSignals: withdrawalProof.publicSignals.map(String),
    scope: scope.toString(),
  })));
  journal.phase = "proof-ready";
  journal.existing_nullifier_hash = asHex(existingNullifierHash);
  journal.new_commitment = asHex(proof.pubSignals[0]);
  journal.fee_bps = validatedQuote.feeBPS.toString();
  journal.relay_binding = relayBinding;
  journal.withdrawal = withdrawal;
  journal.proof = withdrawalProof.proof;
  journal.public_signals = withdrawalProof.publicSignals.map(String);
  journal.fee_commitment = quote.feeCommitment;
  journal.scope = scope.toString();
  await persistJournal(journalPath, journal);
  faultAfter("proof-ready");
  await atomicWrite(
    replacementPath,
    Buffer.from(`${JSON.stringify({ ...journal.replacement, new_commitment: journal.new_commitment })}\n`),
  );

  await client.simulateContract({
    address: ENTRYPOINT,
    abi: entrypointAbi,
    functionName: "relay",
    args: [withdrawal, proof, scope],
    account: validatedQuote.feeRecipient,
  });
  await client.estimateContractGas({
    address: ENTRYPOINT,
    abi: entrypointAbi,
    functionName: "relay",
    args: [withdrawal, proof, scope],
    account: validatedQuote.feeRecipient,
  });
  assert(await client.readContract({ address: POOL, abi: poolAbi, functionName: "currentRoot" }) === currentRoot,
    "pool root changed after proving; rerun to create a fresh proof");
  assert(await client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "latestRoot" }) === latestAspRoot,
    "ASP root changed after proving; rerun to create a fresh proof");
  assert(Number(quote.feeCommitment.expiration) > Date.now() + 5_000, "signed relayer quote is too close to expiry for submission");

  const relayPayload = {
    chainId: 1,
    scope: scope.toString(),
    withdrawal,
    proof: withdrawalProof.proof,
    publicSignals: withdrawalProof.publicSignals.map(String),
    feeCommitment: quote.feeCommitment,
  };
  journal.phase = "submitting";
  journal.start_block = (await client.getBlockNumber()).toString();
  journal.submission_started_ms = Date.now();
  await persistJournal(journalPath, journal);
  faultAfter("submitting");
  let relayed;
  try {
    const relayResponse = await fetch(new URL("/relayer/request", relayer), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(relayPayload),
      signal: AbortSignal.timeout(120_000),
    });
    assert(relayResponse.ok, `relayer submission failed: HTTP ${relayResponse.status}`);
    relayed = await relayResponse.json();
    assert(relayed.success === true && /^0x[0-9a-fA-F]{64}$/.test(relayed.txHash ?? ""), "relayer did not return a successful transaction hash");
    journal.tx_hash = relayed.txHash;
    journal.request_id = relayed.requestId;
  } catch (error) {
    journal.phase = "ambiguous";
    await persistJournal(journalPath, journal);
    faultAfter("ambiguous");
    const recovered = await recoverRelayTransaction(client, journal);
    if (!recovered) throw error;
    journal.tx_hash = recovered;
  }
  journal.phase = "broadcast";
  await persistJournal(journalPath, journal);
  faultAfter("broadcast");
  await finalizePrivateRelay({ client, journal, journalPath, note, notePath, root, statusPath, recipientPath, resultPath });
}

function usage() {
  return `Usage:
  bloom-privacy-pools backup --wallet W --id ID --out FILE --passphrase-file FILE [--home DIR]
  bloom-privacy-pools restore --in FILE --passphrase-file FILE [--home DIR]
    (a v1/legacy-schema backup additionally requires --trust-legacy-wallet W --trust-legacy-id ID
     --trust-legacy-kind deposit|replacement, asserting out of band what its unauthenticated
     metadata is trusted to claim)
  bloom-privacy-pools verify-artifacts --artifacts DIR
  bloom-privacy-pools prepare --note-wallet W --id ID --signing-wallet W --replacement-id ID --artifacts DIR --replacement-backup FILE --passphrase-file FILE --out FILE [--amount WEI] [--rpc URL] [--home DIR]
  bloom-privacy-pools relay-private --note-wallet W --id ID --replacement-id ID --relayer URL --max-fee-bps BPS --artifacts DIR --replacement-backup FILE --passphrase-file FILE [--retry-ambiguous yes] [--rpc URL] [--home DIR]`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { command, options } = parseArgs(process.argv.slice(2));
  const commands = {
    backup: backupCommand,
    restore: restoreCommand,
    "verify-artifacts": verifyArtifactsCommand,
    prepare: prepareCommand,
    "relay-private": relayPrivateCommand,
  };
  if (!commands[command]) {
    console.error(usage());
    process.exitCode = 2;
  } else {
    commands[command](options).catch((error) => {
      if (command === "relay-private") {
        // Library and provider errors can include witness inputs or request
        // payloads. Never project an arbitrary nested error into an
        // agent-visible terminal for the recipient-private workflow.
        console.error(stringify({
          petal: "privacy-pools",
          command,
          phase: "failed",
          error: "private relay failed; retry or inspect it locally outside the agent session",
        }));
      } else {
        console.error(`privacy-pools ${command} failed: ${error instanceof Error ? error.message : String(error)}`);
      }
      process.exitCode = 1;
    });
  }
}
