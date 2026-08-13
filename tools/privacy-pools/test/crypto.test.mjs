import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createCipheriv, createHash, randomBytes, scryptSync } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { encodeAbiParameters } from "viem";

import {
  decryptEnvelope,
  encryptEnvelope,
  atomicWrite,
  redactPrivateReplacementNote,
  restoreCommand,
  validateRelayQuote,
  verifiedBackup,
  verifySettlementReceipt,
  writeIdenticalOrCreate,
} from "../cli.mjs";

test("encrypted note backup round trips", () => {
  const plaintext = Buffer.from('{"nullifier":"secret material"}\n');
  const envelope = encryptEnvelope(plaintext, "a sufficiently long passphrase", {
    kind: "deposit",
    wallet: "dev",
    id: "deposit-1",
  });
  assert.deepEqual(decryptEnvelope(envelope, "a sufficiently long passphrase"), plaintext);
  assert.notEqual(envelope.ciphertext, plaintext.toString("base64"));
});

test("wrong passphrase cannot decrypt", () => {
  const envelope = encryptEnvelope(Buffer.from("secret"), "a sufficiently long passphrase", {});
  assert.throws(() => decryptEnvelope(envelope, "a different long passphrase"));
});

test("v2 backup envelope authenticates its own routing metadata", () => {
  const password = "a sufficiently long passphrase";
  const plaintext = Buffer.from("secret note material");
  const envelope = encryptEnvelope(plaintext, password, { kind: "deposit", wallet: "alice", id: "note-1" });
  assert.equal(envelope.schema, "bloom.privacy-pools.encrypted-note.v2");
  assert.deepEqual(decryptEnvelope(envelope, password), plaintext);

  // restoreCommand trusts kind/wallet/id (read from the same JSON object) to
  // decide where on disk to write. None of these are the encryption key, so
  // an attacker with only file-write access — no password — could edit them
  // directly. AAD must make that fail authentication before those fields
  // are ever used for routing.
  for (const [field, value] of [["kind", "replacement"], ["wallet", "mallory"], ["id", "note-2"]]) {
    const tampered = { ...envelope, [field]: value };
    assert.throws(
      () => decryptEnvelope(tampered, password),
      /unsupported state|unable to authenticate/i,
      `mutating ${field} should invalidate the envelope`,
    );
  }
});

test("v1 backup envelopes (no AAD) still decrypt for backward compatibility", () => {
  // encryptEnvelope always produces v2 now, so this reconstructs the exact
  // pre-v2 shape by hand to pin the legacy reader path against real
  // v0.1.3-era backups rather than a self-consistent round trip.
  const password = "a sufficiently long passphrase";
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(password, salt, 32, { N: 1 << 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from("legacy secret");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const legacyEnvelope = {
    schema: "bloom.privacy-pools.encrypted-note.v1",
    cipher: "aes-256-gcm",
    kdf: { name: "scrypt", N: 131072, r: 8, p: 1, salt: salt.toString("base64") },
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    plaintext_sha256: createHash("sha256").update(plaintext).digest("hex"),
    kind: "deposit",
    wallet: "alice",
    id: "note-1",
  };
  assert.deepEqual(decryptEnvelope(legacyEnvelope, password), plaintext);
});

test("v1 (legacy) backup restore requires an explicit, matching operator assertion", async () => {
  const password = "a sufficiently long passphrase";
  const home = await mkdtemp(join(tmpdir(), "privacy-pools-home-"));
  const hash = "a".repeat(64);
  await mkdir(`${home}/petals/store/owners`, { recursive: true });
  await writeFile(`${home}/petals/store/owners/privacy-pools.json`, JSON.stringify({ hash }));
  const passphraseFile = join(home, "passphrase.txt");
  await writeFile(passphraseFile, password, { mode: 0o600 });

  // A hand-crafted v1 (no-AAD) envelope, matching real v0.1.3 shape. Its
  // wallet/id are plaintext and unauthenticated -- exactly what this gate
  // exists to stop restore from blindly trusting.
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(password, salt, 32, { N: 1 << 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(`${JSON.stringify({ nullifier: "0x1", secret: "0x2", remaining_value: "1" })}\n`);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const envelopeIn = join(home, "legacy-replacement.enc.json");
  await writeFile(envelopeIn, JSON.stringify({
    schema: "bloom.privacy-pools.encrypted-note.v1",
    cipher: "aes-256-gcm",
    kdf: { name: "scrypt", N: 131072, r: 8, p: 1, salt: salt.toString("base64") },
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    plaintext_sha256: createHash("sha256").update(plaintext).digest("hex"),
    kind: "replacement",
    wallet: "dev",
    id: "note-2",
  }));

  await assert.rejects(
    restoreCommand({ in: envelopeIn, "passphrase-file": passphraseFile, home }),
    /trust-legacy-wallet/,
  );
  await assert.rejects(
    restoreCommand({
      in: envelopeIn,
      "passphrase-file": passphraseFile,
      home,
      "trust-legacy-wallet": "mallory",
      "trust-legacy-id": "note-2",
      "trust-legacy-kind": "replacement",
    }),
    /do not match/,
  );
  await assert.rejects(
    restoreCommand({
      in: envelopeIn,
      "passphrase-file": passphraseFile,
      home,
      "trust-legacy-wallet": "dev",
      "trust-legacy-id": "note-2",
      // kind alone selects the destination directory and which validation
      // runs -- must be gated exactly like wallet/id, not left implicit.
      "trust-legacy-kind": "deposit",
    }),
    /do not match/,
  );
  await restoreCommand({
    in: envelopeIn,
    "passphrase-file": passphraseFile,
    home,
    "trust-legacy-wallet": "dev",
    "trust-legacy-id": "note-2",
    "trust-legacy-kind": "replacement",
  });
  const restored = JSON.parse(
    await readFile(`${home}/petals/data/${hash}/secrets/privacy-pools/replacements/dev/note-2`, "utf8"),
  );
  assert.equal(restored.nullifier, "0x1");
});

const recipient = "0x1111111111111111111111111111111111111111";
const feeRecipient = "0x2222222222222222222222222222222222222222";

function quoteFor(encodedRecipient = recipient, feeBPS = 250n) {
  return {
    feeBPS: feeBPS.toString(),
    feeCommitment: {
      expiration: 2_000,
      withdrawalData: encodeAbiParameters(
        [{ type: "address" }, { type: "address" }, { type: "uint256" }],
        [encodedRecipient, feeRecipient, feeBPS],
      ),
      signedRelayerCommitment: "0x1234",
      asset: "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
      amount: "1000",
      extraGas: false,
    },
  };
}

test("private relay quote binds recipient, amount, and owner fee ceiling", () => {
  const validated = validateRelayQuote(quoteFor(), {
    recipient,
    amount: 1000n,
    maxFeeBPS: 250n,
    now: 1_000,
  });
  assert.equal(validated.feeBPS, 250n);
  assert.throws(() => validateRelayQuote(quoteFor(), {
    recipient,
    amount: 1000n,
    maxFeeBPS: 249n,
    now: 1_000,
  }), /exceeds max-fee-bps/);
});

test("private relay quote rejects a substituted recipient", () => {
  assert.throws(() => validateRelayQuote(quoteFor(feeRecipient), {
    recipient,
    amount: 1000n,
    maxFeeBPS: 500n,
    now: 1_000,
  }), /another recipient/);
});

test("private relay CLI never prints arbitrary failure details", () => {
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("../cli.mjs", import.meta.url)), "relay-private"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /private relay failed/);
  assert.doesNotMatch(result.stderr, /missing required option/);
  assert.doesNotMatch(result.stderr, /\d{4}-\d{2}-\d{2}T/);
  assert.doesNotMatch(result.stderr, /submitted|proof|quote|recipient/i);
});

test("durable writes are atomic and identical retries are idempotent", async () => {
  const directory = await mkdtemp(join(tmpdir(), "privacy-pools-journal-"));
  const path = join(directory, "nested", "attempt.json");
  await atomicWrite(path, Buffer.from("one\n"));
  assert.equal(await readFile(path, "utf8"), "one\n");
  await writeIdenticalOrCreate(join(directory, "stable.json"), { secret: "fixed" });
  await writeIdenticalOrCreate(join(directory, "stable.json"), { secret: "fixed" });
  await assert.rejects(
    writeIdenticalOrCreate(join(directory, "stable.json"), { secret: "changed" }),
    /different durable state/,
  );
});

test("concurrent exclusive writers: exactly one wins", async () => {
  const directory = await mkdtemp(join(tmpdir(), "privacy-pools-race-"));
  const path = join(directory, "note.json");
  const attempts = 50;
  const results = await Promise.allSettled(
    Array.from({ length: attempts }, (_, index) =>
      atomicWrite(path, Buffer.from(`writer-${index}\n`), { exclusive: true })),
  );
  const succeeded = results.filter((result) => result.status === "fulfilled");
  const failed = results.filter((result) => result.status === "rejected");
  assert.equal(succeeded.length, 1, `expected exactly one exclusive writer to win, got ${succeeded.length}/${attempts}`);
  assert.equal(failed.length, attempts - 1);
  for (const result of failed) assert.match(result.reason.message, /refusing to overwrite/);
  const finalContent = await readFile(path, "utf8");
  assert.match(finalContent, /^writer-\d+\n$/, "the file must hold exactly one writer's untorn content");
});

test("replacement backup is reusable but cannot silently change", async () => {
  const directory = await mkdtemp(join(tmpdir(), "privacy-pools-backup-"));
  const output = join(directory, "replacement.enc.json");
  const password = "a sufficiently long passphrase";
  const metadata = { kind: "replacement", wallet: "dev", id: "next", parent_id: "old" };
  await verifiedBackup({ nullifier: "fixed", secret: "fixed" }, output, password, metadata);
  await verifiedBackup({ nullifier: "fixed", secret: "fixed" }, output, password, metadata);
  await assert.rejects(
    verifiedBackup({ nullifier: "changed", secret: "fixed" }, output, password, metadata),
    /different replacement material/,
  );
});

test("settlement requires both pool and Entrypoint events with the hidden recipient", () => {
  const amount = 1000n;
  const nullifierHash = 22n;
  const newCommitment = 33n;
  const feeBPS = 250n;
  const word = (value) => value.toString(16).padStart(64, "0");
  const addressTopic = (address) => `0x${address.slice(2).padStart(64, "0")}`;
  const journal = {
    amount_wei: amount.toString(),
    existing_nullifier_hash: `0x${nullifierHash.toString(16)}`,
    new_commitment: `0x${newCommitment.toString(16)}`,
    recipient,
    fee_bps: feeBPS.toString(),
  };
  const receipt = {
    status: "success",
    logs: [
      {
        address: "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb",
        topics: [
          "0x75e161b3e824b114fc1a33274bd7091918dd4e639cede50b78b15a4eea956a21",
          addressTopic("0x6818809eefce719e480a7526d76bd3e561526b46"),
        ],
        data: `0x${word(amount)}${word(nullifierHash)}${word(newCommitment)}`,
      },
      {
        address: "0x6818809eefce719e480a7526d76bd3e561526b46",
        topics: [
          "0xe9b67844a7bb6e6ac95e8a0de02e4448dbb0c9460be9194348e4bbac6d13c2cf",
          addressTopic(feeRecipient),
          addressTopic(recipient),
          addressTopic("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
        ],
        data: `0x${word(amount)}${word(amount * feeBPS / 10_000n)}`,
      },
    ],
  };
  verifySettlementReceipt(receipt, journal);
  const tampered = structuredClone(receipt);
  tampered.logs[1].topics[2] = addressTopic(feeRecipient);
  assert.throws(() => verifySettlementReceipt(tampered, journal), /recipient mismatch/);
});

test("private replacement public state removes secrets and transaction correlation", () => {
  const publicNote = redactPrivateReplacementNote({
    nullifier: "secret-nullifier",
    secret: "secret-secret",
    commitment: "0x1234",
    tx: { chain: "mainnet", outbox_id: "private-relay", tx_hash: "0xleak" },
  });
  assert.deepEqual(publicNote, {
    commitment: "0x1234",
    tx: { chain: "mainnet", outbox_id: "private-relay" },
  });
});
