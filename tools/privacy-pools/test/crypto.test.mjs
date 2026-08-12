import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
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
