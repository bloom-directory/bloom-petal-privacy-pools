# Privacy Pools withdrawal runbook

This is the canonical operating guide. Direct ETH withdrawals use Bloom's
outbox. Recipient-private withdrawals use the protocol's relayer path so the
agent can initiate and monitor the operation through VFS without receiving the
destination. Never substitute an `Entrypoint.withdraw` call—it does not exist.

## Security boundary

- `nullifier`, `secret`, and replacement secrets never cross a VFS route.
- Never print them or put them in a shell argument, log, chat, or issue.
- The companion reads the active local secrets store and accepts passphrases
  only through a mode-`0600` file.
- Backups use scrypt plus AES-256-GCM, are decrypt-and-compare verified, and are
  written mode `0600` without overwriting an existing file.
- A direct withdrawal cannot be staged until both the existing note and its
  replacement note have verified encrypted backups.
- Petal package-store migration is still not a backup.
- A private relay keeps the recipient out of VFS, route bodies, public petal
  state, console output, and Bloom transaction intents. The destination is
  still necessarily visible to the chosen relayer and on Ethereum.
- This boundary assumes the agent cannot arbitrarily read the Bloom daemon's
  OS-level secret files or process memory.

## Install the companion

```sh
cd tools/privacy-pools
npm ci --ignore-scripts
```

The dependency lock pins `@0xbow/privacy-pools-core-sdk@1.4.0`. The tool also
checks the SDK's expected SHA-256 values for `withdraw.wasm`, `withdraw.vkey`,
and `withdraw.zkey` before every proof. Keep those artifacts in a private local
directory and verify them before use:

```sh
node tools/privacy-pools/cli.mjs verify-artifacts \
  --artifacts /secure/path/privacy-pools-artifacts
```

## 1. Reconcile and back up the deposit

First read the deposit. This now falls back to a direct Ethereum receipt when
an older Bloom receipt omitted logs, and it checks the spent-nullifier mapping
on-chain without returning the private nullifier.

```sh
bloom vfs cat /petals/privacy-pools/deposits/<note-wallet>/<id>.json
```

Create a mode-`0600` passphrase file, then make and verify the encrypted backup:

```sh
node tools/privacy-pools/cli.mjs backup \
  --wallet <note-wallet> \
  --id <id> \
  --out /secure/backups/<id>.note.enc \
  --passphrase-file /secure/passphrase
```

The tool marks `backup_verified: true` only after it decrypts the newly written
backup and compares its complete plaintext hash. Restore is explicit and
refuses to replace a different existing note:

```sh
node tools/privacy-pools/cli.mjs restore \
  --in /secure/backups/<id>.note.enc \
  --passphrase-file /secure/passphrase
```

## 2. Inspect readiness

```sh
bloom vfs cat /petals/privacy-pools/withdrawals/<note-wallet>/<id>.json
```

The preview is deliberately incomplete. In particular,
`withdrawal_proof_input.public_signals.context` remains `null` until a real
signing wallet/processooor is selected. The route never emits a zero-address
placeholder that could be mistaken for a usable context.

Readiness requires:

1. Reconciled `value`, `label`, and `commitment` from the `Deposited` event.
2. A verified encrypted backup.
3. `Poseidon(nullifier)` unspent on-chain.
4. Commitment inclusion in ordered state leaves.
5. Label inclusion in ordered ASP leaves.
6. Fresh state/ASP roots.
7. A locally verified Groth16 proof.
8. Successful simulation from the exact processooor.

## 3. Prepare a direct withdrawal

The deposit alias and signing alias are separate. They may differ only when the
selected signing wallet resolves to the exact processooor encoded in the proof.

```sh
node tools/privacy-pools/cli.mjs prepare \
  --note-wallet <note-wallet> \
  --id <id> \
  --signing-wallet <signing-wallet> \
  --replacement-id <new-unique-id> \
  --artifacts /secure/path/privacy-pools-artifacts \
  --replacement-backup /secure/backups/<new-unique-id>.note.enc \
  --passphrase-file /secure/passphrase \
  --out /secure/work/<id>-stage.json
```

Omit `--amount` for a full withdrawal or add `--amount <wei>` for a partial
withdrawal. The tool:

- resolves the signing wallet address;
- fetches fresh `stateTreeLeaves` and `aspLeaves` from the public 0xBOW ASP;
- verifies state and ASP roots against the contracts;
- verifies the note commitment and on-chain unspent state;
- generates fresh replacement secrets and backs them up before producing a
  stage request;
- proves and verifies with the official SDK and pinned artifacts;
- simulates the exact `PrivacyPool.withdraw` calldata;
- rechecks the ASP root after proving; and
- writes a public stage request without secret fields.

The circuit always creates a replacement commitment. For a full withdrawal its
remaining value is zero; for a partial withdrawal it becomes a new note under
`<replacement-id>` after settlement.

## 4. Stage and approve

```sh
bloom vfs write \
  /petals/privacy-pools/withdrawals/<note-wallet>/<id>.json \
  < /secure/work/<id>-stage.json

bloom vfs cat /petals/privacy-pools/withdrawals/<note-wallet>/<id>.json
bloom wallet confirm <signing-wallet> mainnet <outbox-id>
```

Before staging, the petal independently:

- decodes the exact direct-withdrawal ABI shape;
- checks the processooor against the signing wallet;
- recomputes `Poseidon(nullifier)` from the private note;
- checks the proof's value, context, and latest ASP root;
- recomputes the replacement commitment from its private secrets;
- requires both backup-verification flags; and
- simulates the exact calldata from the exact processooor.

Bloom performs another simulation during confirmation. When private routing is
enabled, Bloom must resolve the configured provider before opening the owner
ceremony. A retained private transaction may only be replayed as identical
bytes to the same private relay.

## 5. Verify settlement

Poll the withdrawal path after mining:

```sh
bloom vfs cat /petals/privacy-pools/withdrawals/<note-wallet>/<id>.json
```

The petal marks `settlement_verified: true` only after all of these pass:

- successful outbox/receipt state;
- a `Withdrawn` event emitted by the expected PrivacyPool;
- matching processooor, value, spent nullifier, and new commitment;
- the pool reports the nullifier spent; and
- the replacement secret record is still present and verified.

It then atomically advances durable state as far as the host store API allows:
the original note is marked spent, the withdrawal is confirmed, and a non-zero
replacement is promoted to a new backed-up note. All write steps are idempotent
so polling can safely finish reconciliation after an interrupted process.

## Recipient-private relayed withdrawal

First let the agent initiate the flow without an address:

```sh
bloom vfs write \
  /petals/privacy-pools/withdrawals/<note-wallet>/<id>.json \
  --data '{"mode":"private-relay","replacement_id":"<new-unique-id>"}'

bloom vfs cat /petals/privacy-pools/withdrawals/<note-wallet>/<id>.json
```

Add `"amount_wei":"<wei>"` for a partial withdrawal; if you omit it, the full
note value is used. The VFS write records only public intent and returns
`awaiting-owner-input`. It does not launch a Bloom approval or private-input
ceremony, and there is no second VFS write.

Run the redacting companion:

```sh
node tools/privacy-pools/cli.mjs relay-private \
  --note-wallet <note-wallet> \
  --id <id> \
  --relayer https://<trusted-relayer> \
  --max-fee-bps <owner-approved-ceiling> \
  --artifacts /secure/path/privacy-pools-artifacts \
  --replacement-backup /secure/backups/<new-unique-id>.note.enc \
  --passphrase-file /secure/passphrase
```

The helper reads and validates the replacement id from the public intent
record; it is not repeated as a command-line argument.

The companion opens a one-shot form bound to `127.0.0.1` and shows the exact
amount in ETH and wei, asset, source note, relayer origin, and fee ceiling
before accepting the Ethereum destination. Do not paste the address into chat
or a VFS command. The form uses a random
short-lived token, sends the destination only to the same loopback process,
and closes after one valid submission. This is private input, not transaction
approval or authentication.

The helper retains the address only in its mode-`0600` retry journal, reads the
note directly from the secret store, obtains the relayer's details, preloads
and verifies circuit artifacts, synchronizes
both trees, and only then requests the short-lived signed fee commitment. It
generates and locally verifies the proof, exactly simulates and estimates
`Entrypoint.relay(withdrawal, proof, scope)`, and verifies both the Pool
`Withdrawn` event and Entrypoint `WithdrawalRelayed` event at finalized state.
It does not query the recipient balance. Its output contains only coarse
working/final booleans. The address, proof, calldata, transaction hash, request
id, and journal timestamps remain in the secret namespace.

`--max-fee-bps` is mandatory. The helper decodes the signed withdrawal data
and verifies its recipient, asset, amount, fee, non-zero fee recipient, and
expiry before it creates replacement state or submits anything.

`relay-private` is resumable. A fsynced secret journal records stable
replacement material and these checkpoints: `destination-ready`, `proving`,
`proof-ready`, `submitting`, `ambiguous`, `broadcast`, `finalizing`, and
`complete`. On a lost POST response it scans from the pre-submit block for the
exact nullifier, value, and replacement commitment. It resumes the matching
transaction without resubmitting. If no event is visible, it waits at least
five minutes and requires the owner/operator to rerun with
`--retry-ambiguous yes`; the same replacement secrets are reused.

## Current limitations

- Only native ETH withdrawals are implemented.
- The companion is a local Node tool, not WASM proving inside the petal.
- ASP availability is external; a changed ASP root requires a fresh proof but
  reuses the same backed-up replacement material.
- Store updates are idempotent but not multi-key transactional; repeated reads
  complete reconciliation after a crash between individual writes.
- The local helper protects against accidental agent-visible output, but a
  process with unrestricted access to the same Unix account can read Bloom's
  secret store. Strong isolation requires running Bloom and the helper under a
  separate OS identity. Venice is not a trusted execution environment and must
  not receive the destination. A Tor/proxy transport is optional if hiding the
  owner's network address from the relayer is also required.
