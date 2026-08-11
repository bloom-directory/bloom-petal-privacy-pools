# Privacy Pools Petal — operating contract

> ## ⚠️ CRITICAL SAFETY — READ BEFORE OPERATING
>
> **Deposit notes (nullifier + secret) are the ONLY way to withdraw.** If they
> are lost, the deposited ETH is **permanently locked** — no recovery path.
>
> ### Mandatory rules for any agent or operator:
>
> 1. **Test the full cycle first.** Deposit → prepare withdrawal → generate
>    proof → withdraw → verify ETH arrived. Use the **minimum deposit amount**
>    (check `pool/config.json`). Never deposit more than the minimum until
>    withdrawal is proven end-to-end.
>
> 2. **Back up the note immediately.** After each deposit, read
>    `/petals/privacy-pools/recovery/<wallet>/<id>.json` and save the note
>    offline. **Do NOT rely on the petal's store as the only copy.**
>
> 3. **NEVER reinstall this petal without backing up.** The petal's secret
>    store is keyed by package hash. Reinstalling (new build, new version)
>    **destroys all stored notes**. Run `bloom petals export-secrets
>    privacy-pools` (or read all `/recovery/` routes) before any reinstall.
>
> 4. **One deposit at a time.** Stage, confirm on-chain, back up the note,
>    and verify withdrawal preparation works BEFORE making another deposit.
>
> 5. **Minimum amounts only.** Never deposit more than the pool minimum
>    (`pool/config.json` → `minimum_deposit_wei`) for testing. Real deposits
>    are the user's explicit decision, not the agent's.
>
> ### What happened that led to these rules (lesson learned):
>
> During integration testing, two deposits (2 × 0.01 ETH) were made without
> testing withdrawal. The petal was then reinstalled (to add a new route),
> which replaced the secret store. Both notes were destroyed. The 0.02 ETH
> (~$38) is permanently locked in the 0xBOW pool. This was entirely
> preventable — the cycle should have been tested end-to-end with minimum
> funds before scaling, and the store should have been backed up before
> reinstalling.

This petal integrates the deployed **0xBOW Privacy Pools** protocol on Ethereum
mainnet. Entrypoint proxy `0x6818809eefce719e480a7526d76bd3e561526b46`; ETH pool
`0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb`.

It targets `bloom:route@0.1.0` and the canonical SDK/builder. Development uses
the ignored `local-petal` workspace link; a release must replace that path with
the immutable revision containing the private-input contract. It does not copy
WIT, SDK, or builder code.

## Non-negotiable live-funds rules

1. Read [WITHDRAWAL.md](WITHDRAWAL.md) before operating this petal.
2. Keep deposits at the current pool minimum until one complete
   deposit -> prove -> simulate -> approve -> withdraw -> verify cycle passes.
3. Never print, log, or transmit a note's `nullifier` or `secret`.
4. Verify an encrypted/offline note backup before changing or reinstalling a
   package. Bloom's best-effort private-store migration is not a backup.
5. Do not claim a deposit is proof-ready merely because its transaction mined
   or its cached status says `confirmed`.
6. Do not claim a withdrawal succeeded until its receipt, Pool `Withdrawn`
   event, spent nullifier, and proof outputs have been reconciled. A private
   relay additionally requires the Entrypoint `WithdrawalRelayed` event and a
   canonical finalized block. Do not query recipient balances.

Use the local `tools/privacy-pools` companion for encrypted backup/restore and
proof generation. Secrets never cross a VFS route and must never be requested
as chat or shell-argument input.

## Routes

| Route | Read | Write |
|-------|------|-------|
| `/petals/privacy-pools/status.json` | Health + self-documenting capabilities | — |
| `/petals/privacy-pools/protocol.json` | Mainnet constants, addresses, hashing scheme | — |
| `/petals/privacy-pools/pool/config.json` | Live pool config (min deposit, fees) | — |
| `/petals/privacy-pools/pool/state.json` | Live pool state (tree size, ASP root, scope) | — |
| `/petals/privacy-pools/deposits/<wallet>/<id>.json` | Read status (reconciles on-chain) | Stage ETH deposit |
| `/petals/privacy-pools/notes/<wallet>/<id>.json` | Public note view (no secrets) | — |
| `/petals/privacy-pools/recovery/<wallet>/<id>.json` | **Full note (nullifier + secret) for backup** | — |
| `/petals/privacy-pools/withdrawals/<wallet>/<id>.json` | Readiness, direct settlement, or redacted private-relay status | Stage a direct withdrawal, or advance a private destination ceremony |
| `/petals/privacy-pools/private/<wallet>/<id>.json` | Agent-blind deposit (returns only `{status, id}`) | Stage + auto-broadcast deposit |

## Recovery route

`/petals/privacy-pools/recovery/<wallet>/<id>.json` returns the **full note**
including `nullifier` and `secret`. This is the only way to export the
withdrawal proof. **Agents should NOT read this route** — it is for the
human user to back up their note. After reading, save the output offline
(file, paper, password manager). If the petal store is lost, this backup is
the only way to recover deposited funds.

## Private (agent-blind) route

`/petals/privacy-pools/private/<wallet>/<id>.json` stages + auto-broadcasts a
deposit internally, returning only `{status, id}`. The note stays in the
petal's secret store — no addresses, precommitments, or tx details are
surfaced. This lets an agent delegate deposits without seeing sensitive data.

**Important:** the agent-blind route still stores the note in the petal's
secret store. The same backup rules apply — read `/recovery/` after the
deposit and save the note offline.

## State machine

```
                WRITE (amount_wei, asset="eth")
                  │
                  ▼
             ┌─────────────┐
             │   staging   │ placeholder persisted, tx outbox call in flight
             └──────┬──────┘
                    │ tx_stage succeeds
                    ▼
             ┌─────────────┐
             │    staged   │ tx in outbox, awaiting owner approval + mining
             └──────┬──────┘
                    │ tx mined + Deposited log parsed
                    ▼
            ┌──────────────┐
            │   confirmed  │ label, value, commitment filled from receipt
            └──────────────┘

    Failure branches:
    staging ──(tx_stage fails)──▶ stage-failed ← same id can retry
    staged  ──(tx reverted)────▶ failed       ← terminal
```

### Next actions by status

| Status | Meaning | Next action |
|--------|---------|-------------|
| `staging` | Placeholder persisted, stage call outcome uncertain | Wait, then re-read. If stuck, use a new `<id>` or ask operator to inspect outbox. |
| `stage-failed` | Stage call definitively failed | Retry with same `<id>` + same `amount_wei`, or use a new `<id>`. |
| `staged` | Tx accepted by outbox | Direct owner to `approval_ceremony_url` if approval required. Poll with GET to reconcile. |
| `confirmed` | Tx mined and `Deposited` log parsed | Confirm that `value`, `label`, and `commitment` are all present, **read `/recovery/<wallet>/<id>.json` and save the note offline**, then apply every readiness gate in `WITHDRAWAL.md` before preparing withdrawal via `withdrawals/<wallet>/<id>.json`. |
| `failed` | Tx reverted | Terminal. Funds did not move. Use a new `<id>` to retry. |

If a mined deposit lacks `value`, `label`, or `commitment`, classify it as
**mined-unreconciled** regardless of the cached status string. Recover the
public fields from the receipt's `Deposited` log and verify the commitment
before attempting proof preparation.

### Error recovery

| Error message | Cause | Resolution |
|---------------|-------|------------|
| `amount_wei is not a decimal integer` | Non-numeric input | Provide a decimal string like `"1000000000000000000"` |
| `amount_wei must be greater than zero` | Zero amount | Provide a non-zero amount |
| `amount is below the pool minimum deposit` | Amount < pool min | Check `pool/config.json` for the minimum |
| `only asset "eth" is supported` | Non-ETH asset | Set `asset` to `"eth"` or omit it |
| `a deposit already exists for this id with a different amount` | Idempotency conflict | Use a new `<id>` |
| `a previous staging attempt did not complete cleanly` | Stale `staging` state | Use a new `<id>` or inspect the outbox |
| `deposit is not fully reconciled` | Mined/stored note lacks value, label, or commitment | Decode the `Deposited` receipt log, recompute the commitment, and persist the public fields |
| `receipt commitment does not match poseidon(...)` | Receipt tamper / hash divergence | Critical error — inspect the transaction manually |
| `deposit staging was denied by the host` | Host denied | Owner must approve via the ceremony URL |

## Canonical operation

`/petals/privacy-pools/deposits/<wallet>/<id>.json`

`<wallet>` is a Bloom wallet alias (resolved by the tx outbox). `<id>` is a
caller-defined durable idempotency key. Write body:

```json
{ "amount_wei": "1000000000000000000", "asset": "eth" }
```

`asset` is optional and only `"eth"` is supported. `amount_wei` is decimal wei
and becomes `msg.value`. The petal generates a fresh nullifier/secret, derives
`precommitment = poseidon([nullifier, secret])`, and stages
`Entrypoint.deposit(precommitment)` through `bloom:tx.outbox`. A write means the
deposit was staged and is awaiting owner approval / mining, not that it settled.

Reads reconcile against the outbox: once mined, the `Deposited` receipt log is
parsed to fill `label`, `value` (post vetting-fee), and `commitment`, and the
note's precommitment is checked against the emitted one.

## Secrets boundary

`nullifier` and `secret` are the only thing that lets the owner later withdraw.
They are persisted in the **secrets** store namespace and are never returned by
the `deposits/` or `notes/` routes. **The only route that exposes them is
`/recovery/<wallet>/<id>.json`** — intended for one-time human backup. Public
surfaces (`deposits/.../<id>.json`, `notes/.../<id>.json`) expose only
`commitment`, `label`, `value`, `precommitment`, `status`, and `spent`.

The precommitment is `Poseidon(nullifier, secret)`. The spent nullifier hash is
`Poseidon(nullifier)`. They are not interchangeable. Reads derive the latter
inside the petal and reconcile it against the pool without exposing it.

### Why the note must be backed up externally

The petal's secret store is keyed by the petal's **package hash**. When the
petal is reinstalled (new build, version bump, hash change), the old store
becomes inaccessible. Without an external backup (from the `/recovery/` route),
the deposit is permanently locked. This is a known design limitation of the
bloom petal store; future bloom versions should migrate stores across petal
updates.

## Safety validation

The petal enforces these checks before staging:

1. **Amount validation** — decimal parse + non-zero check
2. **Minimum deposit** — on-chain `assetConfig().minimumDeposit` check
3. **Idempotency** — `store_put_new` claims the `<id>` atomically; retry with same id is safe
4. **Partial-failure recovery** — `"staging"` placeholder persists before the stage call; `"stage-failed"` tombstones allow retry
5. **Emitter allow-list** — `Deposited` log only accepted from `POOL_ETH` or `ENTRYPOINT` (case-insensitive)
6. **Commitment integrity** — `poseidon([value, label, precommitment])` must match the emitted commitment (tamper guard)
7. **Precommitment ownership** — receipt precommitment must equal this note's precommitment

## Withdrawal operating boundary

The local companion owns secret backup/restore, ASP leaf fetching, artifact
verification, proof generation, replacement-note creation, and initial exact
simulation. It outputs public calldata only.

The writable withdrawal route supports the direct call shape with empty data.
It independently decodes and validates the public signals against private
state, verifies the signing wallet/processooor, rechecks the latest ASP root,
recomputes the replacement commitment, simulates, and stages through
`bloom:tx.outbox`. Reads reconcile the `Withdrawn` event and promote a non-zero
replacement note.

The route also supports a distinct `private-relay` mode. The agent-visible
request has no recipient. Bloom returns a local ceremony URL, binds the entered
address digest to a separately resolved passkey approval wallet, and releases
the value only to this petal. An omitted approval wallet is valid only when the
note wallet is passkey-gated or exactly one passkey wallet exists. The petal
persists the recipient in the secret namespace and exposes only redacted
lifecycle state. The local companion uses an fsynced secret journal, reuses the
same replacement material across proof retries, simulates the exact relay,
recovers lost responses by matching on-chain events, and waits for finalized
settlement. It must never print the recipient, proof payload, calldata,
transaction hash, or exact submission time. There is no `Entrypoint.withdraw`.

## Directory listings

The `deposits/`, `notes/`, and `withdrawals/` directory listings enumerate
wallets and ids through `store_list` in the public state namespace. Never list
or infer ids from the secret namespace.
The `recovery/` and `private/` routes intentionally expose no directory
listings — agents and clients must know exact `<wallet>` and `<id>` values.

## Capabilities

Declared in `petal.toml`: `bloom:store`, `bloom:tx.outbox`, `bloom:chain`,
`bloom:vfs.read` for resolving a direct signing wallet, and
`bloom:private-input` for the Privacy Pools-only recipient ceremony. No
`bloom:http` or `bloom:sign`; the tx outbox owns direct owner approval.

## Cryptographic provenance

`poseidon.rs` is a 1:1 port of `circomlibjs/src/poseidon_reference.js` with the
canonical BN254 constant tables (auto-generated into `poseidon_constants.rs`).
It is validated against published circomlib vectors (`poseidon([1,2])`,
`poseidon([1,2,3,4])`, `poseidon([1])`). `lean_imt.rs` is a 1:1 port of
`@zk-kit/lean-imt` and is validated against an oracle produced by that package.

## Development

Until the revised canonical Petal SDK is published and pinned, create the
ignored local workspace link used by both route manifests:

```sh
ln -s ../../petal local-petal
```

```sh
cargo fmt --manifest-path route/Cargo.toml --check
cargo test --manifest-path route/Cargo.toml --locked
cargo clippy --manifest-path route/Cargo.toml --locked --all-targets -- -D warnings
cd tools/privacy-pools && npm ci --ignore-scripts && npm test
npm run test:fork -- --note <secret-note-path> --deposit-status <public-status-path> --artifacts <artifact-dir>
scripts/build.sh                      # petal build --root .
scripts/check-route-architecture.sh   # source-level architecture check
```

Do not commit generated `.wasm`, `target/`, or `petal/privacy-pools/` output.
Never run a live-money deposit without explicit authorization and without
testing the full deposit → withdrawal cycle with minimum funds first.

## Integration smoke-test notes

`CHAIN = "mainnet"` is the identifier passed to `bloom:chain` reads and the tx
outbox. Current Bloom hosts canonicalize the `mainnet` alias to Ethereum. Keep
that alias behavior covered by integration tests if chain configuration
changes.

When `tx_inspect` proves mining but omits logs, the deposit and withdrawal read
paths fetch the canonical Ethereum receipt by transaction hash. A note remains
`mined-unreconciled` if that fallback is unavailable or fails integrity checks.
