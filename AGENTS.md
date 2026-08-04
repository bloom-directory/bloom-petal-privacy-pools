# Privacy Pools Petal — operating contract

This petal integrates the deployed **0xBOW Privacy Pools** protocol on Ethereum
mainnet. Entrypoint proxy `0x6818809eefce719e480a7526d76bd3e561526b46`; ETH pool
`0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb`.

It targets `bloom:route@0.1.0` and the canonical SDK/builder pinned in
`petal-build.toml` (rev `b9fc22d6d8211bc41304b38b1ef8b5269c8035bd`). It does not
copy WIT, SDK, or builder code.

## Routes

| Route | Read | Write |
|-------|------|-------|
| `/petals/privacy-pools/status.json` | Health + self-documenting capabilities | — |
| `/petals/privacy-pools/protocol.json` | Mainnet constants, addresses, hashing scheme | — |
| `/petals/privacy-pools/pool/config.json` | Live pool config (min deposit, fees) | — |
| `/petals/privacy-pools/pool/state.json` | Live pool state (tree size, ASP root, scope) | — |
| `/petals/privacy-pools/deposits/<wallet>/<id>.json` | Read status (reconciles on-chain) | Stage ETH deposit |
| `/petals/privacy-pools/notes/<wallet>/<id>.json` | Public note view (no secrets) | — |
| `/petals/privacy-pools/withdrawals/<wallet>/<id>.json` | Withdrawal proof-input prep | — |

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
| `confirmed` | Tx mined, `Deposited` log parsed | Deposit settled. Read `notes/<wallet>/<id>.json` for the public note. Prepare withdrawal via `withdrawals/<wallet>/<id>.json`. |
| `failed` | Tx reverted | Terminal. Funds did not move. Use a new `<id>` to retry. |

### Error recovery

| Error message | Cause | Resolution |
|---------------|-------|------------|
| `amount_wei is not a decimal integer` | Non-numeric input | Provide a decimal string like `"1000000000000000000"` |
| `amount_wei must be greater than zero` | Zero amount | Provide a non-zero amount |
| `amount is below the pool minimum deposit` | Amount < pool min | Check `pool/config.json` for the minimum |
| `only asset "eth" is supported` | Non-ETH asset | Set `asset` to `"eth"` or omit it |
| `a deposit already exists for this id with a different amount` | Idempotency conflict | Use a new `<id>` |
| `a previous staging attempt did not complete cleanly` | Stale `staging` state | Use a new `<id>` or inspect the outbox |
| `deposit is not confirmed yet; reconcile it first` | Withdrawal prep before confirmation | Poll `deposits/<wallet>/<id>.json` until `status: "confirmed"` |
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
any read route. Public surfaces (`deposits/.../<id>.json`, `notes/.../<id>.json`)
expose only `commitment`, `label`, `value`, `precommitment` (== the spent
nullifier hash), `status`, and `spent`.

## Safety validation

The petal enforces these checks before staging:

1. **Amount validation** — decimal parse + non-zero check
2. **Minimum deposit** — on-chain `assetConfig().minimumDeposit` check
3. **Idempotency** — `store_put_new` claims the `<id>` atomically; retry with same id is safe
4. **Partial-failure recovery** — `"staging"` placeholder persists before the stage call; `"stage-failed"` tombstones allow retry
5. **Emitter allow-list** — `Deposited` log only accepted from `POOL_ETH` or `ENTRYPOINT` (case-insensitive)
6. **Commitment integrity** — `poseidon([value, label, precommitment])` must match the emitted commitment (tamper guard)
7. **Precommitment ownership** — receipt precommitment must equal this note's precommitment

## Withdrawal proving is out-of-petal

Withdrawals require a Groth16 proof (`snarkjs.groth16.fullProve`) over the
withdrawal circuit, which needs the circuit wasm + a trusted-setup zkey and runs
for seconds. It is also privacy-critical that proving happens locally (a remote
prover learns the deposit linkage). Therefore the petal **prepares** the
withdrawal proof input (at `withdrawals/<wallet>/<id>.json`) — note commitment,
nullifier hash, withdrawal context, current roots, and the exact witness schema
— but does not generate the proof. The state/ASP Merkle proofs require syncing
`Deposited` events into a LeanIMT; that bulk sync belongs in a data service, not
a route handler, so those two fields are returned as `null` with instructions.

## Directory listing gap

The `deposits/`, `notes/`, and `withdrawals/` directory listings (including
`<wallet>/` children) return empty — the SDK does not expose `store_list`.
Agents and clients must know exact `<wallet>` and `<id>` values. A transaction
history view requires an external indexer or a separate data service.

## Capabilities

Declared in `petal.toml`: `bloom:store`, `bloom:tx.outbox`, `bloom:chain`. No
`bloom:http` (all reads go through `bloom:chain`), no `bloom:sign` (the tx
outbox owns owner approval), no `net.allow` entries, no signing intents.

## Route/controller/module shape

- `route/files/**/*.rs` are controllers: route params, list/read/write
  selection, small responses. Each builds as one WASM component.
- Domain code lives under `route/src/`: `field`, `poseidon`,
  `poseidon_constants`, `commitment`, `lean_imt`, `protocol`, `chain`, `types`,
  `notes`, `deposit`, `withdrawal`.
- Use the canonical `petal` SDK helpers (`petal::param`, `petal::is_safe_segment`,
  `petal::write_spec`, `petal::static_read_spec`, `petal::store_read_spec`).
  `RouteSpec::file()`/`writable()`/`ttl()` are private — compose via the public
  spec constructors and `.caps(...)`.

## Cryptographic provenance

`poseidon.rs` is a 1:1 port of `circomlibjs/src/poseidon_reference.js` with the
canonical BN254 constant tables (auto-generated into `poseidon_constants.rs`).
It is validated against published circomlib vectors (`poseidon([1,2])`,
`poseidon([1,2,3,4])`, `poseidon([1])`). `lean_imt.rs` is a 1:1 port of
`@zk-kit/lean-imt` and is validated against an oracle produced by that package.

## Development

```sh
cargo fmt --manifest-path route/Cargo.toml --check
cargo test --manifest-path route/Cargo.toml --locked
cargo clippy --manifest-path route/Cargo.toml --locked --all-targets -- -D warnings
scripts/build.sh                      # petal build --root .
scripts/check-route-architecture.sh   # source-level architecture check
```

Do not commit generated `.wasm`, `target/`, or `petal/privacy-pools/` output.
Never run a live-money deposit without explicit authorization.

## Integration smoke-test notes

`CHAIN = "mainnet"` is the identifier passed to `bloom:chain` reads and the tx
outbox. This matches the bloom host's canonical mainnet key (verified against
the live host: `/chains/ethereum/...` returns "chain 'ethereum' not found",
`/chains/mainnet/head/number` works). If a different host deployment resolves
mainnet Ethereum under another key, adjust the single constant in
`route/src/protocol.rs`. The `tx_inspect` receipt is expected to carry a
standard `logs` array; if the host shape differs, the deposit still stages and
settles, but `label`/`value`/`commitment` will not be auto-filled until the
parser is aligned.
