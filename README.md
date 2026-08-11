# Privacy Pools Petal

A [Bloom Petal](https://github.com/bloom-directory/petal) that integrates the
deployed [0xBOW Privacy Pools](https://docs.privacypools.com/) protocol on
Ethereum mainnet — compliant, non-custodial private transfers via zero-knowledge
proofs and an Association Set Provider (ASP).

- **Entrypoint (proxy):** `0x6818809eefce719e480a7526d76bd3e561526b46`
- **PrivacyPool (ETH):** `0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb`
- **Chain:** Ethereum mainnet

## What this petal does

- Generates private deposit notes (`nullifier`, `secret`) with the host RNG.
- Derives `precommitment = poseidon([nullifier, secret])` and stages
  `Entrypoint.deposit(precommitment)` with ETH value via Bloom's tx outbox.
- Stores the private note in the **secrets** store and a public status in the
  **state** store.
- Reads back and reconciles the on-chain `Deposited` event to fill the note's
  `label`, committed `value`, and `commitment`.
- Exposes pool reads (`assetConfig`, `currentTreeSize`, ASP `latestRoot`).
- Prepares the withdrawal Groth16 proof input (note, nullifier hash, context,
  roots, witness schema).

The BN254 Poseidon hash and the LeanIMT are ported from `circomlibjs` and
`@zk-kit/lean-imt` respectively, and are validated against their published test
vectors and an upstream oracle.

## Supported assets

| Asset | Symbol | Decimals | Pool Address |
|-------|--------|----------|-------------|
| Native ETH | ETH | 18 | `0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb` |

ERC-20 deposits are not supported in this release.

## Route table

| Route | Method | Purpose |
|-------|--------|---------|
| `status.json` | GET | Petal health + self-documenting capability summary |
| `protocol.json` | GET | Mainnet constants, addresses, hashing scheme |
| `pool/config.json` | GET | Live pool config (minimum deposit, fees) |
| `pool/state.json` | GET | Live pool state (tree size, ASP root, scope) |
| `deposits/<wallet>/<id>.json` | GET | Read deposit status (reconciles on-chain) |
| `deposits/<wallet>/<id>.json` | WRITE | Stage a new ETH deposit |
| `notes/<wallet>/<id>.json` | GET | Public note view (no secrets) |
| `withdrawals/<wallet>/<id>.json` | GET | Withdrawal proof-input preparation |

Directory listings (`deposits/`, `notes/`, `withdrawals/` and their
`<wallet>/` children) return empty — an agent must know exact `<wallet>` and
`<id>` values. This is a known gap (no `store_list` in the SDK); see AGENTS.md
for workaround.

## Deposit write body

```json
{
  "amount_wei": "1000000000000000000",
  "asset": "eth"
}
```

- **`amount_wei`** (required): decimal wei amount. Becomes `msg.value`. Must be
  ≥ the pool's minimum deposit (check `pool/config.json` first).
- **`asset`** (optional): only `"eth"` is supported. Omitting it defaults to ETH.

`<wallet>` is a Bloom wallet alias. `<id>` is a caller-chosen durable
idempotency key (e.g. `"deposit-001"`).

### Example

```sh
bloom vfs write \
  /petals/privacy-pools/deposits/my-wallet/deposit-001.json \
  --data '{ "amount_wei": "1000000000000000000" }'
```

## Transaction lifecycle

```
                WRITE
                  │
                  ▼
             ┌─────────┐
             │ staging │ ← placeholder persisted, tx outbox call in flight
             └────┬────┘
                  │ tx_stage succeeds
                  ▼
             ┌─────────┐
             │  staged │ ← tx in outbox, awaiting owner approval + mining
             └────┬────┘
                  │ tx mined, Deposited log parsed
                  ▼
            ┌──────────┐
            │ confirmed│ ← label, value, commitment filled
            └──────────┘

    Error branches:
    staging ──(tx_stage fails)──▶ stage-failed ← retryable with same id
    staged  ──(tx reverted)────▶ failed
```

A WRITE means the deposit was **staged**, not settled. Only a later GET
returning `status: "confirmed"` means it settled.

### Idempotency contract

- Same `<id>` + same `amount_wei` + `"staged"`/`"confirmed"` status → returns
  the existing deposit (safe retry).
- Same `<id>` + same `amount_wei` + `"stage-failed"` status → retries the
  deposit.
- Same `<id>` + different `amount_wei` → error `-3` (conflict, use new id).
- Same `<id>` + `"staging"` status → error `-3` (incomplete, inspect outbox).

## Deposit status fields (GET response)

| Field | Type | Present when | Description |
|-------|------|-------------|-------------|
| `status` | string | always | `staging` / `staged` / `confirmed` / `failed` / `stage-failed` |
| `amount_wei` | string | always | Decimal wei sent |
| `precommitment` | string | always | `0x`-hex poseidon([nullifier, secret]) |
| `tx` | object | always | `{ chain, outbox_id, tx_hash? }` |
| `value` | string | confirmed | Decimal wei committed (post vetting-fee) |
| `label` | string | confirmed | `0x`-hex keccak256(scope, nonce) |
| `commitment` | string | confirmed | `0x`-hex poseidon([value, label, precommitment]) |
| `spent` | bool | always | Whether this note was withdrawn (always false in-petal) |
| `approval_action_id` | string | staged | Owner-approval action ID |
| `approval_expires_ms` | integer | staged | Expiry of the owner-visible Bloom approval action |

## Withdrawal proving boundary

Generating the withdrawal Groth16 proof needs the circuit wasm + a trusted-setup
zkey, runs for seconds, and must happen locally for privacy. That step stays
**out of the petal** (matching the official TypeScript SDK + relayer split).

`withdrawals/<wallet>/<id>.json` returns everything an external prover needs:

- Note's public commitment, label, value, nullifier hash (precommitment)
- Example withdrawal context hash (with zero-address recipient — caller
  recomputes with the real recipient)
- Current ASP root and state tree size (best-effort live reads)
- Full witness schema: public inputs, private signals, Merkle proof slots

The Merkle proof fields (`stateSiblings`, `stateIndex`, `ASPSiblings`,
`ASPIndex`) are `null` — generating them requires syncing the pool's
`Deposited` events into a LeanIMT and querying the ASP set, which belongs in a
data service, not a route handler. The response includes instructions for
filling these fields.

## Secrets boundary

`nullifier` and `secret` are the only thing that lets the owner later withdraw.
They are persisted in the **secrets** store namespace and are **never** returned
by any read route. Public surfaces expose only `commitment`, `label`, `value`,
`precommitment`, `status`, and `spent`.

## Capabilities

`bloom:store`, `bloom:tx.outbox`, `bloom:chain`. No raw HTTP (`bloom:http`),
no signing intents (`bloom:sign`), no network allowlist (`net.allow`).

## Development

```sh
cargo fmt --manifest-path route/Cargo.toml --check
cargo test --manifest-path route/Cargo.toml --locked
cargo clippy --manifest-path route/Cargo.toml --locked --all-targets -- -D warnings
scripts/build.sh                      # petal build --root .
scripts/check-route-architecture.sh   # source-level architecture check
```

Do not run a live-money deposit without explicit authorization.
