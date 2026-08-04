# Privacy Pools Petal

A [Bloom Petal](https://github.com/bloom-directory/petal) that integrates the
deployed [0xBOW Privacy Pools](https://docs.privacypools.com/) protocol on
Ethereum mainnet — compliant, non-custodial private transfers via zero-knowledge
proofs and an Association Set Provider (ASP).

- **Entrypoint (proxy):** `0x6818809eefce719e480a7526d76bd3e561526b46`
- **PrivacyPool (ETH):** `0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb`

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

## Withdrawal proving boundary

Generating the withdrawal Groth16 proof needs the circuit wasm + a trusted-setup
zkey, runs for seconds, and must happen locally for privacy. That step stays
**out of the petal** (matching the official TypeScript SDK + relayer split). Use
`withdrawals/<wallet>/<id>.json` to get the prepared input, then prove and
submit with `snarkjs` / the official SDK.

## Canonical route

```text
/petals/privacy-pools/deposits/<wallet-alias>/<id>.json
```

Stage an ETH deposit:

```sh
bloom vfs write \
  /petals/privacy-pools/deposits/<wallet>/<id>.json \
  --data '{ "amount_wei": "1000000000000000000" }'
```

Read status (reconciles on-chain after mining):

```sh
bloom vfs cat /petals/privacy-pools/deposits/<wallet>/<id>.json
```

Public note view (no secrets):

```sh
bloom vfs cat /petals/privacy-pools/notes/<wallet>/<id>.json
```

Pool config and state:

```sh
bloom vfs cat /petals/privacy-pools/pool/config.json
bloom vfs cat /petals/privacy-pools/pool/state.json
```

A write only means the deposit was staged; only a later read returning
`status: "confirmed"` means it settled.

## Other routes

- `status.json` — petal health and capability summary.
- `protocol.json` — mainnet constants and hashing scheme.
- `pool/config.json`, `pool/state.json` — live pool reads via `bloom:chain`.
- `withdrawals/<wallet>/<id>.json` — withdrawal proof-input preparation.

## Capabilities

`bloom:store`, `bloom:tx.outbox`, `bloom:chain`. No raw HTTP, no signing
intents, no network allowlist.

## Development

```sh
cargo test --manifest-path route/Cargo.toml --locked
cargo clippy --manifest-path route/Cargo.toml --locked --all-targets -- -D warnings
scripts/build.sh     # petal build --root .
petal check --root .
```

Regenerating the Poseidon constants is not part of normal development; they are
checked in (`route/src/poseidon_constants.rs`) and were produced from
`circomlibjs/src/poseidon_constants.js`.

Do not run a live-money deposit without explicit authorization.
