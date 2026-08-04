# Privacy Pools Petal — operating contract

This petal integrates the deployed **0xBOW Privacy Pools** protocol on Ethereum
mainnet. Entrypoint proxy `0x6818809eefce719e480a7526d76bd3e561526b46`; ETH pool
`0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb`.

It targets `bloom:route@0.1.0` and the canonical SDK/builder pinned in
`petal-build.toml` (rev `b9fc22d6d8211bc41304b38b1ef8b5269c8035bd`). It does not
copy WIT, SDK, or builder code.

## Canonical operation

`/petals/privacy-pools/deposits/<wallet-alias>/<id>.json`

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
scripts/build.sh     # petal build --root .
petal check --root .
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
