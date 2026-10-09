# Privacy Pools Petal

A Bloom petal for the deployed 0xBOW Privacy Pools protocol on Ethereum
mainnet.

- Entrypoint: `0x6818809eefce719e480a7526d76bd3e561526b46`
- Native ETH PrivacyPool: `0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb`
- Supported asset: native ETH

## Capabilities

- Generate private deposit notes with the Bloom host RNG.
- Stage `Entrypoint.deposit(precommitment)` through Bloom's transaction outbox.
- Reconcile `Deposited` logs, including a direct-RPC fallback for older Bloom
  receipts that omitted logs.
- Reconcile `spent` from
  `PrivacyPool.nullifierHashes(Poseidon(nullifier))` without exposing secrets.
- Enumerate wallets and deposit ids from the public state namespace.
- Provide a local encrypted note backup/restore and official-SDK prover tool.
- Validate, simulate, stage, and reconcile direct ETH withdrawals through
  Bloom's normal owner-approval ceremony.
- Start a private relayed withdrawal through VFS without putting the recipient,
  proof, calldata, relayer payload, or transaction hash in an agent-visible
  route. The owner supplies the recipient in a one-shot loopback form opened by
  the Privacy Pools companion.

ERC-20 pools are not implemented.

## Routes

| Route | Method | Purpose |
|---|---|---|
| `status.json` | GET | Health and capability summary |
| `protocol.json` | GET | Addresses, hashes, and supported call shapes |
| `pool/config.json` | GET | Live minimum deposit and fee configuration |
| `pool/state.json` | GET | Live tree size, roots, and scope |
| `deposits/<wallet>/<index>/<id>.json` | GET | Reconcile and read deposit state |
| `deposits/<wallet>/<index>/<id>.json` | WRITE | Stage a new ETH deposit |
| `notes/<wallet>/<index>/<id>.json` | GET | Public note view with no secrets |
| `withdrawals/<wallet>/<index>/<id>.json` | GET | Readiness or staged/settled withdrawal state |
| `withdrawals/<wallet>/<index>/<id>.json` | WRITE | Stage a direct withdrawal, or record public intent for a recipient-private relay |

`<wallet>/<index>` selects one Bloom account. Bloom lists wallets and accounts
and keeps a separate private store for each account; the account's own records
list its ids. Listings never inspect the secret namespace.

## Deposit

```sh
bloom vfs write \
  /petals/privacy-pools/deposits/my-wallet/0/deposit-001.json \
  --data '{"amount_wei":"10000000000000000","asset":"eth"}'
```

`amount_wei` is decimal wei and must meet the live pool minimum. The caller id
is a durable idempotency key. A successful write means the transaction was
staged, not mined.

Deposit lifecycle:

```text
staging -> staged -> confirmed
    |          |
    |          +-> failed/reverted
    +-> stage-failed (same id and amount may retry)
```

A confirmed record includes `value` (post-vetting-fee), `label`, and
`commitment`. Reads self-heal these fields from the canonical receipt when
possible.

## Backups and withdrawals

The `nullifier` and `secret` are the ownership credential. Package migration is
not a backup. Direct withdrawal staging requires verified encrypted backups for
the original note and the circuit's replacement note.

Install the pinned local companion:

```sh
cd tools/privacy-pools
npm ci --ignore-scripts
npm test
```

It supports:

```text
bloom-privacy-pools backup
bloom-privacy-pools restore
bloom-privacy-pools verify-artifacts
bloom-privacy-pools prepare
bloom-privacy-pools relay-private
```

`prepare` uses `@0xbow/privacy-pools-core-sdk@1.4.0`, verifies the official
withdrawal artifact hashes, fetches ordered ASP/state leaves, proves locally,
simulates, backs up replacement secrets, and outputs a public write body for
the withdrawal route. The account that holds the note signs the withdrawal,
so its address is the processooor encoded in the proof.

For a recipient-private withdrawal, the VFS request contains mode, replacement
id, and an optional amount. Running `relay-private` opens a short-lived form on
`127.0.0.1`; the owner enters the destination there and it is written directly
to the companion's mode-`0600` retry journal, never to VFS or stdout. The
companion then necessarily sends the destination to the configured HTTPS
relayer, and finalized settlement publishes it in the on-chain
`WithdrawalRelayed` event. “Recipient-private” here means hidden from ordinary
agent-visible surfaces, not hidden from the relayer or Ethereum. The resumable
companion precomputes before requesting the short-lived quote, proves with
`processooor = Entrypoint`, exactly simulates, recovers lost responses from
chain events, waits for finality, and prints only coarse redacted status.

The petal decodes and checks that public body again, including the note's spent
nullifier, withdrawn value, replacement commitment, context, latest ASP root,
signing address, and exact `eth_call`, before it stages anything.

See [WITHDRAWAL.md](WITHDRAWAL.md) for the complete commands and settlement
contract.

## Important protocol distinctions

- Precommitment: `Poseidon(nullifier, secret)`.
- Spent nullifier hash: `Poseidon(nullifier)`.
- Commitment: `Poseidon(value, label, precommitment)`.
- Direct submission: `PrivacyPool.withdraw(withdrawal, proof)`.
- Relayed submission: `Entrypoint.relay(withdrawal, proof, scope)`.
- `Entrypoint.withdraw` does not exist.

The preview leaves `context` null until a real processooor is selected; it does
not emit a zero-address value that could be mistaken for usable proof input.

## Capabilities and security boundary

Declared host capabilities are `bloom:store`, `bloom:tx.outbox`,
`bloom:chain`, and `bloom:vfs.read`. VFS read is used only to resolve the
selected account's address for a direct withdrawal. The Wasm petal has no raw HTTP or signing
capability. Direct owner approval remains in Bloom's outbox; private recipient
collection and relay submission are performed by the local companion.

Secrets are never returned by a VFS route. The companion binds its input form
only to loopback, protects it with a random one-use URL token, reads the active
local secret store, and accepts passphrases only via a mode-`0600` file. The
form also refuses a request whose `Origin` is not its own and whose `Host` is
not `127.0.0.1:<port>`, so another web page or a rebound DNS name cannot reach
it.

None of that is a defence against another process on the same OS account. The
one-use token is handed to the browser on its command line, so anything that
can read the local process list can read the token and post its own address
before the owner does. State the boundary precisely: this hides the destination
from an agent driving VFS, and a process with shell access to the same account
can **substitute** the destination, not merely learn it.

## Development

```sh
cargo fmt --manifest-path route/Cargo.toml --check
cargo test --manifest-path route/Cargo.toml --locked
cargo clippy --manifest-path route/Cargo.toml --locked --all-targets -- -D warnings
cd tools/privacy-pools && npm ci --ignore-scripts && npm test
scripts/build.sh
scripts/check-route-architecture.sh
```

Do not run a live-money deposit or withdrawal without explicit authorization.
