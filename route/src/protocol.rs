//! Protocol constants and ABI selectors for the deployed 0xBOW Privacy Pools
//! on Ethereum mainnet. Addresses come from `docs.privacypools.com/deployments`.

use alloy_primitives::{Address, address};
use sha3::{Digest, Keccak256};

/// Bloom chain name used for `bloom:chain` reads and the tx outbox.
///
/// Bloom daemons expose mainnet Ethereum under the chain key `mainnet`
/// (verified against the live host: `/chains/ethereum/...` returns
/// "chain 'ethereum' not found", `/chains/mainnet/head/number` works).
/// TODO: make this configurable via a runtime setting so the petal is portable
/// across Bloom deployments that use different chain keys.
pub const CHAIN: &str = "mainnet";

/// Entrypoint (UUPS proxy). Deposit and relay target.
pub const ENTRYPOINT: Address = address!("6818809eefce719e480a7526d76bd3e561526b46");

/// PrivacyPool for native ETH.
pub const POOL_ETH: Address = address!("f241d57c6debae225c0f2e6ea1529373c9a9c9fb");

/// Sentinel used by the protocol for the native asset in `assetConfig`.
pub const NATIVE_ASSET: Address = address!("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE");

/// First 4 bytes of `keccak256(signature)` — the EVM function selector.
pub fn selector(signature: &str) -> [u8; 4] {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&keccak256(signature)[..4]);
    buf
}

/// `keccak256(data)`.
pub fn keccak256(data: &str) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data.as_bytes());
    let digest = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&digest);
    buf
}

// Entrypoint / PrivacyPool view selectors.
pub fn deposit_eth_selector() -> [u8; 4] {
    selector("deposit(uint256)")
}
pub fn deposit_erc20_selector() -> [u8; 4] {
    selector("deposit(address,uint256,uint256)")
}
pub fn asset_config_selector() -> [u8; 4] {
    selector("assetConfig(address)")
}
pub fn scope_to_pool_selector() -> [u8; 4] {
    selector("scopeToPool(uint256)")
}
pub fn latest_root_selector() -> [u8; 4] {
    selector("latestRoot()")
}
pub fn scope_selector() -> [u8; 4] {
    selector("SCOPE()")
}
pub fn asset_selector() -> [u8; 4] {
    selector("ASSET()")
}
pub fn current_tree_size_selector() -> [u8; 4] {
    selector("currentTreeSize()")
}
pub fn current_root_selector() -> [u8; 4] {
    selector("currentRoot()")
}
pub fn current_tree_depth_selector() -> [u8; 4] {
    selector("currentTreeDepth()")
}
pub fn nullifier_hashes_selector() -> [u8; 4] {
    selector("nullifierHashes(uint256)")
}
pub fn withdraw_selector() -> [u8; 4] {
    selector("withdraw((address,bytes),(uint256[2],uint256[2][2],uint256[2],uint256[8]))")
}

/// `Deposited(address indexed _depositor, uint256 _commitment, uint256 _label,
/// uint256 _value, uint256 _precommitmentHash)` topic0
/// (see `IPrivacyPool.sol:39`). Only `_depositor` is indexed; the other four
/// fields travel in the log `data`. Verified topic0 =
/// `0xe3b53cd1a44fbf11535e145d80b8ef1ed6d57a73bf5daa7e939b6b01657d6549`.
pub fn deposited_topic0() -> [u8; 32] {
    keccak256("Deposited(address,uint256,uint256,uint256,uint256)")
}

pub fn withdrawn_topic0() -> [u8; 32] {
    keccak256("Withdrawn(address,uint256,uint256,uint256)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_are_stable() {
        // Verified via `cast sig` against the canonical signatures.
        assert_eq!(deposit_eth_selector(), [0xb6, 0xb5, 0x5f, 0x25]);
        assert_eq!(deposit_erc20_selector(), [0x0e, 0xfe, 0x6a, 0x8b]);
        assert_eq!(asset_config_selector(), [0xd6, 0xdb, 0xaf, 0x58]);
        assert_eq!(scope_to_pool_selector(), [0xad, 0xec, 0xa3, 0xdc]);
        assert_eq!(latest_root_selector(), [0xd7, 0xb0, 0xfe, 0xf1]);
        assert_eq!(scope_selector(), [0x33, 0xd0, 0x92, 0x00]);
        assert_eq!(asset_selector(), [0x48, 0x00, 0xd9, 0x7f]);
        assert_eq!(current_tree_size_selector(), [0xa8, 0xf0, 0xf9, 0x5a]);
    }

    #[test]
    fn entrypoint_and_pool_are_mainnet_constants() {
        assert_eq!(
            format!("{ENTRYPOINT:?}"),
            "0x6818809eefce719e480a7526d76bd3e561526b46"
        );
        assert_eq!(
            format!("{POOL_ETH:?}"),
            "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb"
        );
    }

    /// Canonical topic0 for the pool's `Deposited` event
    /// (`IPrivacyPool.sol:39` — only `_depositor` is indexed). Verified via
    /// `cast keccak "Deposited(address,uint256,uint256,uint256,uint256)"`.
    #[test]
    fn deposited_topic0_matches_canonical_event() {
        assert_eq!(
            format!("0x{}", hex::encode(deposited_topic0())),
            "0xe3b53cd1a44fbf11535e145d80b8ef1ed6d57a73bf5daa7e939b6b01657d6549"
        );
    }
}
