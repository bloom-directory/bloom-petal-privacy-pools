//! On-chain reads through Bloom's `bloom:chain` import (`petal::sdk::chain_read`).
//!
//! `chain_read` forwards an EVM RPC `method` + JSON `params` to the configured
//! provider for the chain and returns the raw result as a JSON string. For
//! `eth_call` that is a `"0x..."` hex string of the return data.

use alloy_primitives::{Address, U256};

use crate::protocol::{CHAIN, ENTRYPOINT, POOL_ETH};

fn eth_call(to: Address, data: &[u8], label: &str) -> Result<Vec<u8>, String> {
    let params = serde_json::json!([
        { "to": format!("{to:?}"), "data": format!("0x{}", hex::encode(data)) },
        "latest"
    ])
    .to_string();
    let result = petal::sdk::chain_read(CHAIN, "eth_call", &params).map_err(|e| e.message())?;
    let s: String = serde_json::from_str(&result)
        .map_err(|_| format!("{label}: RPC result is not a string"))?;
    let body = s
        .strip_prefix("0x")
        .ok_or(format!("{label}: result is not 0x-prefixed"))?;
    hex::decode(body).map_err(|e| format!("{label}: hex decode failed: {e}"))
}

fn call_view(selector: &[u8; 4], label: &str, to: Address) -> Result<Vec<u8>, String> {
    eth_call(to, selector, label)
}

fn call_view_addr(
    selector: &[u8; 4],
    arg: Address,
    label: &str,
    to: Address,
) -> Result<Vec<u8>, String> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(selector);
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(arg.as_ref());
    data.extend_from_slice(&word);
    eth_call(to, &data, label)
}

fn u256_word(bytes: &[u8]) -> Result<U256, String> {
    if bytes.len() < 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes[..32]);
    Ok(U256::from_be_bytes(buf))
}

fn addr_word(bytes: &[u8]) -> Result<Address, String> {
    if bytes.len() < 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    Address::try_from(&bytes[12..32]).map_err(|e| format!("address decode: {e}"))
}

/// Entrypoint `assetConfig(asset)` → `(pool, minDeposit, vettingFeeBPS, maxRelayFeeBPS)`.
pub fn asset_config(asset: Address) -> Result<(Address, U256, U256, U256), String> {
    let out = call_view_addr(
        &crate::protocol::asset_config_selector(),
        asset,
        "assetConfig",
        ENTRYPOINT,
    )?;
    if out.len() < 128 {
        return Err(format!(
            "assetConfig returned {} bytes, expected 128",
            out.len()
        ));
    }
    let pool = addr_word(&out[0..32])?;
    let min = u256_word(&out[32..64])?;
    let vet = u256_word(&out[64..96])?;
    let max_relay = u256_word(&out[96..128])?;
    Ok((pool, min, vet, max_relay))
}

/// PrivacyPool `SCOPE()`.
pub fn pool_scope(pool: Address) -> Result<U256, String> {
    let out = call_view(&crate::protocol::scope_selector(), "SCOPE", pool)?;
    u256_word(&out)
}

/// PrivacyPool `ASSET()`.
pub fn pool_asset(pool: Address) -> Result<Address, String> {
    let out = call_view(&crate::protocol::asset_selector(), "ASSET", pool)?;
    addr_word(&out)
}

/// PrivacyPool `currentTreeSize()` (next leaf index / number of leaves).
pub fn current_tree_size(pool: Address) -> Result<U256, String> {
    let out = call_view(
        &crate::protocol::current_tree_size_selector(),
        "currentTreeSize",
        pool,
    )?;
    u256_word(&out)
}

/// Entrypoint `latestRoot()` → current ASP root.
pub fn latest_asp_root() -> Result<U256, String> {
    let out = call_view(
        &crate::protocol::latest_root_selector(),
        "latestRoot",
        ENTRYPOINT,
    )?;
    u256_word(&out)
}

/// Entrypoint `scopeToPool(scope)` → pool address.
pub fn scope_to_pool(scope: U256) -> Result<Address, String> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&crate::protocol::scope_to_pool_selector());
    data.extend_from_slice(&scope.to_be_bytes::<32>());
    let out = eth_call(ENTRYPOINT, &data, "scopeToPool")?;
    addr_word(&out)
}

/// Resolved ETH-pool view: the canonical ETH pool address + its scope.
pub fn eth_pool() -> (Address, U256) {
    (POOL_ETH, U256::ZERO) // scope is filled lazily by callers via pool_scope
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    #[test]
    fn u256_word_roundtrip() {
        let x = U256::from(0xdeadbeefu64);
        let mut buf = vec![0u8; 32];
        buf[28..32].copy_from_slice(&x.to_be_bytes::<32>()[28..32]);
        assert_eq!(u256_word(&buf).unwrap(), x);
    }

    #[test]
    fn eth_pool_constant_is_canonical() {
        let (pool, _) = eth_pool();
        assert_eq!(
            format!("{pool:?}"),
            "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb"
        );
    }
}
