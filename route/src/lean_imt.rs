//! Lean Incremental Merkle Tree (LeanIMT), ported 1:1 from
//! `@zk-kit/lean-imt` (`src/lean-imt.ts`). The Privacy Pools state tree and the
//! Association Set Provider (ASP) tree are both LeanIMTs whose internal node
//! hash is `poseidon([left, right])`.
//!
//! Properties (from the upstream class docstring):
//!   * binary, zero-less, dynamic depth;
//!   * when a node has only a left child, the node takes the child's value;
//!   * the last level always holds a single element, the root.
//!
//! This is needed only to *prepare* a withdrawal proof input (state/ASP merkle
//! proofs and roots). The final Groth16 proof itself is generated out-of-petal.

use alloy_primitives::U256;

use crate::poseidon::hash2;

fn hash(left: U256, right: U256) -> U256 {
    hash2(left, right)
}

/// `ceil(log2(n))` for `n >= 1`, with `ceil_log2(1) == 0`.
fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        32 - (n as u32 - 1).leading_zeros() as usize
    }
}

/// A faithful LeanIMT. Nodes use `Option` to mirror the upstream sparse-array
/// ("holes") storage: a missing slot means "this node equals its left child".
#[derive(Clone, Debug, Default)]
pub struct LeanImt {
    nodes: Vec<Vec<Option<U256>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeanImtProof {
    pub root: U256,
    pub leaf: U256,
    pub index: usize,
    pub siblings: Vec<U256>,
}

impl LeanImt {
    pub fn new() -> Self {
        Self {
            nodes: vec![vec![]],
        }
    }

    pub fn from_leaves(leaves: &[U256]) -> Self {
        let mut tree = Self::new();
        for &leaf in leaves {
            tree.insert(leaf);
        }
        tree
    }

    /// Tree depth = number of levels - 1.
    pub fn depth(&self) -> usize {
        self.nodes.len() - 1
    }

    pub fn size(&self) -> usize {
        self.nodes[0].len()
    }

    pub fn leaves(&self) -> Vec<U256> {
        self.nodes[0].iter().copied().flatten().collect()
    }

    pub fn root(&self) -> Option<U256> {
        let top = self.nodes.last()?;
        top.first().copied().flatten()
    }

    fn get(&self, level: usize, index: usize) -> Option<U256> {
        self.nodes.get(level)?.get(index).copied().flatten()
    }

    fn set(&mut self, level: usize, index: usize, value: U256) {
        while self.nodes[level].len() <= index {
            self.nodes[level].push(None);
        }
        self.nodes[level][index] = Some(value);
    }

    pub fn insert(&mut self, leaf: U256) {
        if self.depth() < ceil_log2(self.size() + 1) {
            self.nodes.push(Vec::new());
        }
        let mut node = leaf;
        let mut index = self.size();
        for level in 0..self.depth() {
            self.set(level, index, node);
            if index & 1 == 1 {
                let sibling = self
                    .get(level, index - 1)
                    .expect("left sibling must exist for a right node");
                node = hash(sibling, node);
            }
            index >>= 1;
        }
        let depth = self.depth();
        self.nodes[depth] = vec![Some(node)];
    }

    pub fn index_of(&self, leaf: U256) -> Option<usize> {
        self.nodes[0].iter().position(|slot| slot == &Some(leaf))
    }

    /// Generate a LeanIMT merkle proof, mirroring `LeanIMT.generateProof`.
    pub fn proof(&self, index: usize) -> Option<LeanImtProof> {
        if index >= self.size() {
            return None;
        }
        let leaf = self.get(0, index)?;
        let mut siblings: Vec<U256> = Vec::new();
        let mut path: Vec<u32> = Vec::new();
        let mut idx = index;
        for level in 0..self.depth() {
            let is_right = idx & 1;
            let sibling_index = if is_right == 1 { idx - 1 } else { idx + 1 };
            if let Some(sibling) = self.get(level, sibling_index) {
                path.push(is_right as u32);
                siblings.push(sibling);
            }
            idx >>= 1;
        }
        // Upstream: index = parseInt(path.reverse().join(""), 2) — MSB first
        // over the levels that actually contributed a sibling.
        let mut proof_index = 0usize;
        for &bit in path.iter().rev() {
            proof_index = (proof_index << 1) | bit as usize;
        }
        Some(LeanImtProof {
            root: self.root()?,
            leaf,
            index: proof_index,
            siblings,
        })
    }
}

/// Verify a LeanIMT proof with the canonical node hash. Mirrors
/// `LeanIMT.verifyProof`.
pub fn verify_proof(proof: &LeanImtProof) -> bool {
    let LeanImtProof {
        root,
        leaf,
        siblings,
        index,
    } = proof;
    let mut node = *leaf;
    for (i, sibling) in siblings.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            node = hash(*sibling, node);
        } else {
            node = hash(node, *sibling);
        }
    }
    node == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<U256> {
        (0..n).map(|i| U256::from(i as u64 + 1)).collect()
    }

    #[test]
    fn empty_and_single_leaf() {
        let t = LeanImt::new();
        assert_eq!(t.size(), 0);
        assert!(t.root().is_none());
        let mut t = LeanImt::new();
        t.insert(U256::from(7));
        assert_eq!(t.root(), Some(U256::from(7)));
        assert_eq!(t.depth(), 0);
    }

    #[test]
    fn proofs_self_verify_across_sizes() {
        for n in [2usize, 3, 4, 5, 7, 8, 9, 16, 17, 31] {
            let tree = LeanImt::from_leaves(&leaves(n));
            for i in 0..n {
                let proof = tree.proof(i).expect("proof");
                assert_eq!(proof.leaf, leaves(n)[i]);
                assert!(verify_proof(&proof), "proof {i} in tree of {n} failed");
            }
        }
    }

    #[test]
    fn root_is_stable_under_rebuild() {
        let l = leaves(12);
        let r1 = LeanImt::from_leaves(&l).root();
        let r2 = LeanImt::from_leaves(&l).root();
        assert_eq!(r1, r2);
    }

    /// Validate the port against an oracle produced by the real
    /// `@zk-kit/lean-imt` (using this crate's same BN254 Poseidon as the node
    /// hash). Generated by `tests/oracle.js`.
    #[test]
    fn matches_zk_kit_oracle() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/leanimt_oracle.json");
        let text = std::fs::read_to_string(path).expect("oracle json present");
        let v: serde_json::Value = serde_json::from_str(&text).expect("oracle parses");

        // Cross-check the oracle's poseidon matches our hash2.
        let hc = v["hash_check"].as_str().unwrap();
        let want_hc = crate::poseidon::hash2(U256::from(1), U256::from(2));
        assert_eq!(
            format!("{:x}", want_hc),
            hc,
            "oracle poseidon diverges from hash2"
        );

        let leaves: Vec<U256> = v["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| U256::from_str_radix(x.as_str().unwrap(), 10).unwrap())
            .collect();
        let tree = LeanImt::from_leaves(&leaves);

        let root_dec = v["root"].as_str().unwrap();
        assert_eq!(tree.root().unwrap().to_string(), root_dec, "root mismatch");
        assert_eq!(
            tree.depth(),
            v["depth"].as_u64().unwrap() as usize,
            "depth mismatch"
        );

        for entry in v["proofs"].as_array().unwrap() {
            let idx = entry["idx"].as_u64().unwrap() as usize;
            let proof = tree.proof(idx).unwrap();
            assert_eq!(proof.leaf.to_string(), entry["leaf"].as_str().unwrap());
            assert_eq!(proof.index, entry["index"].as_u64().unwrap() as usize);
            assert_eq!(proof.root.to_string(), entry["root"].as_str().unwrap());
            let want_siblings: Vec<U256> = entry["siblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| U256::from_str_radix(x.as_str().unwrap(), 10).unwrap())
                .collect();
            assert_eq!(
                proof.siblings, want_siblings,
                "siblings mismatch for leaf {idx}"
            );
            assert!(verify_proof(&proof), "self-verify failed for leaf {idx}");
        }
    }
}
