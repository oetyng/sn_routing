// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::HashSet, iter, mem};
use thiserror::Error;

/// Chain of section BLS keys where every key is proven (signed) by the previous key, except the
/// first one.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SectionChain {
    root: bls::PublicKey,
    tree: Vec<Block>,
}

#[allow(clippy::len_without_is_empty)]
impl SectionChain {
    /// Creates a new chain consisting of only one block.
    pub fn new(root: bls::PublicKey) -> Self {
        Self {
            root,
            tree: Vec::new(),
        }
    }

    /// Insert new key into the chain. `parent_key` must exists in the chain and must validate
    /// `signature`, otherwise error is returned.
    pub fn insert(
        &mut self,
        parent_key: &bls::PublicKey,
        key: bls::PublicKey,
        signature: bls::Signature,
    ) -> Result<(), Error> {
        let parent_index = self.index_of(parent_key).ok_or(Error::KeyNotFound)?;
        let block = Block {
            key,
            signature,
            parent_index,
        };

        if block.verify(parent_key) {
            let _ = self.insert_block(block);
            Ok(())
        } else {
            Err(Error::FailedSignature)
        }
    }

    // TODO: remove this when we make SectionChain correct by deserialization too.
    #[cfg(test)]
    pub fn insert_without_validation(
        &mut self,
        _parent_key: &bls::PublicKey,
        _key: bls::PublicKey,
        _signature: bls::Signature,
    ) -> Result<(), Error> {
        todo!()
    }

    /// Merges two chains into one.
    //
    /// This succeeds only if both chains are self-verified and the root key of one of them is
    /// present in the other one.
    pub fn merge(&mut self, mut other: Self) -> Result<(), Error> {
        self.self_verify()?;
        other.self_verify()?;

        let root_index = if let Some(index) = self.index_of(other.root_key()) {
            index
        } else if let Some(index) = other.index_of(self.root_key()) {
            mem::swap(self, &mut other);
            index
        } else {
            return Err(Error::Incompatible);
        };

        let mut reindex_map = vec![0; other.len()];
        reindex_map[0] = root_index;

        for (other_index, mut other_block) in other
            .tree
            .into_iter()
            .enumerate()
            .map(|(index, block)| (index + 1, block))
        {
            other_block.parent_index = reindex_map[other_block.parent_index];
            reindex_map[other_index] = self.insert_block(other_block);
        }

        Ok(())
    }

    /// Creates a minimal sub-chain of `self` that contains all `required_keys`.
    /// Returns `Error::KeyNotFound` if some of `required_keys` is not present in `self`.
    ///
    /// Note: "minimal" means it contains the fewest number of blocks of all such sub-chains.
    pub fn minimize<'a, I>(&self, required_keys: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = &'a bls::PublicKey>,
    {
        // Note: the returned chain is not always strictly minimal. Consider this chain:
        //
        //     0->1->2->3
        //        |
        //        +->4
        //
        // Then calling `minimize([1, 2])` currently returns
        //
        //     1->2
        //     |
        //     +->4
        //
        // Even though the truly minimal chain containing 1 and 2 is just
        //
        //     1->2
        //
        // This is because 4 lies between 1 and 2 in the underlying `tree` vector and so is
        // currently included.
        //
        // TODO: make this function return the truly minimal chain in all cases.

        let mut min_index = self.len() - 1;
        let mut max_index = 0;

        for key in required_keys {
            let index = self.index_of(key).ok_or(Error::KeyNotFound)?;
            min_index = min_index.min(index);
            max_index = max_index.max(index);
        }

        if let Some(min_parent_index) = ((min_index + 1)..(max_index + 1))
            .filter_map(|index| self.parent_index_at(index))
            .min()
        {
            min_index = min_index.min(min_parent_index);
        }

        let mut chain = Self::new(if min_index == 0 {
            self.root
        } else {
            self.tree[min_index - 1].key
        });

        for index in min_index..max_index {
            let block = &self.tree[index];

            chain.tree.push(Block {
                key: block.key,
                signature: block.signature.clone(),
                parent_index: block.parent_index - min_index,
            })
        }

        Ok(chain)
    }

    /// Returns a sub-chain of `self` truncated to the last `count` keys.
    /// NOTE: a chain must have at least 1 block, so if `count` is 0 it is treated the same as if
    /// it was 1.
    pub fn truncate(&self, count: usize) -> Self {
        let count = count.max(1);

        // Indices of the blocks to include in the result, in reverse order.
        let mut indices = Vec::with_capacity(count - 1);

        // Index of the currently processed block.
        let mut index = self.len() - 1;

        // Walk the chain starting from the last key and following the parent links.
        // Stop when count - 1 blocks are visited or we hit the root, whichever comes first.
        for _ in 1..count {
            if index == 0 {
                break;
            }

            indices.push(index);
            index = self.tree[index - 1].parent_index;
        }

        // Visit one more block - this will be the root block of the resulting chain.
        let mut chain = Self::new(if index == 0 {
            self.root
        } else {
            self.tree[index - 1].key
        });

        // Iterate the visited blocks in reverse order (as the indices are reversed, this results
        // in the original order) and push them into the resulting chain, adjusting the parent
        // indices.
        while let Some(index) = indices.pop() {
            let block = &self.tree[index - 1];

            chain.tree.push(Block {
                key: block.key,
                signature: block.signature.clone(),
                parent_index: chain.tree.len(),
            });
        }

        chain
    }

    /// Returns the smallest super-chain of `self` that would be trusted by a peer that trust
    /// `trusted_key`.
    /// Both `trusted_key` and the current root key of `self` must be present in `super_chain`,
    /// otherwise an error is returned.
    ///
    /// NOTE: if `trusted_key` is not reachable from the `last_key` of `self` then this extends the
    /// chain all the way to the root key of `super_chain` instead. This is because the root key
    /// of `super_chain` is assumed to be the "genesis key" which is implicitly trusted by
    /// everyone.
    pub fn extend(&self, trusted_key: &bls::PublicKey, super_chain: &Self) -> Result<Self, Error> {
        super_chain.minimize(vec![trusted_key, self.last_key()])
    }

    /// Iterator over all the keys in the chain in order.
    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &bls::PublicKey> {
        iter::once(&self.root).chain(self.tree.iter().map(|block| &block.key))
    }

    /// Returns the root key of this chain. This is the first key in the chain and is the only key
    /// that doesn't have a parent key.
    pub fn root_key(&self) -> &bls::PublicKey {
        &self.root
    }

    /// Returns the last key of this chain.
    pub fn last_key(&self) -> &bls::PublicKey {
        self.tree
            .last()
            .map(|block| &block.key)
            .unwrap_or(&self.root)
    }

    /// Returns whether `key` is present in this chain.
    pub fn has_key(&self, key: &bls::PublicKey) -> bool {
        self.keys().any(|existing_key| existing_key == key)
    }

    /// Compare the two keys by their position in the chain. The key that is higher (closer to the
    /// last key) is considered `Greater`. If exactly one of the keys is not in the chain, the other
    /// one is implicitly considered `Greater`. If none are in the chain, they are considered
    /// `Equal`.
    pub fn cmp_by_position(&self, _lhs: &bls::PublicKey, _rhs: &bls::PublicKey) -> Ordering {
        todo!()
    }

    /// Returns the number of blocks in the chain. This is always >= 1.
    pub fn len(&self) -> usize {
        1 + self.tree.len()
    }

    /// Verifies that every block in the chain is correctly signed with its parent block (except for
    /// the root block). Also verifies that the block are in the correct order.
    ///
    /// Note: the first block cannot be verified and requires matching against already trusted keys.
    /// Thus this function alone cannot be used to determine whether this chain is trusted. Use
    /// [`Self::verify`] for that.
    pub fn self_verify(&self) -> Result<(), Error> {
        let mut prev_block: Option<&Block> = None;

        for (tree_index, block) in self.tree.iter().enumerate() {
            let parent_key = if block.parent_index == 0 {
                &self.root
            } else if block.parent_index > tree_index {
                return Err(Error::WrongBlockOrder);
            } else if let Some(key) = self
                .tree
                .get(block.parent_index - 1)
                .map(|block| &block.key)
            {
                key
            } else {
                return Err(Error::KeyNotFound);
            };

            if !block.verify(parent_key) {
                // Invalid signature
                return Err(Error::FailedSignature);
            }

            if let Some(prev_block) = prev_block {
                if block.parent_index < prev_block.parent_index {
                    // Wrong order of block that have neither parent-child, not sibling relation.
                    return Err(Error::WrongBlockOrder);
                }

                if block.parent_index == prev_block.parent_index && block <= prev_block {
                    // Wrong sibling order
                    return Err(Error::WrongBlockOrder);
                }
            }

            prev_block = Some(block);
        }

        Ok(())
    }

    /// Verifies this chain against the given trusted keys.
    ///
    /// Checks that the chain contains at least one key from `trusted_keys` and self-verifies the
    /// chain.
    pub fn verify<'a, I>(&self, trusted_keys: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = &'a bls::PublicKey>,
    {
        // First check whether at least one key from `trusted_keys` is contained in this chain.
        let trusted_keys: HashSet<_> = trusted_keys.into_iter().collect();

        if !self.keys().any(|key| trusted_keys.contains(key)) {
            return Err(Error::Untrusted);
        }

        self.self_verify()
    }

    fn insert_block(&mut self, new_block: Block) -> usize {
        // Find the index into `self.tree` to insert the new key at. All the keys above will be
        // pushed upwards.
        let insert_at = self
            .tree
            .iter()
            .enumerate()
            .skip(new_block.parent_index)
            .find(|(_, block)| {
                block.parent_index != new_block.parent_index || block.key >= new_block.key
            })
            .map(|(index, _)| index)
            .unwrap_or(self.tree.len());

        // If the key already exists in the chain, do nothing but still return success to make the
        // `insert` operation idempotent.
        if self.tree.get(insert_at).map(|block| &block.key) != Some(&new_block.key) {
            self.tree.insert(insert_at, new_block);

            // Adjust the parent indices of the keys whose parents are above the inserted key.
            for block in &mut self.tree {
                if block.parent_index > insert_at {
                    block.parent_index += 1;
                }
            }
        }

        insert_at + 1
    }

    fn index_of(&self, key: &bls::PublicKey) -> Option<usize> {
        self.keys()
            .rev()
            .position(|existing_key| existing_key == key)
            .map(|rev_position| self.len() - rev_position - 1)
    }

    // fn key_at(&self, index: usize) -> Option<&bls::PublicKey> {
    //     if index == 0 {
    //         Some(&self.root)
    //     } else {
    //         self.tree.get(index - 1).map(|block| &block.key)
    //     }
    // }

    fn parent_index_at(&self, index: usize) -> Option<usize> {
        if index == 0 {
            None
        } else {
            self.tree.get(index - 1).map(|block| block.parent_index)
        }
    }
}

/// Error resulting from operations on `SectionChain`.
#[allow(missing_docs)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("signature check failed")]
    FailedSignature,
    #[error("key not found in the chain")]
    KeyNotFound,
    #[error("chain blocks are in a wrong order")]
    WrongBlockOrder,
    #[error("chain doesn't contain any trusted keys")]
    Untrusted,
    #[error("chains are incompatible")]
    Incompatible,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
struct Block {
    key: bls::PublicKey,
    signature: bls::Signature,
    parent_index: usize,
}

impl Block {
    fn verify(&self, parent_key: &bls::PublicKey) -> bool {
        bincode::serialize(&self.key)
            .map(|bytes| parent_key.verify(&self.signature, &bytes))
            .unwrap_or(false)
    }
}

// Define a total order on block, to resolve forks.
impl Ord for Block {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl PartialOrd for Block {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_last() {
        let mut expected_keys = vec![];
        let (mut last_sk, pk) = gen_keypair();

        let mut chain = SectionChain::new(pk);
        expected_keys.push(pk);

        for _ in 0..10 {
            let last_pk = &expected_keys[expected_keys.len() - 1];
            let (sk, pk, sig) = gen_signed_keypair(&last_sk);

            assert_eq!(chain.insert(last_pk, pk, sig), Ok(()));

            expected_keys.push(pk);
            last_sk = sk;
        }

        assert_eq!(chain.self_verify(), Ok(()));
        assert_eq!(chain.keys().copied().collect::<Vec<_>>(), expected_keys);
    }

    #[test]
    fn insert_fork() {
        let (sk0, pk0) = gen_keypair();
        let (sk1_a, pk1_a, sig1_a) = gen_signed_keypair(&sk0);
        let (_, pk2_a, sig2_a) = gen_signed_keypair(&sk1_a);
        let (_, pk1_b, sig1_b) = gen_signed_keypair(&sk0);

        let mut chain = SectionChain::new(pk0);
        assert_eq!(chain.insert(&pk0, pk1_a, sig1_a), Ok(()));
        assert_eq!(chain.insert(&pk1_a, pk2_a, sig2_a), Ok(()));
        assert_eq!(chain.insert(&pk0, pk1_b, sig1_b), Ok(()));

        assert_eq!(chain.self_verify(), Ok(()));

        let expected_keys = if pk1_a > pk1_b {
            vec![&pk0, &pk1_b, &pk1_a, &pk2_a]
        } else {
            vec![&pk0, &pk1_a, &pk1_b, &pk2_a]
        };

        let actual_keys: Vec<_> = chain.keys().collect();

        assert_eq!(actual_keys, expected_keys);
    }

    #[test]
    fn insert_duplicate_key() {
        let (sk0, pk0) = gen_keypair();
        let (_, pk1, sig1) = gen_signed_keypair(&sk0);

        let mut chain = SectionChain::new(pk0);
        assert_eq!(chain.insert(&pk0, pk1, sig1.clone()), Ok(()));
        assert_eq!(chain.insert(&pk0, pk1, sig1), Ok(()));
        assert_eq!(chain.keys().collect::<Vec<_>>(), vec![&pk0, &pk1]);
    }

    #[test]
    fn invalid_chain_invalid_signature() {
        let (_, pk0) = gen_keypair();
        let (_, pk1) = gen_keypair();

        let bad_sk = bls::SecretKey::random();
        let bad_sig = sign(&bad_sk, &pk1);

        let chain = SectionChain {
            root: pk0,
            tree: vec![Block {
                key: pk1,
                signature: bad_sig,
                parent_index: 0,
            }],
        };

        assert_eq!(chain.self_verify(), Err(Error::FailedSignature));
    }

    #[test]
    fn invalid_chain_wrong_parent_child_order() {
        // 0  2<-1<-+
        // |        |
        // +--------+

        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);

        let chain = SectionChain {
            root: pk0,
            tree: vec![
                Block {
                    key: pk2,
                    signature: sig2,
                    parent_index: 2,
                },
                Block {
                    key: pk1,
                    signature: sig1,
                    parent_index: 0,
                },
            ],
        };

        assert_eq!(chain.self_verify(), Err(Error::WrongBlockOrder));
    }

    #[test]
    fn invalid_chain_wrong_sibling_order() {
        // 0->2 +->1
        // |    |
        // +----+

        let (sk0, pk0) = gen_keypair();

        let block1 = {
            let (_, key, signature) = gen_signed_keypair(&sk0);
            Block {
                key,
                signature,
                parent_index: 0,
            }
        };

        let block2 = {
            let (_, key, signature) = gen_signed_keypair(&sk0);
            Block {
                key,
                signature,
                parent_index: 0,
            }
        };

        let (small, large) = if block1 < block2 {
            (block1, block2)
        } else {
            (block2, block1)
        };

        let chain = SectionChain {
            root: pk0,
            tree: vec![large, small],
        };

        assert_eq!(chain.self_verify(), Err(Error::WrongBlockOrder));
    }

    #[test]
    fn invalid_chain_wrong_unrelated_block_order() {
        // "unrelated" here means the blocks have neither parent-child relation, nor are they
        // siblings.

        // 0->1->2 +->3
        // |       |
        // +-------+

        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);
        let (_, pk3, sig3) = gen_signed_keypair(&sk0);

        let chain = SectionChain {
            root: pk0,
            tree: vec![
                Block {
                    key: pk1,
                    signature: sig1,
                    parent_index: 0,
                },
                Block {
                    key: pk2,
                    signature: sig2,
                    parent_index: 1,
                },
                Block {
                    key: pk3,
                    signature: sig3,
                    parent_index: 0,
                },
            ],
        };

        assert_eq!(chain.self_verify(), Err(Error::WrongBlockOrder));
    }

    #[test]
    fn merge() {
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (sk2, pk2, sig2) = gen_signed_keypair(&sk1);
        let (_, pk3, sig3) = gen_signed_keypair(&sk2);

        // lhs: 0->1->2
        // rhs: 2->3
        // out: 0->1->2->3
        let lhs = make_chain(
            pk0,
            vec![
                (&pk0, pk1, sig1.clone()),
                (&pk1, pk2, sig2.clone()),
                (&pk2, pk3, sig3.clone()),
            ],
        );
        let rhs = make_chain(pk2, vec![(&pk2, pk3, sig3.clone())]);
        assert_eq!(merge_chains(lhs, rhs), Ok(vec![pk0, pk1, pk2, pk3]));

        // lhs: 1->2->3
        // rhs: 0->1
        // out: 0->1->2->3
        let lhs = make_chain(pk1, vec![(&pk1, pk2, sig2), (&pk2, pk3, sig3.clone())]);
        let rhs = make_chain(pk0, vec![(&pk0, pk1, sig1.clone())]);
        assert_eq!(merge_chains(lhs, rhs), Ok(vec![pk0, pk1, pk2, pk3]));

        // lhs: 0->1
        // rhs: 2->3
        // out: Err(Incompatible)
        let lhs = make_chain(pk0, vec![(&pk0, pk1, sig1)]);
        let rhs = make_chain(pk2, vec![(&pk2, pk3, sig3)]);
        assert_eq!(merge_chains(lhs, rhs), Err(Error::Incompatible));
    }

    #[test]
    fn merge_fork() {
        let (sk0, pk0) = gen_keypair();
        let (_, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk0);

        // rhs: 0->1
        // lhs: 0->2
        // out: Ok(0->1
        //         |
        //         +->2)
        let lhs = make_chain(pk0, vec![(&pk0, pk1, sig1)]);
        let rhs = make_chain(pk0, vec![(&pk0, pk2, sig2)]);

        let expected = if pk1 < pk2 {
            vec![pk0, pk1, pk2]
        } else {
            vec![pk0, pk2, pk1]
        };

        assert_eq!(merge_chains(lhs, rhs), Ok(expected))
    }

    #[test]
    fn minimize() {
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);

        let chain = make_chain(
            pk0,
            vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())],
        );

        assert_eq!(
            chain.minimize(iter::once(&pk0)),
            Ok(make_chain(pk0, vec![]))
        );
        assert_eq!(
            chain.minimize(iter::once(&pk1)),
            Ok(make_chain(pk1, vec![]))
        );
        assert_eq!(
            chain.minimize(iter::once(&pk2)),
            Ok(make_chain(pk2, vec![]))
        );

        assert_eq!(
            chain.minimize(vec![&pk0, &pk1]),
            Ok(make_chain(pk0, vec![(&pk0, pk1, sig1.clone())]))
        );
        assert_eq!(
            chain.minimize(vec![&pk1, &pk2]),
            Ok(make_chain(pk1, vec![(&pk1, pk2, sig2.clone())]))
        );
        assert_eq!(
            chain.minimize(vec![&pk0, &pk1, &pk2]),
            Ok(make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)]))
        );

        let (_, bad_pk) = gen_keypair();
        assert_eq!(chain.minimize(iter::once(&bad_pk)), Err(Error::KeyNotFound));
    }

    #[test]
    fn minimize_fork() {
        // 0->1->2
        //    |
        //    +->3
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);
        let (_, pk3, sig3) = gen_signed_keypair(&sk1);

        let chain = make_chain(
            pk0,
            vec![
                (&pk0, pk1, sig1),
                (&pk1, pk2, sig2.clone()),
                (&pk1, pk3, sig3.clone()),
            ],
        );

        // 1->2
        // |
        // +->3
        assert_eq!(
            chain.minimize(vec![&pk2, &pk3]),
            Ok(make_chain(pk1, vec![(&pk1, pk2, sig2), (&pk1, pk3, sig3)]))
        );
    }

    // TODO:
    // #[test]
    // fn minimize_trims_unneeded_branches()

    #[test]
    fn truncate() {
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);

        let chain = make_chain(
            pk0,
            vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())],
        );

        assert_eq!(chain.truncate(1), make_chain(pk2, vec![]));
        assert_eq!(
            chain.truncate(2),
            make_chain(pk1, vec![(&pk1, pk2, sig2.clone())])
        );
        assert_eq!(
            chain.truncate(3),
            make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)])
        );

        // 0 is the same as 1
        assert_eq!(chain.truncate(0), make_chain(pk2, vec![]));
    }

    #[test]
    fn trim_fork() {
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (_, pk2, sig2) = gen_signed_keypair(&sk1);
        let (_, pk3, sig3) = gen_signed_keypair(&sk1);

        let chain = make_chain(
            pk0,
            vec![
                (&pk0, pk1, sig1.clone()),
                (&pk1, pk2, sig2.clone()),
                (&pk1, pk3, sig3.clone()),
            ],
        );

        if pk2 < pk3 {
            assert_eq!(chain.truncate(1), make_chain(pk3, vec![]));
            assert_eq!(
                chain.truncate(2),
                make_chain(pk1, vec![(&pk1, pk3, sig3.clone())])
            );
            assert_eq!(
                chain.truncate(3),
                make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk3, sig3)])
            );
        } else {
            assert_eq!(chain.truncate(1), make_chain(pk2, vec![]));
            assert_eq!(
                chain.truncate(2),
                make_chain(pk1, vec![(&pk1, pk2, sig2.clone())])
            );
            assert_eq!(
                chain.truncate(3),
                make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)])
            );
        }
    }

    #[test]
    fn extend() {
        let (sk0, pk0) = gen_keypair();
        let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
        let (sk2, pk2, sig2) = gen_signed_keypair(&sk1);

        // 0->1->2
        let main_chain = make_chain(
            pk0,
            vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())],
        );

        // in:       2
        // new root: 1
        // out:      1->2
        let chain = make_chain(pk2, vec![]);
        assert_eq!(
            chain.extend(&pk1, &main_chain),
            Ok(make_chain(pk1, vec![(&pk1, pk2, sig2.clone())]))
        );

        // in:       2
        // new root: 0
        // out:      0->1->2
        let chain = make_chain(pk2, vec![]);
        assert_eq!(
            chain.extend(&pk0, &main_chain),
            Ok(make_chain(
                pk0,
                vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())]
            ))
        );

        // in:       1->2
        // new root: 0
        // out:      0->1->2
        let chain = make_chain(pk1, vec![(&pk1, pk2, sig2.clone())]);
        assert_eq!(
            chain.extend(&pk0, &main_chain),
            Ok(make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)]))
        );

        // in:       2->3
        // new root: 1
        // out:      Error
        let (_, pk3, sig3) = gen_signed_keypair(&sk2);
        let chain = make_chain(pk2, vec![(&pk2, pk3, sig3)]);
        assert_eq!(chain.extend(&pk1, &main_chain), Err(Error::KeyNotFound));

        // in:       2
        // new_root: 2
        // out:      2
        let chain = make_chain(pk2, vec![]);
        assert_eq!(chain.extend(&pk2, &main_chain), Ok(make_chain(pk2, vec![])));
    }

    fn gen_keypair() -> (bls::SecretKey, bls::PublicKey) {
        let sk = bls::SecretKey::random();
        let pk = sk.public_key();

        (sk, pk)
    }

    fn gen_signed_keypair(
        signing_sk: &bls::SecretKey,
    ) -> (bls::SecretKey, bls::PublicKey, bls::Signature) {
        let (sk, pk) = gen_keypair();
        let signature = sign(signing_sk, &pk);
        (sk, pk, signature)
    }

    fn make_chain(
        root: bls::PublicKey,
        rest: Vec<(&bls::PublicKey, bls::PublicKey, bls::Signature)>,
    ) -> SectionChain {
        let mut chain = SectionChain::new(root);
        for (parent_key, key, signature) in rest {
            assert_eq!(chain.insert(parent_key, key, signature), Ok(()));
        }
        chain
    }

    // Merge `rhs` into `lhs`, verify the resulting chain is valid and return a vector of its keys.
    fn merge_chains(
        mut lhs: SectionChain,
        rhs: SectionChain,
    ) -> Result<Vec<bls::PublicKey>, Error> {
        lhs.merge(rhs)?;
        lhs.self_verify()?;
        Ok(lhs.keys().copied().collect())
    }

    fn sign(signing_sk: &bls::SecretKey, pk_to_sign: &bls::PublicKey) -> bls::Signature {
        bincode::serialize(pk_to_sign)
            .map(|bytes| signing_sk.sign(&bytes))
            .expect("failed to serialize public key")
    }
}