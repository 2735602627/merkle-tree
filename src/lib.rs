use sha2::Digest;

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

/// A Merkle (sub)tree
pub struct MerkleTree {
    hash: Hash,
    #[allow(dead_code)]
    children: MerkleTreeChildren,
}

/// Potential children of a single Merkle tree node
pub enum MerkleTreeChildren {
    Leaf,
    Branch {
        left: Box<MerkleTree>,
        right: Box<MerkleTree>,
    },
}

impl MerkleTree {
    fn leaf(hash: Hash) -> MerkleTree {
        MerkleTree {
            hash,
            children: MerkleTreeChildren::Leaf,
        }
    }

    fn branch(left: MerkleTree, right: MerkleTree) -> MerkleTree {
        MerkleTree {
            hash: hash_concat(&left.hash, &right.hash),
            children: MerkleTreeChildren::Branch {
                left: Box::new(left),
                right: Box::new(right),
            },
        }
    }

    /// Constructs a Merkle tree from given leaf blobs
    /// Length of the input must be a nonzero power of two
    pub fn construct(input: &[Data]) -> MerkleTree {
        assert!(input.len().is_power_of_two());

        let depth = (input.len().trailing_zeros() + 1) as usize;

        // Unfinished subtrees that are waiting for corresponding right-side trees
        let mut left_side: Vec<Option<MerkleTree>> = (0..depth).map(|_| None).collect();

        for item in input {
            let mut right = MerkleTree::leaf(hash_data(item));
            // Propagate and merge subtrees
            for ls in left_side.iter_mut() {
                // Merge with left-side node if it exists
                if let Some(left) = ls.take() {
                    right = MerkleTree::branch(left, right);
                } else {
                    *ls = Some(right);
                    break;
                }
            }
        }

        // The topmost node is root of the merkle tree
        left_side.pop().unwrap().unwrap()
    }

    /// Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        MerkleTree::construct(input).hash == *root_hash
    }
}

fn hash_data(data: &Data) -> Hash {
    sha2::Sha256::digest(data).to_vec()
}

fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}

#[cfg(test)]
mod tests {
    use super::{hash_concat, hash_data, MerkleTree};

    #[test]
    fn manual_hash_calculation() {
        let input: Vec<_> = (0..4).map(|i| vec![i]).collect();

        let mt = MerkleTree::construct(&input);

        let a = hash_data(&input[0]);
        let b = hash_data(&input[1]);
        let c = hash_data(&input[2]);
        let d = hash_data(&input[3]);

        let ab = hash_concat(&a, &b);
        let cd = hash_concat(&c, &d);

        let abcd = hash_concat(&ab, &cd);

        assert_eq!(abcd, mt.hash);

        assert!(MerkleTree::verify(&input, &mt.hash));
    }

    #[test]
    fn different_sizes() {
        for size in 1..10 {
            let input: Vec<_> = (0..(1 << size)).map(|i| vec![i as u8]).collect();

            let mt = MerkleTree::construct(&input);
            assert!(MerkleTree::verify(&input, &mt.hash));
        }
    }

    #[test]
    fn integrity_check() {
        let mut input: Vec<_> = (0..8).map(|i| vec![i]).collect();

        let mt = MerkleTree::construct(&input);

        input[0][0] += 1; // Mutate to non-original value

        assert!(!MerkleTree::verify(&input, &mt.hash));
    }
}
