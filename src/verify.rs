//! Forward-only, fail-fast streaming verifier.
//!
//! bao-tree's `valid_ranges` needs random-access (seekable) data and reports a
//! corrupt group as an *omitted* range rather than an error — awkward for the
//! "stop the moment a byte is wrong" behaviour that is the whole point here. So
//! we verify the way the BLAKE3 tree is actually defined, using the public
//! `blake3::hazmat` API (the same primitives bao-tree uses internally):
//!
//!   * Feed the plain file bytes in order.
//!   * Every time a full 16 KiB chunk group completes, compute its BLAKE3
//!     subtree chaining value and compare it against the corresponding leaf
//!     hash held in the (already-verified-by-signature) outboard.
//!   * On the first mismatch, abort immediately — the caller has fetched at
//!     most one chunk group past the tampered byte.
//!
//! The outboard is a pre-order sequence of 64-byte (left CV, right CV) parent
//! pairs. We don't need the interior parents to check leaves: the leaf hashes
//! are the CVs stored at the lowest level. Rather than reason about pre-order
//! offsets, we reconstruct the expected per-group leaf CVs top-down from the
//! outboard once (cheap: the whole outboard is ~0.4% of the file and already in
//! memory), then stream-check data groups against that vector. We also verify
//! the outboard's own internal consistency up to the trusted root while doing
//! so, so a tampered outboard is caught too.

use blake3::Hash;
use blake3::hazmat::{HasherExt, Mode, merge_subtrees_non_root, merge_subtrees_root};

const CHUNK_LEN: u64 = 1024;
const CHUNK_GROUP_LOG: u8 = 4;
/// 16 KiB.
pub const GROUP_LEN: usize = (CHUNK_LEN as usize) << CHUNK_GROUP_LOG;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error(
        "integrity check failed: chunk group {group} (byte offset {offset}) does not match the signed root"
    )]
    GroupMismatch { group: u64, offset: u64 },
    #[error(
        "integrity check failed: the outboard tree does not hash to the signed root (tampered .obao)"
    )]
    OutboardRootMismatch,
    #[error("integrity check failed: stream longer than the signed size ({expected} bytes)")]
    LongStream { expected: u64 },
    #[error("malformed outboard: {0}")]
    BadOutboard(&'static str),
}

/// Expected leaf chaining values, one per 16 KiB group, in file order, derived
/// from the outboard and checked to hash up to the trusted root.
#[derive(Debug)]
pub struct GroupPlan {
    size: u64,
    /// Per-group expected CV. The final group may be short.
    leaf_cvs: Vec<Hash>,
}

impl GroupPlan {
    pub fn group_count(&self) -> usize {
        self.leaf_cvs.len()
    }

    /// Build and validate the plan from the trusted root, the file size, and the
    /// outboard bytes. Fails if the outboard doesn't hash to `root`.
    pub fn new(root: Hash, size: u64, outboard: &[u8]) -> Result<Self, VerifyError> {
        if size == 0 {
            // Empty file: the root is the hash of the empty input; no groups.
            let empty = blake3::hash(b"");
            if empty != root {
                return Err(VerifyError::OutboardRootMismatch);
            }
            return Ok(GroupPlan {
                size,
                leaf_cvs: vec![],
            });
        }
        let group_count = size.div_ceil(GROUP_LEN as u64) as usize;
        if group_count == 1 {
            // Single group: the whole file is one leaf and its root hash is the
            // trusted root. There are no parent pairs, so the outboard is empty.
            // check_group() recomputes and compares against `root` directly.
            if !outboard.is_empty() {
                return Err(VerifyError::BadOutboard(
                    "single-group outboard must be empty",
                ));
            }
            return Ok(GroupPlan {
                size,
                leaf_cvs: vec![root],
            });
        }
        let mut leaves = Vec::with_capacity(group_count);
        let mut cursor = OutboardCursor {
            data: outboard,
            pos: 0,
        };
        // Walk the tree top-down. Each leaf subtree covers up to GROUP_LEN bytes.
        let computed_root = build(&mut cursor, 0, size, /* is_root */ true, &mut leaves)?;
        if cursor.pos != outboard.len() {
            return Err(VerifyError::BadOutboard("trailing bytes in outboard"));
        }
        if computed_root != root {
            return Err(VerifyError::OutboardRootMismatch);
        }
        debug_assert_eq!(leaves.len(), group_count);
        Ok(GroupPlan {
            size,
            leaf_cvs: leaves,
        })
    }

    /// Verify the CV of the `group_index`-th group of `data` (the plain group
    /// bytes) against the plan. Returns the group's byte offset on mismatch.
    pub fn check_group(&self, group_index: usize, data: &[u8]) -> Result<(), VerifyError> {
        let expected = self
            .leaf_cvs
            .get(group_index)
            .ok_or(VerifyError::LongStream {
                expected: self.size,
            })?;
        let start_chunk = (group_index as u64) << CHUNK_GROUP_LOG;
        let is_root = self.leaf_cvs.len() == 1; // single-group file: leaf is the root
        let actual = leaf_cv(start_chunk, data, is_root);
        if &actual != expected {
            return Err(VerifyError::GroupMismatch {
                group: group_index as u64,
                offset: start_chunk * CHUNK_LEN,
            });
        }
        Ok(())
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

/// Compute the BLAKE3 chaining value (or root hash) of one chunk group.
fn leaf_cv(start_chunk: u64, data: &[u8], is_root: bool) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.set_input_offset(start_chunk * CHUNK_LEN);
    hasher.update(data);
    if is_root {
        hasher.finalize()
    } else {
        Hash::from(hasher.finalize_non_root())
    }
}

struct OutboardCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> OutboardCursor<'a> {
    fn read_pair(&mut self) -> Result<(Hash, Hash), VerifyError> {
        let end = self.pos + 64;
        if end > self.data.len() {
            return Err(VerifyError::BadOutboard("outboard shorter than expected"));
        }
        let l: [u8; 32] = self.data[self.pos..self.pos + 32].try_into().unwrap();
        let r: [u8; 32] = self.data[self.pos + 32..end].try_into().unwrap();
        self.pos = end;
        Ok((Hash::from(l), Hash::from(r)))
    }
}

/// The largest power-of-two number of chunk-groups strictly less than
/// `group_count`, i.e. the left-subtree split for a subtree of `group_count`
/// groups. Mirrors bao-tree's tree geometry at chunk-group granularity.
fn left_groups(group_count: u64) -> u64 {
    debug_assert!(group_count > 1);
    // Largest power of two < group_count.
    let mut p = 1u64;
    while p << 1 < group_count {
        p <<= 1;
    }
    p
}

/// Recursively reconstruct the expected leaf CVs from the outboard for the
/// subtree covering `[start_byte, start_byte+len)` and return the subtree hash.
fn build(
    cursor: &mut OutboardCursor,
    start_byte: u64,
    len: u64,
    is_root: bool,
    leaves: &mut Vec<Hash>,
) -> Result<Hash, VerifyError> {
    let start_chunk = start_byte / CHUNK_LEN;
    let groups = len.div_ceil(GROUP_LEN as u64);
    if groups <= 1 {
        // Leaf group: its CV isn't stored in the outboard (only parents are).
        // The caller will recompute it from data; here we record a placeholder
        // slot and return the CV that the *parent* expects. But we can't know
        // the leaf CV without the data. Instead we push the parent-provided CV.
        // This branch is only reached for a single-group file (no parents at
        // all); handle that by returning a sentinel the caller replaces.
        unreachable!("build() is only entered when there is at least one parent");
    }
    // There is at least one parent pair for this subtree.
    let (l_cv, r_cv) = cursor.read_pair()?;
    let left_len_groups = left_groups(groups);
    let left_bytes = left_len_groups * GROUP_LEN as u64;
    let right_start = start_byte + left_bytes;
    let right_len = len - left_bytes;

    let l_actual = subtree(cursor, start_byte, left_bytes, l_cv, leaves)?;
    let r_actual = subtree(cursor, right_start, right_len, r_cv, leaves)?;
    if l_actual != l_cv || r_actual != r_cv {
        return Err(VerifyError::BadOutboard("internal parent mismatch"));
    }
    let _ = start_chunk;
    if is_root {
        Ok(merge_subtrees_root(
            &into_cv(l_cv),
            &into_cv(r_cv),
            Mode::Hash,
        ))
    } else {
        Ok(Hash::from(merge_subtrees_non_root(
            &into_cv(l_cv),
            &into_cv(r_cv),
            Mode::Hash,
        )))
    }
}

/// Handle a subtree that may be a single leaf group (CV supplied by the parent,
/// recorded for later data-checking) or a further parent subtree.
fn subtree(
    cursor: &mut OutboardCursor,
    start_byte: u64,
    len: u64,
    expected_cv: Hash,
    leaves: &mut Vec<Hash>,
) -> Result<Hash, VerifyError> {
    let groups = len.div_ceil(GROUP_LEN as u64);
    if groups <= 1 {
        // Leaf: the parent's CV for this position IS the group's expected leaf
        // CV. Record it in file order; data verification happens during stream.
        leaves.push(expected_cv);
        Ok(expected_cv)
    } else {
        build(cursor, start_byte, len, /* is_root */ false, leaves)
    }
}

fn into_cv(h: Hash) -> blake3::hazmat::ChainingValue {
    *h.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bao_tree::BlockSize;
    use bao_tree::io::outboard::PreOrderOutboard;
    use bao_tree::io::sync::CreateOutboard;
    use std::io::Cursor;

    const BS: BlockSize = BlockSize::from_chunk_log(CHUNK_GROUP_LOG);

    fn make(size: usize) -> (Hash, u64, Vec<u8>, Vec<u8>) {
        let mut data = vec![0u8; size];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let ob = PreOrderOutboard::<Vec<u8>>::create(Cursor::new(&data), BS).unwrap();
        (ob.root, size as u64, ob.data, data)
    }

    fn run_plan(root: Hash, size: u64, outboard: &[u8], data: &[u8]) -> Result<(), VerifyError> {
        let plan = GroupPlan::new(root, size, outboard)?;
        for (i, group) in data.chunks(GROUP_LEN).enumerate() {
            plan.check_group(i, group)?;
        }
        Ok(())
    }

    #[test]
    fn plan_root_matches_blake3() {
        for &size in &[
            0usize,
            1,
            1000,
            GROUP_LEN,
            GROUP_LEN + 1,
            5 * GROUP_LEN + 37,
            200_000,
        ] {
            let (root, sz, ob, data) = make(size);
            assert_eq!(root, blake3::hash(&data), "size {size}");
            run_plan(root, sz, &ob, &data).unwrap_or_else(|e| panic!("size {size}: {e}"));
        }
    }

    #[test]
    fn detects_single_byte_flip_in_each_group() {
        let (root, size, ob, mut data) = make(5 * GROUP_LEN + 100);
        let group_count = data.len().div_ceil(GROUP_LEN);
        for g in 0..group_count {
            let mut d = data.clone();
            let idx = g * GROUP_LEN + 3;
            d[idx] ^= 0xFF;
            let err = run_plan(root, size, &ob, &d).unwrap_err();
            match err {
                VerifyError::GroupMismatch { group, offset } => {
                    assert_eq!(group as usize, g);
                    assert_eq!(offset, (g * GROUP_LEN) as u64);
                }
                other => panic!("group {g}: wrong error {other}"),
            }
        }
        let _ = &mut data;
    }

    #[test]
    fn detects_tampered_outboard() {
        let (root, size, mut ob, _data) = make(10 * GROUP_LEN);
        ob[10] ^= 0xFF;
        let err = GroupPlan::new(root, size, &ob).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::OutboardRootMismatch | VerifyError::BadOutboard(_)
        ));
    }

    #[test]
    fn detects_wrong_root() {
        let (_root, size, ob, _data) = make(3 * GROUP_LEN);
        let wrong = blake3::hash(b"not it");
        assert!(GroupPlan::new(wrong, size, &ob).is_err());
    }
}
