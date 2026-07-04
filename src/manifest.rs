//! The blacklight manifest: the small signed document that binds a file's
//! BLAKE3 Merkle root, its length, and the chunk-group size used for the
//! outboard tree.
//!
//! The Sigstore signature covers the manifest's exact bytes as hosted, so the
//! manifest is verified as raw bytes *before* parsing. There is deliberately
//! no canonicalization step: whatever bytes the publisher signed are the bytes
//! the client must present.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Chunk-group log2 (in 1 KiB BLAKE3 chunks) fixed for format v1.
/// 4 => 16 chunks => 16 KiB groups, ~0.4% outboard overhead.
pub const CHUNK_GROUP_LOG: u8 = 4;

pub const MANIFEST_SUFFIX: &str = ".blacklight.json";
pub const OUTBOARD_SUFFIX: &str = ".obao";
pub const BUNDLE_SUFFIX: &str = ".sigstore.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Format version. Must be 1.
    pub v: u32,
    /// Original file name (basename only; informational).
    pub name: String,
    /// File size in bytes.
    pub size: u64,
    /// Hex-encoded BLAKE3 root hash of the file. Identical to
    /// `blake3::hash(file)` — chunk grouping affects only the outboard layout.
    pub blake3_root: String,
    /// Log2 of the chunk-group size in 1 KiB chunks. Baked into the outboard
    /// tree layout, so it is part of the signed statement.
    pub chunk_group_log: u8,
    /// Optional artifact URL hints. The client may override; integrity never
    /// depends on where the bytes come from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
}

impl Manifest {
    pub fn new(name: String, size: u64, root: blake3::Hash) -> Self {
        Self {
            v: 1,
            name,
            size,
            blake3_root: root.to_hex().to_string(),
            chunk_group_log: CHUNK_GROUP_LOG,
            urls: Vec::new(),
        }
    }

    /// Serialize to the exact bytes that get signed and hosted.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = serde_json::to_vec_pretty(self)?;
        out.push(b'\n');
        Ok(out)
    }

    /// Parse and validate. Callers must verify the Sigstore bundle over the
    /// raw bytes *before* trusting anything returned here.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let m: Manifest = serde_json::from_slice(bytes).context("manifest is not valid JSON")?;
        if m.v != 1 {
            bail!("unsupported manifest version {} (expected 1)", m.v);
        }
        if m.chunk_group_log != CHUNK_GROUP_LOG {
            bail!(
                "unsupported chunk_group_log {} (format v1 fixes it at {})",
                m.chunk_group_log,
                CHUNK_GROUP_LOG
            );
        }
        // `name` is a basename only (documented, and used by `fetch` as the
        // default output path). Reject anything that could escape the current
        // directory — a hostile manifest must not steer writes to `../../…`,
        // an absolute path, or `.`/`..`.
        m.validate_name()?;
        m.root()?;
        Ok(m)
    }

    /// Enforce the basename-only contract for `name`.
    fn validate_name(&self) -> Result<()> {
        let name = &self.name;
        if name.is_empty() {
            bail!("manifest name is empty");
        }
        if name == "." || name == ".." {
            bail!("manifest name {name:?} is a path traversal component");
        }
        if name.contains('/') || name.contains('\\') || name.contains('\0') {
            bail!("manifest name {name:?} must be a bare filename, not a path");
        }
        // Belt and suspenders: the OS-parsed form must be exactly one normal
        // component (rejects absolute paths, drive prefixes, `..`, etc.).
        let path = std::path::Path::new(name);
        let mut comps = path.components();
        match (comps.next(), comps.next()) {
            (Some(std::path::Component::Normal(c)), None) if c == name.as_str() => Ok(()),
            _ => bail!("manifest name {name:?} is not a single filename component"),
        }
    }

    pub fn root(&self) -> Result<blake3::Hash> {
        blake3::Hash::from_hex(&self.blake3_root).with_context(|| {
            format!(
                "blake3_root {:?} is not a 64-char hex hash",
                self.blake3_root
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest::new("demo.bin".into(), 1234, blake3::hash(b"hello"))
    }

    #[test]
    fn round_trip() {
        let m = sample();
        let bytes = m.to_bytes().unwrap();
        let back = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(m, back);
        assert_eq!(back.root().unwrap(), blake3::hash(b"hello"));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut m = sample();
        m.v = 2;
        let err = Manifest::from_bytes(&m.to_bytes().unwrap()).unwrap_err();
        assert!(err.to_string().contains("unsupported manifest version"));
    }

    #[test]
    fn rejects_wrong_chunk_group() {
        let mut m = sample();
        m.chunk_group_log = 0;
        let err = Manifest::from_bytes(&m.to_bytes().unwrap()).unwrap_err();
        assert!(err.to_string().contains("chunk_group_log"));
    }

    #[test]
    fn rejects_bad_root_hex() {
        let mut m = sample();
        m.blake3_root = "zz".into();
        assert!(Manifest::from_bytes(&m.to_bytes().unwrap()).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let json =
            br#"{"v":1,"name":"a","size":1,"blake3_root":"00","chunk_group_log":4,"evil":true}"#;
        assert!(Manifest::from_bytes(json).is_err());
    }

    #[test]
    fn rejects_path_traversal_names() {
        for evil in [
            "../evil",
            "../../etc/passwd",
            "/etc/passwd",
            "a/b",
            "sub/../x",
            "..",
            ".",
            "",
            "back\\slash",
            "with\0null",
        ] {
            let mut m = sample();
            m.name = evil.into();
            let bytes = m.to_bytes().unwrap();
            assert!(
                Manifest::from_bytes(&bytes).is_err(),
                "should have rejected name {evil:?}"
            );
        }
    }

    #[test]
    fn accepts_plain_basenames() {
        for ok in ["demo.bin", "my-file_v1.2.tar.gz", "a"] {
            let mut m = sample();
            m.name = ok.into();
            let bytes = m.to_bytes().unwrap();
            assert!(
                Manifest::from_bytes(&bytes).is_ok(),
                "should have accepted name {ok:?}"
            );
        }
    }
}
