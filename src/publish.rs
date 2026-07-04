//! `blacklight publish`: hash the file, build its outboard Merkle tree, write
//! the manifest, and (unless `--unsigned`) sign the manifest with Sigstore.

use anyhow::{Context, Result};
use bao_tree::BlockSize;
use bao_tree::io::outboard::PreOrderOutboard;
use bao_tree::io::sync::CreateOutboard;
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::manifest::{BUNDLE_SUFFIX, CHUNK_GROUP_LOG, MANIFEST_SUFFIX, Manifest, OUTBOARD_SUFFIX};
use crate::sigstore;

/// 16 KiB chunk groups. Fixed by the manifest format (see CHUNK_GROUP_LOG).
pub const BLOCK_SIZE: BlockSize = BlockSize::from_chunk_log(CHUNK_GROUP_LOG);

pub struct Options {
    pub file: PathBuf,
    pub out: Option<PathBuf>,
    pub unsigned: bool,
    pub target: sigstore::Target,
    pub urls: Vec<String>,
}

pub async fn publish(opts: Options) -> Result<()> {
    let file = &opts.file;
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .context("input file has no valid name")?
        .to_string();

    let out_dir = opts
        .out
        .clone()
        .unwrap_or_else(|| file.parent().map(Path::to_path_buf).unwrap_or_default());
    std::fs::create_dir_all(&out_dir).ok();

    // Build the outboard tree. bao-tree hashes the file as it goes; the root it
    // returns equals plain blake3::hash(file) — chunk grouping only changes the
    // outboard layout, not the hashing math.
    eprintln!("hashing and building outboard tree for {name} …");
    let f = File::open(file).with_context(|| format!("cannot open {}", file.display()))?;
    let size = f.metadata()?.len();
    let ob = PreOrderOutboard::<Vec<u8>>::create(&f, BLOCK_SIZE)
        .context("failed to build outboard tree")?;
    let root = ob.root;

    let outboard_path = sidecar(&out_dir, &name, OUTBOARD_SUFFIX);
    std::fs::write(&outboard_path, &ob.data)
        .with_context(|| format!("cannot write {}", outboard_path.display()))?;

    // Manifest.
    let mut manifest = Manifest::new(name.clone(), size, root);
    manifest.urls = opts.urls.clone();
    let manifest_bytes = manifest.to_bytes()?;
    let manifest_path = sidecar(&out_dir, &name, MANIFEST_SUFFIX);
    std::fs::write(&manifest_path, &manifest_bytes)
        .with_context(|| format!("cannot write {}", manifest_path.display()))?;

    eprintln!("  root   {}", root.to_hex());
    eprintln!("  size   {size} bytes");
    eprintln!(
        "  outboard {} ({} bytes, {:.2}% overhead)",
        outboard_path.display(),
        ob.data.len(),
        100.0 * ob.data.len() as f64 / size.max(1) as f64
    );
    eprintln!("  manifest {}", manifest_path.display());

    // Sign the manifest bytes.
    if opts.unsigned {
        eprintln!("  (unsigned — no Sigstore bundle emitted)");
        return Ok(());
    }

    let bundle_path = sidecar(
        &out_dir,
        &name,
        &format!("{MANIFEST_SUFFIX}{BUNDLE_SUFFIX}"),
    );
    eprintln!(
        "signing manifest via Sigstore ({}, keyless OIDC) …",
        describe_target(&opts.target)
    );
    let bundle_json = sigstore::sign_manifest(&manifest_bytes, &opts.target)
        .await
        .context("Sigstore signing failed")?;
    std::fs::write(&bundle_path, &bundle_json)
        .with_context(|| format!("cannot write {}", bundle_path.display()))?;
    eprintln!("  bundle   {}", bundle_path.display());
    eprintln!("done. host: artifact, {OUTBOARD_SUFFIX}, {MANIFEST_SUFFIX}, and the bundle.");
    Ok(())
}

fn describe_target(target: &sigstore::Target) -> String {
    match target {
        sigstore::Target::Staging => "staging".to_string(),
        sigstore::Target::Production => "production".to_string(),
        sigstore::Target::Custom(c) => {
            let rekor = c.rekor_url.as_deref().unwrap_or("(default rekor)");
            format!("private: rekor={rekor}")
        }
    }
}

fn sidecar(dir: &Path, name: &str, suffix: &str) -> PathBuf {
    dir.join(format!("{name}{suffix}"))
}
