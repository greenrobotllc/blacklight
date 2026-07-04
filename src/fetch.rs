//! `blacklight fetch`: verify the manifest's Sigstore bundle offline, then
//! stream the artifact, verifying every 16 KiB chunk group against the signed
//! BLAKE3 root as it arrives — aborting the transfer on the first bad byte.
//!
//! Order of operations matters. Nothing about the artifact is trusted until:
//!   1. the manifest bytes verify against the Sigstore bundle (signature,
//!      Fulcio cert chain, Rekor inclusion proof, and the required identity
//!      policy), and
//!   2. every delivered chunk group verifies against the root in that manifest.
//!
//! The network, the mirror, and the CDN are all untrusted.

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

use crate::manifest::{BUNDLE_SUFFIX, MANIFEST_SUFFIX, Manifest, OUTBOARD_SUFFIX};
use crate::sigstore::{self, Env, IdentityPolicy};
use crate::verify::{GROUP_LEN, GroupPlan, VerifyError};

/// Distinct error type so `main` can map integrity failures to exit code 3.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TamperError(pub String);

pub struct Options {
    pub manifest: String,
    pub expect_identity: Option<String>,
    pub expect_issuer: Option<String>,
    pub allow_unsigned: bool,
    pub production: bool,
    pub url_override: Option<String>,
    pub output: Option<PathBuf>,
}

pub async fn fetch(opts: Options) -> Result<()> {
    let env = if opts.production {
        Env::Production
    } else {
        Env::Staging
    };

    // 1. Load manifest + bundle (from URL or local path).
    let manifest_bytes = load(&opts.manifest).await.context("cannot load manifest")?;

    if opts.allow_unsigned {
        eprintln!(
            "WARNING: --allow-unsigned — the manifest root is NOT proven to come from any publisher."
        );
    } else {
        let policy = build_policy(&opts)?;
        let bundle_src = format!("{}{BUNDLE_SUFFIX}", opts.manifest);
        let bundle_bytes = load(&bundle_src)
            .await
            .with_context(|| format!("cannot load Sigstore bundle from {bundle_src}"))?;
        eprintln!("verifying Sigstore bundle offline ({env:?}) …");
        let v = sigstore::verify_manifest(&manifest_bytes, &bundle_bytes, &policy, env)
            .context("Sigstore verification FAILED — refusing to download")?;
        eprintln!("  signer   {} (issuer {})", v.identity, v.issuer);
        if let Some(t) = v.integrated_time {
            eprintln!("  rekor    integrated at unix time {t}");
        }
    }

    // Only now do we parse and trust the manifest contents.
    let manifest = Manifest::from_bytes(&manifest_bytes)?;
    let root = manifest.root()?;
    eprintln!(
        "manifest verified: {} ({} bytes, root {})",
        manifest.name,
        manifest.size,
        &manifest.blake3_root[..16]
    );

    // 2. Fetch the outboard tree (small; downloaded fully before streaming data).
    let outboard_src = artifact_relative(&opts.manifest, OUTBOARD_SUFFIX, &manifest);
    let outboard = load(&outboard_src)
        .await
        .with_context(|| format!("cannot load outboard from {outboard_src}"))?;

    // Build + self-check the verification plan. A tampered outboard is caught
    // here (it won't hash up to the signed root).
    let plan = GroupPlan::new(root, manifest.size, &outboard)
        .map_err(|e| TamperError(e.to_string()))
        .context("outboard failed to verify against signed root")?;

    // 3. Stream the artifact, verifying each group as it lands.
    let artifact_url = resolve_artifact_url(&opts, &manifest)?;
    let out_path = opts
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(&manifest.name));
    eprintln!("streaming {artifact_url} …");

    stream_verified(&artifact_url, &plan, &out_path).await
}

/// The core loop: pull bytes, accumulate into 16 KiB groups, verify each group
/// against the plan the instant it completes, and abort on the first mismatch.
async fn stream_verified(url: &str, plan: &GroupPlan, out_path: &Path) -> Result<()> {
    let tmp_path = out_path.with_extension("blacklight-partial");
    let mut tmp = tokio::fs::File::create(&tmp_path)
        .await
        .with_context(|| format!("cannot create {}", tmp_path.display()))?;

    let result = stream_verified_inner(url, plan, &mut tmp).await;

    // On any failure — tampering or network — never leave a partial file that
    // could be mistaken for a good download.
    if result.is_err() {
        drop(tmp);
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return result.map(|_| ());
    }

    tmp.flush().await?;
    tmp.sync_all().await?;
    drop(tmp);
    tokio::fs::rename(&tmp_path, out_path)
        .await
        .with_context(|| format!("cannot finalize {}", out_path.display()))?;
    let bytes = result.unwrap();
    eprintln!(
        "OK — {bytes} bytes verified against the signed root; wrote {}",
        out_path.display()
    );
    Ok(())
}

async fn stream_verified_inner(
    url: &str,
    plan: &GroupPlan,
    tmp: &mut tokio::fs::File,
) -> Result<u64> {
    let resp = reqwest::get(url)
        .await
        .with_context(|| format!("request to {url} failed"))?;
    if !resp.status().is_success() {
        bail!("server returned HTTP {} for {url}", resp.status());
    }

    let mut stream = resp.bytes_stream();
    let mut group_buf: Vec<u8> = Vec::with_capacity(GROUP_LEN);
    let mut group_index: usize = 0;
    let mut total: u64 = 0;

    while let Some(chunk) = stream.next().await {
        // A network read error is NOT tampering — surface it as an ordinary
        // error (exit 1), distinct from integrity failure (exit 3).
        let chunk = chunk.with_context(|| format!("network error reading {url}"))?;
        let mut data = &chunk[..];
        while !data.is_empty() {
            let need = GROUP_LEN - group_buf.len();
            let take = need.min(data.len());
            group_buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if group_buf.len() == GROUP_LEN {
                verify_group(plan, group_index, &group_buf)?;
                tmp.write_all(&group_buf).await?;
                total += group_buf.len() as u64;
                group_index += 1;
                group_buf.clear();
            }
        }
    }

    // Final short group (if any).
    if !group_buf.is_empty() {
        verify_group(plan, group_index, &group_buf)?;
        tmp.write_all(&group_buf).await?;
        total += group_buf.len() as u64;
        group_index += 1;
    }

    // Length must match exactly: a truncated or padded stream is a mismatch.
    if total != plan.size() {
        return Err(TamperError(format!(
            "stream length {total} != signed size {} (truncated or padded)",
            plan.size()
        ))
        .into());
    }
    if group_index != plan.group_count() {
        return Err(TamperError(format!(
            "received {group_index} groups, expected {}",
            plan.group_count()
        ))
        .into());
    }
    Ok(total)
}

fn verify_group(plan: &GroupPlan, index: usize, data: &[u8]) -> Result<()> {
    match plan.check_group(index, data) {
        Ok(()) => Ok(()),
        Err(e @ VerifyError::GroupMismatch { .. }) => {
            // The whole point: report exactly where tampering was caught, and
            // how little was fetched past it (at most one group).
            Err(TamperError(format!(
                "{e} — aborting transfer; at most {} extra bytes were fetched past the tampered byte",
                GROUP_LEN
            ))
            .into())
        }
        Err(e) => Err(TamperError(e.to_string()).into()),
    }
}

fn build_policy(opts: &Options) -> Result<IdentityPolicy> {
    let identity = opts.expect_identity.clone().ok_or_else(|| {
        anyhow!("--expect-identity is required (or pass --allow-unsigned to skip verification)")
    })?;
    let issuer = opts.expect_issuer.clone().ok_or_else(|| {
        anyhow!("--expect-issuer is required (or pass --allow-unsigned to skip verification)")
    })?;
    Ok(IdentityPolicy { identity, issuer })
}

/// Load bytes from an http(s) URL or a local filesystem path.
async fn load(src: &str) -> Result<Vec<u8>> {
    if is_url(src) {
        let resp = reqwest::get(src).await?;
        if !resp.status().is_success() {
            bail!("HTTP {} for {src}", resp.status());
        }
        Ok(resp.bytes().await?.to_vec())
    } else {
        Ok(tokio::fs::read(src).await?)
    }
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Derive a sibling resource's location from the manifest location by swapping
/// the manifest suffix for another. Works for both URLs and paths.
fn artifact_relative(manifest_src: &str, new_suffix: &str, manifest: &Manifest) -> String {
    if let Some(base) = manifest_src.strip_suffix(MANIFEST_SUFFIX) {
        // base already ends with the artifact name; e.g. ".../demo.bin"
        format!("{base}{new_suffix}")
    } else {
        // Fall back to a sibling of the manifest named after the artifact.
        sibling(manifest_src, &format!("{}{new_suffix}", manifest.name))
    }
}

/// Decide where the artifact bytes come from: explicit override, else the
/// manifest location minus its suffix, else the manifest's URL hints.
fn resolve_artifact_url(opts: &Options, manifest: &Manifest) -> Result<String> {
    if let Some(u) = &opts.url_override {
        return Ok(u.clone());
    }
    if let Some(base) = opts.manifest.strip_suffix(MANIFEST_SUFFIX) {
        return Ok(base.to_string());
    }
    if let Some(u) = manifest.urls.first() {
        return Ok(u.clone());
    }
    bail!("cannot determine artifact URL; pass --url")
}

fn sibling(src: &str, name: &str) -> String {
    match src.rfind('/') {
        Some(i) => format!("{}{name}", &src[..=i]),
        None => name.to_string(),
    }
}
