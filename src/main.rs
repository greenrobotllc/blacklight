mod fetch;
mod manifest;
mod publish;
mod sigstore;
mod verify;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

/// Verified-streaming downloads anchored in the Sigstore transparency log.
///
/// `publish` produces, next to the artifact: an outboard BLAKE3 Merkle tree
/// (.obao), a manifest (.blacklight.json), and a Sigstore bundle
/// (.blacklight.json.sigstore.json). `fetch` verifies the bundle offline,
/// then streams the artifact, verifying every 16 KiB chunk group against the
/// signed root as it arrives — aborting on the first tampered byte.
#[derive(Parser)]
#[command(name = "blacklight", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hash a file, build its outboard tree, and sign the manifest.
    Publish {
        /// File to publish.
        file: PathBuf,
        /// Directory for the sidecar files (defaults to the file's directory).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Skip signing; emit only .obao + manifest. For local testing.
        /// (Signing is otherwise keyless via OIDC — ambient CI or browser.)
        #[arg(long)]
        unsigned: bool,
        /// Use Sigstore production infrastructure instead of staging.
        #[arg(long, conflicts_with_all = ["rekor_url", "fulcio_url", "oidc_url"])]
        production: bool,
        /// Sign against a private Rekor transparency log (self-hosted Sigstore).
        /// e.g. https://rekor.corp.internal — pairs with --fulcio-url/--oidc-url.
        #[arg(long)]
        rekor_url: Option<String>,
        /// Private Fulcio (certificate authority) URL for a self-hosted Sigstore.
        #[arg(long)]
        fulcio_url: Option<String>,
        /// Private OIDC issuer URL for a self-hosted Sigstore.
        #[arg(long)]
        oidc_url: Option<String>,
        /// URL hint(s) to embed in the manifest.
        #[arg(long)]
        url: Vec<String>,
    },
    /// Fetch and verify an artifact via its manifest URL (or local path).
    Fetch {
        /// Manifest URL (…/file.blacklight.json) or local path.
        manifest: String,
        /// Expected signer identity (email or URI SAN), e.g. you@example.com.
        #[arg(long)]
        expect_identity: Option<String>,
        /// Expected OIDC issuer, e.g. https://github.com/login/oauth.
        #[arg(long)]
        expect_issuer: Option<String>,
        /// DANGEROUS: skip Sigstore bundle verification entirely. The
        /// download is still integrity-checked against the manifest root,
        /// but nothing proves who published that root.
        #[arg(long)]
        allow_unsigned: bool,
        /// Verify against the Sigstore production trust root instead of staging.
        #[arg(long, conflicts_with = "trust_root")]
        production: bool,
        /// Verify against a private Sigstore's trust root (JSON exported from
        /// that deployment's TUF root). Use this to verify artifacts signed
        /// against a self-hosted Rekor/Fulcio.
        #[arg(long)]
        trust_root: Option<PathBuf>,
        /// Override the artifact URL (defaults to manifest URL minus suffix,
        /// then manifest url hints).
        #[arg(long)]
        url: Option<String>,
        /// Output path (defaults to the manifest's `name` in the current dir).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            // Tampering gets a distinct exit code so scripts/tests can tell
            // "integrity violation" from ordinary failures.
            if err.is::<fetch::TamperError>() {
                ExitCode::from(3)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

async fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Publish {
            file,
            out,
            unsigned,
            production,
            rekor_url,
            fulcio_url,
            oidc_url,
            url,
        } => {
            let target = if rekor_url.is_some() || fulcio_url.is_some() || oidc_url.is_some() {
                sigstore::Target::Custom(sigstore::CustomTarget {
                    fulcio_url,
                    rekor_url,
                    oidc_url,
                    trust_root_path: None,
                })
            } else if production {
                sigstore::Target::Production
            } else {
                sigstore::Target::Staging
            };
            publish::publish(publish::Options {
                file,
                out,
                unsigned,
                target,
                urls: url,
            })
            .await
        }
        Command::Fetch {
            manifest,
            expect_identity,
            expect_issuer,
            allow_unsigned,
            production,
            trust_root,
            url,
            output,
        } => {
            let target = if let Some(path) = trust_root {
                sigstore::Target::Custom(sigstore::CustomTarget {
                    trust_root_path: Some(path.to_string_lossy().into_owned()),
                    ..Default::default()
                })
            } else if production {
                sigstore::Target::Production
            } else {
                sigstore::Target::Staging
            };
            fetch::fetch(fetch::Options {
                manifest,
                expect_identity,
                expect_issuer,
                allow_unsigned,
                target,
                url_override: url,
                output,
            })
            .await
        }
    }
}
