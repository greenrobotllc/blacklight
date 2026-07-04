//! Sigstore signing and verification, wrapped behind small functions so the
//! rest of blacklight never depends on the exact sigstore-rust API (which
//! churns fast at 0.x). See docs/DESIGN.md for the trust chain.
//!
//! Signing is **keyless only**: sigstore-rust 0.10 has no path for a
//! self-managed private key, so `publish` obtains an OIDC identity (ambient CI
//! credentials if present, otherwise an interactive browser flow) and Fulcio
//! issues a short-lived certificate bound to that identity. The signature and a
//! Rekor inclusion proof are stapled into a v0.3 bundle.
//!
//! Verification is offline: the trusted roots for staging and production are
//! embedded in `sigstore-trust-root`, so `fetch` verifies the signature, the
//! certificate chain, and the Rekor inclusion proof without any network call —
//! and enforces the caller's identity policy (exact SAN + issuer match).
//!
//! # Private / self-hosted Sigstore
//!
//! Anyone — a company behind a VPN, a nonprofit, or an individual experimenting
//! locally — can run their own Fulcio + Rekor (and OIDC issuer) so that
//! artifacts are logged to a *private* transparency log rather than the
//! public-good instance. Point `publish` at those endpoints
//! (`--rekor-url`/`--fulcio-url`/`--oidc-url`) and give `fetch` the matching
//! trust root exported from that deployment (`--trust-root`). Everything else —
//! the trust chain, the offline verification, the identity policy — is
//! identical.

use anyhow::{Context, Result, anyhow, bail};
use sigstore_trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, SIGSTORE_STAGING_TRUSTED_ROOT};
use sigstore_types::Bundle;
use sigstore_verify::{VerificationPolicy, verify as sig_verify};

/// Which Sigstore infrastructure to sign against / verify with.
#[derive(Debug, Clone)]
pub enum Target {
    /// Sigstore staging (default; good for tests and demos).
    Staging,
    /// The Sigstore public-good production instance.
    Production,
    /// A self-hosted / private Sigstore deployment — anyone running their own
    /// Fulcio + Rekor (a company behind a VPN, a nonprofit, or an individual
    /// experimenting locally). Endpoints are only needed for signing;
    /// verification is offline against `trust_root_path`.
    Custom(CustomTarget),
}

/// Endpoints and trust root for a private Sigstore deployment.
#[derive(Debug, Clone, Default)]
pub struct CustomTarget {
    /// Fulcio (certificate authority) base URL. Signing only.
    pub fulcio_url: Option<String>,
    /// Rekor (transparency log) base URL. Signing only.
    pub rekor_url: Option<String>,
    /// OIDC issuer URL used to obtain the identity token. Signing only.
    pub oidc_url: Option<String>,
    /// Path to the deployment's trust root JSON (exported from its TUF root).
    /// Required to verify bundles produced by this deployment.
    pub trust_root_path: Option<String>,
}

/// Identity policy the verifier enforces against the signing certificate.
#[derive(Debug, Clone)]
pub struct IdentityPolicy {
    pub identity: String,
    pub issuer: String,
}

/// Result of a successful verification, surfaced to the user.
#[derive(Debug, Clone)]
pub struct Verified {
    pub identity: String,
    pub issuer: String,
    /// Rekor integrated time (unix seconds), if the entry carried one.
    pub integrated_time: Option<i64>,
}

/// Sign the manifest bytes keyless and return the serialized v0.3 bundle JSON.
pub async fn sign_manifest(manifest_bytes: &[u8], target: &Target) -> Result<Vec<u8>> {
    use sigstore_oidc::{IdentityToken, get_identity_token};
    use sigstore_sign::{SigningConfig, SigningContext};

    let context = match target {
        Target::Staging => SigningContext::staging(),
        Target::Production => SigningContext::production(),
        Target::Custom(c) => {
            // Start from the public-good defaults and override the endpoints
            // the operator supplied, so anything they omit falls back sanely.
            let mut config = SigningConfig::default();
            if let Some(u) = &c.fulcio_url {
                config.fulcio_url = u.clone();
            }
            if let Some(u) = &c.rekor_url {
                config.rekor_url = u.clone();
            }
            if let Some(u) = &c.oidc_url {
                config.oidc_url = Some(u.clone());
            }
            SigningContext::with_config(config)
        }
    };

    // Prefer zero-interaction ambient CI credentials; fall back to browser/OOB
    // only when there genuinely is no ambient identity. A detection *error*
    // (e.g. an id-token endpoint that is present but failing) is surfaced, not
    // silently swallowed — otherwise a broken CI signing setup would quietly
    // pop a browser that no one is watching.
    let token: IdentityToken = match IdentityToken::detect_ambient().await {
        Ok(Some(t)) => {
            eprintln!("  using ambient CI OIDC identity");
            t
        }
        Err(e) => {
            return Err(anyhow!("ambient OIDC detection failed: {e}")).context(
                "an ambient CI identity was present but could not be used; \
                 refusing to fall back to an interactive browser flow",
            );
        }
        Ok(None) => {
            eprintln!("  no ambient CI identity; opening browser for OIDC sign-in …");
            get_identity_token(context.config().oidc_url.as_deref())
                .await
                .context("could not obtain an OIDC identity token")?
        }
    };

    let signer = context.signer(token);
    let bundle = signer
        .sign(manifest_bytes)
        .await
        .context("Fulcio/Rekor signing failed")?;
    let json = bundle.to_json_pretty().context("serializing bundle")?;
    Ok(json.into_bytes())
}

/// Verify the bundle over the manifest bytes, offline, enforcing the policy.
pub fn verify_manifest(
    manifest_bytes: &[u8],
    bundle_json: &[u8],
    policy: &IdentityPolicy,
    target: &Target,
) -> Result<Verified> {
    let trusted_root = load_trust_root(target)?;

    let bundle_str = std::str::from_utf8(bundle_json).context("bundle is not UTF-8")?;
    let bundle = Bundle::from_json(bundle_str).context("parsing Sigstore bundle")?;

    let vpolicy = VerificationPolicy::default()
        .require_identity(&policy.identity)
        .require_issuer(&policy.issuer);

    let result = sig_verify(manifest_bytes, &bundle, &vpolicy, &trusted_root)
        .map_err(|e| anyhow!("bundle verification error: {e}"))?;

    if !result.success {
        bail!("bundle did not verify against the trusted root / identity policy");
    }

    Ok(Verified {
        identity: result.identity.unwrap_or_else(|| policy.identity.clone()),
        issuer: result.issuer.unwrap_or_else(|| policy.issuer.clone()),
        integrated_time: result.integrated_time,
    })
}

fn load_trust_root(target: &Target) -> Result<sigstore_trust_root::TrustedRoot> {
    match target {
        Target::Staging => {
            sigstore_trust_root::TrustedRoot::from_json(SIGSTORE_STAGING_TRUSTED_ROOT)
                .context("loading embedded staging trusted root")
        }
        Target::Production => {
            sigstore_trust_root::TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
                .context("loading embedded production trusted root")
        }
        Target::Custom(c) => {
            let path = c.trust_root_path.as_deref().ok_or_else(|| {
                anyhow!(
                    "a custom Sigstore deployment requires --trust-root <path> to verify \
                     (export it from your deployment's TUF root)"
                )
            })?;
            sigstore_trust_root::TrustedRoot::from_file(path)
                .with_context(|| format!("loading custom trusted root from {path}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_presets_load_their_embedded_roots() {
        assert!(load_trust_root(&Target::Staging).is_ok());
        assert!(load_trust_root(&Target::Production).is_ok());
    }

    #[test]
    fn custom_without_trust_root_gives_actionable_error() {
        let t = Target::Custom(CustomTarget::default());
        let err = load_trust_root(&t).unwrap_err().to_string();
        assert!(err.contains("--trust-root"), "unhelpful error: {err}");
    }

    #[test]
    fn custom_with_missing_trust_root_file_errors_on_the_root() {
        let t = Target::Custom(CustomTarget {
            trust_root_path: Some("/no/such/trust-root.json".into()),
            ..Default::default()
        });
        let err = load_trust_root(&t).unwrap_err();
        // The failure is attributed to loading the custom root, not something else.
        assert!(
            format!("{err:#}").contains("custom trusted root"),
            "wrong error: {err:#}"
        );
    }
}
