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

use anyhow::{Context, Result, anyhow, bail};
use sigstore_trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, SIGSTORE_STAGING_TRUSTED_ROOT};
use sigstore_types::Bundle;
use sigstore_verify::{VerificationPolicy, verify as sig_verify};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Env {
    Staging,
    Production,
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
pub async fn sign_manifest(manifest_bytes: &[u8], env: Env) -> Result<Vec<u8>> {
    use sigstore_oidc::{IdentityToken, get_identity_token};
    use sigstore_sign::SigningContext;

    let context = match env {
        Env::Staging => SigningContext::staging(),
        Env::Production => SigningContext::production(),
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
    env: Env,
) -> Result<Verified> {
    let root_json = match env {
        Env::Staging => SIGSTORE_STAGING_TRUSTED_ROOT,
        Env::Production => SIGSTORE_PRODUCTION_TRUSTED_ROOT,
    };
    let trusted_root = sigstore_trust_root::TrustedRoot::from_json(root_json)
        .context("loading embedded trusted root")?;

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
