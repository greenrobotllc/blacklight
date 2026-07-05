# blacklight — Design

Verified-streaming downloads anchored in the Sigstore transparency log.

blacklight downloads a file from an **untrusted** network and mirror, verifying
every 16 KiB chunk group against a signed BLAKE3 Merkle root *as the bytes
arrive*, and aborting the transfer on the first tampered byte. The root is
authorized by a keyless Sigstore signature that is recorded in the public Rekor
transparency log, so the identity that published the root is provable and
publicly auditable.

This document is the engineering reference: goals, threat model, the end-to-end
trust chain, the on-disk and on-wire formats, the `fetch` state machine, the
end-to-end argument for why weaker schemes fail, and the limitations.

Everything here is grounded in the actual code. Key modules:

| Module | Responsibility |
| --- | --- |
| [`src/main.rs`](../src/main.rs) | CLI (`clap`), subcommand dispatch, exit-code mapping |
| [`src/publish.rs`](../src/publish.rs) | hash file, build outboard, write manifest, sign |
| [`src/fetch.rs`](../src/fetch.rs) | verify bundle, fetch outboard, stream + verify, finalize |
| [`src/verify.rs`](../src/verify.rs) | forward-only fail-fast BLAKE3 group verifier (`GroupPlan`) |
| [`src/manifest.rs`](../src/manifest.rs) | the signed manifest document |
| [`src/sigstore.rs`](../src/sigstore.rs) | keyless signing + offline verification wrappers |

---

## 1. Goals and non-goals

### Goals

- **End-to-end integrity.** The client accepts artifact bytes only if they hash
  up to a root that a named publisher signed. No hop in the delivery path (WiFi,
  ISP, CDN, mirror) is trusted with byte integrity.
- **Fail fast, mid-stream.** Detect tampering at the first bad 16 KiB group and
  abort the transfer, rather than after downloading the whole file. At most one
  chunk group (16 KiB) is fetched past the tampered byte.
- **Publicly auditable provenance.** Every signature is a keyless Sigstore
  signature recorded in Rekor, so *who* signed a given root is a matter of
  public record, and a compromised signing identity is detectable after the fact.
- **Offline verification.** `fetch` verifies the signature, the Fulcio
  certificate chain, and the Rekor inclusion proof against an *embedded* trusted
  root, with no network round-trip to Sigstore at fetch time.
- **Policy before bytes.** The required signer identity and OIDC issuer are
  enforced *before any artifact byte is downloaded*.
- **Small overhead.** The outboard Merkle tree adds ~0.4% (measured 0.39% on the
  demo artifact) to what the publisher hosts.

### Non-goals (v1)

- **Rollback / freshness.** An attacker who serves a *stale but validly signed*
  older version is not stopped. Freshness is TUF's domain; blacklight has no
  version/timestamp metadata that a client can require to be current.
- **Availability of the outboard.** If the `.obao` sidecar is missing or
  withheld, `fetch` fails closed (cannot build a plan) but blacklight does not
  provide redundancy or a fallback.
- **Active transparency-log monitoring.** blacklight verifies a Rekor *inclusion
  proof* offline; it does not run a witness or continuously monitor the log for
  rogue entries under a given identity. That is deferred to `rekor-monitor` /
  witness infrastructure.
- **Self-managed signing keys.** sigstore-rust 0.10 exposes no self-managed-key
  path. Signing is **keyless only** (OIDC → Fulcio short-lived cert).
- **Confidentiality.** blacklight is an integrity/provenance tool. It does not
  encrypt artifacts.

---

## 2. Threat model

The trust boundary: **the publisher's Sigstore identity is trusted; everything
between the publisher and the client is not.** The WiFi link, the network, the
ISP, the CDN, and the mirror can all read and rewrite any bytes in transit. What
they cannot do is forge a Sigstore signature that verifies against the embedded
trusted root under the identity + issuer the client demands.

| Attacker capability | blacklight's defense |
| --- | --- |
| Flip / rewrite bytes of the **artifact** in transit (MITM, malicious CDN/mirror) | Each 16 KiB group is checked against the signed root the instant it completes ([`GroupPlan::check_group`](../src/verify.rs)); first mismatch → `TamperError`, exit 3, partial file deleted, byte offset reported |
| **Truncate** the artifact stream (drop the tail) | Exact length check: `total != plan.size()` and `group_index != plan.group_count()` are `TamperError` ([`stream_verified_inner`](../src/fetch.rs)) |
| **Pad / append** bytes to the artifact | Same length check fails; and any group past the signed count has no expected CV (`VerifyError::LongStream`) |
| Tamper with the **`.obao` outboard** tree | The outboard is reconstructed top-down and its computed root compared to the signed root in `GroupPlan::new`; a mismatch is `OutboardRootMismatch` / `BadOutboard`, caught *before* streaming any artifact byte |
| Tamper with the **manifest** JSON (change root, size, name, URLs) | The Sigstore bundle signs the exact manifest bytes; `sigstore::verify_manifest` rejects any change before the manifest is even parsed ([`fetch.rs`](../src/fetch.rs) verifies bytes, *then* `Manifest::from_bytes`) |
| Add extra JSON fields to the manifest to smuggle data | `#[serde(deny_unknown_fields)]` on `Manifest` rejects unknown keys |
| Serve a **different file** signed by someone else | Client passes `--expect-identity` + `--expect-issuer`; `VerificationPolicy::require_identity/require_issuer` enforces an exact SAN + issuer match |
| Present a **valid signature by the wrong issuer** (e.g. attacker's own Google account) | Issuer is pinned by `--expect-issuer`; a signature from an unexpected OIDC issuer fails the policy |
| Strip the signature and serve an **unsigned** manifest | Without `--allow-unsigned`, a missing/invalid bundle is a hard failure ("refusing to download"). `--allow-unsigned` is opt-in and loudly warned |
| Forge a **Rekor inclusion proof** | The inclusion proof is checked against Rekor's key material in the embedded trusted root; a forged proof does not verify |
| **Compromise the publisher's signing identity** and sign a malicious root | *Detectable, not prevented.* Every signature is in the public Rekor log, so a rogue signature under the publisher's identity is discoverable by log monitoring (out of scope for v1, see §8) |
| Serve a **stale but validly signed** older version | **Out of scope (v1).** No freshness metadata; see non-goals |
| Downgrade TLS / present a bad TLS cert | Irrelevant to integrity — blacklight does not rely on TLS for artifact integrity; the artifact URL may even be plain `http://`. TLS is orthogonal (see §6) |

A network read error (connection reset, timeout) is explicitly **not**
tampering: it is surfaced as an ordinary error (exit 1), kept distinct from an
integrity violation (exit 3) so scripts and tests can tell them apart
([`stream_verified_inner`](../src/fetch.rs) wraps stream errors with `network
error reading …`).

---

## 3. Trust chain, end to end

The chain runs from a human/CI OIDC identity all the way down to a single
streamed 16 KiB group. Each link is verified; no link is assumed.

```
OIDC identity (email or workload URI, at a named issuer)
        │  proven at signing time by the OIDC token
        ▼
Fulcio short-lived certificate  (SAN = identity, extension = issuer)
        │  chains to a CA in the embedded trusted root
        ▼
Signature over the exact manifest bytes
        │  covers {v, name, size, blake3_root, chunk_group_log, urls}
        ▼
Rekor inclusion proof  (this signature is in the public transparency log)
        │  verified offline against Rekor key material in the trusted root
        ▼
blake3_root  (the signed 32-byte BLAKE3 Merkle root of the file)
        │  bound because it is a field of the signed manifest
        ▼
per-16-KiB-group leaf chaining values  (reconstructed from the .obao,
        │  and checked to hash back up to blake3_root in GroupPlan::new)
        ▼
each streamed 16 KiB group  (its recomputed CV must equal the expected leaf CV)
```

Concretely:

1. **Identity → certificate.** At publish time, `sigstore::sign_manifest`
   obtains an OIDC identity token — ambient CI credentials via
   `IdentityToken::detect_ambient()` if present, otherwise an interactive
   browser flow via `get_identity_token`. Fulcio issues a short-lived
   certificate whose Subject Alternative Name is the identity and which records
   the OIDC issuer.

2. **Certificate → signature → log.** The `SigningContext` signer signs the
   manifest bytes; the signature and a Rekor inclusion proof are stapled into a
   **Sigstore v0.3 bundle** (`bundle.to_json_pretty()`).

3. **Signature → root (verification).** At fetch time, `sigstore::verify_manifest`
   loads the *embedded* trusted root
   (`SIGSTORE_STAGING_TRUSTED_ROOT` / `SIGSTORE_PRODUCTION_TRUSTED_ROOT`),
   parses the bundle, and runs `sigstore_verify::verify` over the raw manifest
   bytes with a `VerificationPolicy` that requires the exact identity + issuer.
   This checks the signature, the Fulcio cert chain, and the Rekor inclusion
   proof **offline**. Only after this succeeds does [`fetch.rs`](../src/fetch.rs)
   call `Manifest::from_bytes` and trust `blake3_root`.

4. **Root → leaf CVs.** `GroupPlan::new(root, size, outboard)` walks the
   outboard tree top-down, reconstructing each group's expected leaf chaining
   value, and verifies the whole tree hashes back up to `root`. A tampered
   outboard cannot reach the signed root and is rejected here.

5. **Leaf CV → streamed group.** As each 16 KiB group lands,
   `GroupPlan::check_group` recomputes its BLAKE3 chaining value with the correct
   input offset and compares it to the expected leaf CV. First mismatch aborts.

Because the manifest is verified as **raw bytes before parsing**, and it fixes
`chunk_group_log`, the *tree geometry itself* is part of the signed statement —
an attacker cannot re-shape the tree to smuggle bytes.

---

## 4. On-disk and on-wire formats

`publish` emits three sidecars next to the artifact. The publisher hosts four
files total: the artifact, the `.obao`, the manifest, and the bundle.

| File | Suffix | Contents |
| --- | --- | --- |
| Artifact | *(none)* | The original file, byte-for-byte |
| Outboard | `.obao` | Pre-order BLAKE3 Merkle tree at 16 KiB groups |
| Manifest | `.blacklight.json` | Signed JSON binding root, size, geometry |
| Bundle | `.blacklight.json.sigstore.json` | Sigstore v0.3 bundle over the manifest bytes |

Suffixes are defined once in [`src/manifest.rs`](../src/manifest.rs):
`MANIFEST_SUFFIX = ".blacklight.json"`, `OUTBOARD_SUFFIX = ".obao"`,
`BUNDLE_SUFFIX = ".sigstore.json"`.

### 4.1 Manifest JSON

The manifest is the small signed document. Schema (from the `Manifest` struct):

| Field | Type | Meaning |
| --- | --- | --- |
| `v` | u32 | Format version. Must be `1`. |
| `name` | string | Basename of the artifact (informational; default output name). |
| `size` | u64 | Exact file length in bytes. |
| `blake3_root` | string | 64-hex-char BLAKE3 root hash. Equals `blake3::hash(file)`. |
| `chunk_group_log` | u8 | Log2 of chunk-group size in 1 KiB chunks. Fixed at `4` (16 KiB) for v1. |
| `urls` | array of strings | Optional artifact URL hints. Omitted when empty. |

It is serialized with `serde_json::to_vec_pretty` plus a trailing newline
(`Manifest::to_bytes`). There is **deliberately no canonicalization**: the exact
bytes the publisher signed are the exact bytes the client must present and
verify. Parsing uses `#[serde(deny_unknown_fields)]`, and `from_bytes` rejects
any `v != 1`, any `chunk_group_log != 4`, and any non-hex root.

Real example (`demo.bin`, 32 MiB):

```json
{
  "v": 1,
  "name": "demo.bin",
  "size": 33554432,
  "blake3_root": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
  "chunk_group_log": 4,
  "urls": [
    "https://mirror.example.org/demo.bin"
  ]
}
```

(The `blake3_root` above is illustrative; the real value is printed by
`publish` as `root <hex>`.)

### 4.2 The `.obao` outboard tree

The outboard is built by the `bao-tree` crate (`PreOrderOutboard::create` with
`BlockSize::from_chunk_log(4)`). "Outboard" means the tree lives in a **separate
file** from the artifact — the artifact stays byte-for-byte identical, and the
tree is a ~0.4% sidecar.

Layout: a **pre-order** sequence of 64-byte parent nodes, each node being a pair
`(left CV, right CV)` of 32-byte BLAKE3 chaining values. Leaf chaining values are
**not** stored — they are exactly the child CVs held in the lowest parents, and
the client recomputes each leaf from the streamed data. Grouping chunks into
16 KiB blocks reduces the number of parents ~16× versus per-1-KiB-chunk BLAKE3,
which is where the low overhead comes from.

Crucially, **the outboard's root equals `blake3::hash(file)`**. Chunk grouping
changes only the *layout* of the outboard, not the hashing math: BLAKE3's tree
is defined over 1 KiB chunks regardless, and a 16 KiB group is just a subtree of
16 chunks. The unit test `plan_root_matches_blake3` in
[`src/verify.rs`](../src/verify.rs) asserts `ob.root == blake3::hash(&data)`
across many sizes, which is what lets a single BLAKE3 root in the manifest
authorize the grouped tree.

Edge cases the verifier encodes:

- **Empty file (`size == 0`):** root is `blake3::hash(b"")`; zero groups.
- **Single group (`size <= 16 KiB`):** the whole file is one leaf whose *root*
  hash is the trusted root; the outboard is empty (no parents). `GroupPlan::new`
  rejects a non-empty outboard here (`"single-group outboard must be empty"`).
- **Trailing bytes / short outboard:** rejected as `BadOutboard`.

### 4.3 The Sigstore bundle

`.blacklight.json.sigstore.json` is a **Sigstore v0.3 bundle** (`sigstore-types`
`Bundle`): the signature over the manifest bytes, the Fulcio signing
certificate, and the Rekor inclusion proof, as JSON. It is self-contained enough
for offline verification against the embedded trusted root — no call to
Fulcio/Rekor at fetch time.

### 4.4 The trust root (public and private deployments)

Verification is anchored in a **trust root** — the set of Fulcio CA
certificates, Rekor public keys, and timestamp-authority keys that the verifier
considers authoritative. It is the one thing a client must obtain out-of-band;
everything else (the bundle, the manifest, the artifact) can come from an
untrusted mirror. The trust root is *public* data (it contains only public keys
and certificates), so distributing it is safe.

blacklight selects the trust root via `sigstore::Target` (see
[`src/sigstore.rs`](../src/sigstore.rs)):

- **`Staging` / `Production`** use the trust roots **embedded** in
  `sigstore-trust-root` (`SIGSTORE_STAGING_TRUSTED_ROOT` /
  `SIGSTORE_PRODUCTION_TRUSTED_ROOT`) — no file needed.
- **`Custom`** (a self-hosted / private Sigstore) loads the trust root from a
  file via `TrustedRoot::from_file`, supplied with `--trust-root`. An operator
  exports this JSON from their deployment's **TUF** root of trust (the standard
  way Sigstore distributes and rotates trust material) and ships it to clients.

On the **signing** side, `Custom` builds a `SigningConfig` from the public-good
defaults and overrides only the endpoints the operator provides
(`--rekor-url`/`--fulcio-url`/`--oidc-url`), so a private Rekor/Fulcio/SSO can be
mixed and matched. The signing endpoints are *not* needed at verification time —
the bundle's stapled inclusion proof plus the trust root are sufficient, and
`fetch` never contacts the private Rekor. `--trust-root` is required for a
private deployment (blacklight will not silently fall back to a public root) and
is mutually exclusive with `--production`.

This is the mechanism behind the "private transparency log for internal/VPN
distribution" use case: the design does not change, only which log and which
trust root are in play.

**Security note for self-hosters.** Running a private Fulcio + Rekor turns two
normally distributed-trust systems into single-operator systems, and that shift
is the whole security burden:

- **Fulcio's CA key is existential** — it can mint a cert for any accepted
  identity, and short-lived certs have no per-cert revocation (recovery is via
  the TUF root only). Keep the root offline (hardware) and the online signing
  key non-exportable in an HSM/KMS.
- **A private log must still be watched.** A single operator can mount a
  split-view/fork attack that inclusion and consistency proofs alone don't
  detect. Deploy `rekor-monitor` (consistency + identity monitoring), add
  independent witnesses that co-sign checkpoints, or dual-log to the public
  Rekor. An unmonitored private log provides no non-equivocation guarantee.
- **Constrain the OIDC issuer** (audience `sigstore`, exact issuer pinning,
  verified claims, 2FA) and **threshold-sign an offline, multi-party TUF root**;
  add an RFC 3161 timestamp authority and rollback-resistant backups.
- **Reduced-trust reality:** a single-org private log gives internal
  auditability and privacy, but *not* the public instance's "many independent
  watchers" property. It is only as trustworthy as the party running it. See
  Sigstore's threat model (https://docs.sigstore.dev/about/threat-model/) and
  security model (https://docs.sigstore.dev/about/security/).

---

## 5. The `fetch` state machine

From [`src/fetch.rs`](../src/fetch.rs). Each stage gates the next; nothing about
the artifact is trusted until both the bundle and every group have verified.

```
                 ┌─────────────────────────────┐
                 │ 1. LOAD manifest bytes       │  load() — URL or local path
                 │    (raw, unparsed)           │
                 └──────────────┬──────────────┘
                                │
              --allow-unsigned? ─┴─ no ──► ┌──────────────────────────────────┐
                    │ yes                  │ 2. VERIFY BUNDLE (offline)         │
                    │  (warn loudly)       │    sigstore::verify_manifest       │
                    │                      │    - signature over manifest bytes │
                    │                      │    - Fulcio cert chain             │
                    │                      │    - Rekor inclusion proof         │
                    │                      │    - require identity + issuer     │
                    │                      │    FAIL ► exit 1, no download       │
                    └──────────┬───────────┴────────────┬─────────────────────┘
                               │                         │ ok
                               ▼                         ▼
                 ┌─────────────────────────────────────────────┐
                 │ 3. PARSE manifest  (Manifest::from_bytes)     │  now trusted
                 │    extract blake3_root, size                  │
                 └───────────────────────┬──────────────────────┘
                                         ▼
                 ┌─────────────────────────────────────────────┐
                 │ 4. FETCH outboard  (.obao, downloaded fully)  │
                 └───────────────────────┬──────────────────────┘
                                         ▼
                 ┌─────────────────────────────────────────────┐
                 │ 5. BUILD + SELF-CHECK GroupPlan               │
                 │    GroupPlan::new(root, size, outboard)       │
                 │    tampered .obao ► TamperError, no download   │
                 └───────────────────────┬──────────────────────┘
                                         ▼
                 ┌─────────────────────────────────────────────┐
                 │ 6. STREAM artifact into <out>.blacklight-     │
                 │    partial; buffer 16 KiB groups              │
                 │    each full group ► GroupPlan::check_group    │
                 │      mismatch ► TamperError (exit 3):          │
                 │        delete partial, report byte offset      │
                 │    final short group verified too             │
                 │    length + group-count must match exactly     │
                 └───────────────────────┬──────────────────────┘
                                         ▼
                 ┌─────────────────────────────────────────────┐
                 │ 7. FINALIZE: flush, fsync, atomic rename into  │
                 │    place. On ANY error the partial is removed. │
                 └─────────────────────────────────────────────┘
```

Notes:

- **Streaming buffer.** `stream_verified_inner` pulls `reqwest` byte chunks and
  re-buckets them into exactly `GROUP_LEN` (16 KiB) groups regardless of how the
  transport framed them, verifying each complete group before writing it.
- **No partial ever looks good.** The download goes to a
  `.blacklight-partial` temp file; on any failure it is deleted, and only a
  fully verified file is atomically `rename`d into place. This is why the
  integration tests assert `!out.exists()` after a tampered fetch.
- **URL resolution.** The artifact URL is: `--url` override, else the manifest
  location with `.blacklight.json` stripped, else the first manifest `urls` hint
  (`resolve_artifact_url`). Integrity never depends on which of these is used.
- **Exit codes.** `TamperError` → exit **3** (mapped in
  [`src/main.rs`](../src/main.rs)); any other error → exit **1**; success → **0**.

---

## 6. Why weaker schemes don't stop a MITM (the end-to-end argument)

The folk instinct — "check the hash and hackers can't tamper with your download"
— is correct in spirit but fails in every common instantiation, because of the
classic end-to-end argument: an integrity check is only as strong as the trust
you have in *where the reference value came from* and *when you check it*.

- **In-band / same-channel checksum.** Hosting a `SHA256SUMS` file next to the
  artifact protects nothing against a MITM: the same attacker who rewrites the
  artifact also rewrites the checksum file. Both travel the same untrusted
  channel. There is no independent anchor.

- **A weak or broken hash (MD5).** MD5 is collision-broken; an attacker can craft
  a malicious artifact that matches a published MD5. Even a strong hash doesn't
  help if it's delivered in-band (previous point). blacklight uses BLAKE3 *and*
  anchors the root in a signature.

- **TLS "protects the download."** TLS authenticates the *server you connected
  to* and encrypts the hop, but (a) it says nothing about whether that server —
  a CDN edge, a mirror — is honest about the bytes, (b) a compromised or
  malicious mirror serves tampered bytes over perfectly valid TLS, and (c) TLS
  blinds *you* to the network layer, so you cannot inspect what arrived. TLS is
  transport security, not artifact provenance. blacklight deliberately does not
  depend on it: the artifact URL can be plain `http://` and integrity is
  unchanged.

- **Network-level / middlebox integrity checking.** Any check performed by the
  network (a proxy, a middlebox, an "integrity-verifying CDN") is performed by a
  party inside the untrusted region. It can lie about the result.

The end-to-end fix, which blacklight implements: the integrity reference (the
BLAKE3 root) must be **bound to a publisher identity by a signature**, that
signature must be **publicly auditable** (Rekor), the reference must be verified
**at the client** against an **out-of-band anchor** (the embedded trusted root),
and the artifact bytes must be checked against it **as they arrive** — not by a
hop in the middle, and not after the whole (possibly malicious) file has already
been consumed.

---

## 7. Prior art: where this is, and is not, novel

It is worth stating plainly what blacklight does *not* invent, because both of
its ingredients are independently and widely deployed.

**Merkle-verified streaming is not new — the Linux kernel does it at scale.**
`dm-verity` is a Merkle tree over a read-only block device, verifying each 4 KiB
block against a signed root hash on page-in (Android Verified Boot, ChromeOS,
immutable distros). `fs-verity` is the per-file equivalent (Merkle tree past
end-of-file, verified per page; the basis of Android APK and Fedora RPM file
integrity). IMA/EVM add measured boot and on-access appraisal. blacklight's
per-16 KiB-group verification is the *same technique* applied to a different
deployment shape: a fresh transfer from an untrusted *remote* mirror, aborting
mid-stream, rather than a local, already-provisioned read-only volume. The kernel
mechanisms anchor trust in a local key (kernel keyring / MOK / TPM), never a
public transparency log or an identity.

**Transparency-log-anchored, identity-bound signing is not new either.** npm
provenance and PyPI PEP 740 attestations already sign packages keylessly via
Sigstore and log them to Rekor; experimental `apt-rekor`/`apt-cosign` plugins
require Debian archive metadata to appear in Rekor before `apt update` proceeds.
Go's checksum database is a deployed tiled-Merkle transparency log — though it
proves *non-equivocation*, not identity.

**Content-addressing + signing is table stakes** in modern distribution:
OSTree/rpm-ostree, Nix, Guix, and Flatpak all pair a content-addressed store with
signatures over roots/commits. Positioning blacklight as "content-addressed
distribution" would be redundant.

**So what is the contribution?** The *composition*, in one deployment shape: a
transparency-logged, **identity-bound** signature over a Merkle root that
authorizes chunk-granular, abort-on-first-bad-byte verification of a download
from an untrusted mirror, with a signer-identity policy enforced before byte one.
That specific combination we could not find already built — and even it is
adjacent to the apt/Rekor and registry-provenance work, and can be expected to
narrow as Sigstore spreads through OS distribution. A June 2026 Guix disclosure
(files written during download *before* hash verification; substitute URLs left
unprotected by signatures) is field evidence that the failure modes this design
targets remain live in shipping distros — but note their fix ("verify before
writing") needs neither a Merkle tree nor a transparency log, so it does not by
itself validate the full blacklight design, only the verify-during-transfer half.

For a fuller treatment (kernel integrity, package managers, immutable distros,
and the mostly-social barriers to landing any of this in a distribution) see the
related-work section of [`../paper/PAPER.md`](../paper/PAPER.md) and the
[open enhancement issues](https://github.com/greenrobotllc/blacklight/issues)
on log-agnostic verification (sigsum, not only Rekor) and package-manager
augment mode.

### 7.1 Sigstore vs. sigsum — and what supporting both would take

blacklight anchors transparency and identity in **Sigstore** (Fulcio + Rekor).
That is a deliberate choice with a real tradeoff, and the alternative worth
knowing about is **[sigsum](https://www.sigsum.org/)**. They are not competitors
so much as different points in the design space:

| Property | Sigstore / Rekor (today) | Sigsum |
| --- | --- | --- |
| Identity binding | **Yes** — OIDC identity → short-lived Fulcio cert | **No** — logs a signed checksum, not *who* signed via which issuer |
| Non-equivocation | Via a stapled inclusion proof (SCT / Rekor proof) | Via **witness cosigning** — a tree head is valid only if a *threshold of independent witnesses* cosigns it |
| OIDC dependency | **Yes** (a centralization / liveness concern for some) | **No** |
| Decentralization | More centralized public-good instance | Designed around multiple independent witnesses + gossip |
| Operational weight | Heavier (CA + log + OIDC) | Lighter (log + witnesses; you bring your own key) |

The distinction matters for adoption: communities that want transparency but
distrust a central log or an OIDC dependency (notably some Linux distributions —
Debian's package-transparency planning leans toward sigsum + multiple witnesses)
would reject the Sigstore dependency outright. Conversely, sigsum alone does
**not** give blacklight its identity policy (`--expect-identity`/`--expect-issuer`),
which is central to the current threat model. So the honest conclusion is
**support both**, and let the operator state which properties they require
(identity-bound, or witnessed-non-equivocation, or both where a deployment layers
them).

**What supporting sigsum would take** (design sketch — full spec in
[issue #18](https://github.com/greenrobotllc/blacklight/issues/18)):

1. A `TransparencyBackend` trait in the verification core: given the signed
   manifest plus a proof bundle, verify inclusion **offline** and return the
   attested identity *if the backend provides one* (Rekor does; sigsum does not).
   Rekor becomes one implementation, sigsum another.
2. A sigsum verifier that checks a submission's cosigned tree head against a
   configured **witness policy** (which witnesses, what threshold) — this replaces
   Rekor's inclusion proof as the "it's really logged" evidence.
3. A manifest/bundle descriptor field naming the backend, so `fetch` knows how to
   verify what it was handed (coordinate with the manifest-v2 work).
4. A policy model that lets a caller require *"logged + witnessed"* separately from
   *"identity-bound"*, and — critically — **refuses to assert an identity when the
   backend cannot prove one**. Overclaiming identity under sigsum would be a
   security bug, not a convenience.
5. CLI surface: `--transparency rekor|sigsum` on publish; a witness/identity policy
   on fetch.

Keeping verification offline is preserved either way: sigsum's witness
cosignatures and Rekor's stapled proof both support offline checking, so no
fetch-time log round-trip is introduced.

---

## 8. Limitations and future work

> The consolidated, user-facing list of every caveat (with what each means for
> you) lives in [`CAVEATS.md`](CAVEATS.md). This section is the engineering view.

- **Rollback / freshness (biggest gap).** A validly signed *older* version
  replays cleanly. Mitigation is TUF-style metadata (version, timestamp,
  expiry) that the client can require to be current. Not in v1.
- **Log monitoring.** blacklight verifies a Rekor inclusion proof but does not
  monitor the log for rogue entries under a publisher's identity. A compromised
  signing identity is *detectable* only if someone is watching the log
  (`rekor-monitor` / witnesses). Making key-compromise *auditable in practice*
  needs that external piece.
- **Keyless only.** No self-managed-key signing path exists in sigstore-rust
  0.10, so air-gapped or offline signing is not supported.
- **Outboard availability.** A withheld `.obao` fails the fetch closed but there
  is no redundancy/fallback.
- **Fixed geometry.** `chunk_group_log` is pinned at 4 (16 KiB) for format v1.
  Larger artifacts might prefer larger groups (fewer parents, coarser abort
  granularity); this would be a v2 format bump.
- **Single artifact URL at a time.** No multi-source / range-parallel fetching;
  the verifier is forward-only by design (see below), which trades random-access
  speed for strict abort-on-first-bad-byte semantics.

### Why the verifier is hand-rolled

`bao-tree` ships a verifier (`valid_ranges`), but it needs *seekable* (random
access) data and it signals corruption by *omitting* a range from its result
rather than raising an error — the opposite of the "stop the instant a byte is
wrong, forward-only, over a stream" behavior that is the entire point here. So
[`src/verify.rs`](../src/verify.rs) implements a forward-only, fail-fast verifier
directly on the public `blake3::hazmat` chaining-value API (the same primitives
`bao-tree` uses internally): it reconstructs the expected per-group leaf CVs from
the outboard once (checking the tree up to the trusted root), then stream-checks
each 16 KiB group's recomputed CV as it lands. It is unit-tested for round-trip
equivalence with `bao-tree`'s own outboard format (`plan_root_matches_blake3`,
`detects_single_byte_flip_in_each_group`, `detects_tampered_outboard`,
`detects_wrong_root`).

---

## Appendix: primitives and versions

All cryptographic primitives pre-exist; blacklight's contribution is the
*composition*.

| Component | Crate / version | Role |
| --- | --- | --- |
| Content hash + tree math | `blake3` 1.8.5 (hazmat API) | leaf CVs, subtree merges, root |
| Outboard tree engine | `bao-tree` 0.16 (n0-computer; the engine behind iroh-blobs) | pre-order 16 KiB-group outboard |
| Keyless signing/verify | `sigstore-{sign,verify,oidc,trust-root,types}` 0.10 (prefix-dev sigstore-rust; aws-lc-rs backend) | OIDC → Fulcio → Rekor; offline verify |
| Transport | `reqwest` 0.13 + `tokio` 1.52 | streaming HTTP |
| CLI | `clap` 4 | argument parsing |

Rust edition 2024, MSRV ~1.85+.
