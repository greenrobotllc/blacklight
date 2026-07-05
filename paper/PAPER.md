# Blacklight: Verified-Streaming Downloads Anchored in a Public Transparency Log

**Andy Triboletti**
*Draft — iteration one. 2026.*

## Abstract

Software is routinely downloaded over networks that the downloader has no
reason to trust: café WiFi, third-party mirrors, content-delivery networks, and
caching proxies can all rewrite bytes in transit. The folk defense — "publish a
checksum of the file so people can verify what they downloaded" — is correct in
spirit but fails in three specific ways that are worth naming precisely: MD5 (the
checksum most commonly published) is collision-broken and offers no protection
against a deliberate attacker; a checksum delivered over the same channel as the
file can be replaced by the same man-in-the-middle that replaces the file; and
performing the check "at the network level" is impossible for TLS-wrapped
transfers and, more fundamentally, asks the untrusted middle to vouch for the
data it is relaying. The correct place for integrity is the endpoint, and the
correct binding is a *signature* whose authenticity is *publicly auditable*.

We present **blacklight**, a download tool that composes two mature but
previously-uncombined mechanisms into a single trust chain. First, a publisher's
release is bound to a **BLAKE3 Merkle root** and signed with **Sigstore**, so
the signature is keyless (tied to an OIDC identity through a short-lived
certificate) and recorded in the **Rekor public transparency log**. Second, the
client verifies the signed Merkle root *offline*, then **streams** the artifact
and checks every 16 KiB chunk group against that root *as the bytes arrive*,
aborting the transfer at the first byte that does not match. The result is
integrity that is end-to-end (the network is never trusted), first-byte-to-last
(tampering is caught mid-transfer, not after a full download), and publicly
accountable (a compromised publisher key leaves a permanent, monitorable trail
in Rekor).

We want to be careful and honest about what is and is not new here, because it
is easy to overclaim. **Neither** of blacklight's two ingredients is novel on its
own. Merkle-tree *verified access* — verifying data block-by-block against a
signed root as it is read — is well-established and deployed at enormous scale in
the Linux kernel: `dm-verity` is literally a Merkle tree over a block device,
checked per 4 KiB block on page-in (Android, ChromeOS, immutable distros), and
`fs-verity` is the per-file equivalent (the basis of Android APK and Fedora RPM
file integrity). Transparency-log-anchored, identity-bound signing is likewise
already shipping in software distribution — npm provenance, PyPI PEP 740
attestations, and experimental apt/Rekor integrations all bind artifacts to an
identity recorded in a public log. What we could not find is a tool that
*composes* these two into a single verification path — a transparency-logged,
identity-bound signature over a Merkle root that authorizes chunk-granular,
abort-on-first-bad-byte verification of a *fresh transfer from an untrusted
remote mirror*. That specific composition, its trust-chain design, and a working
Rust implementation are the contribution; every underlying primitive pre-exists
and is cited (Section 6). A reproducible attack demonstration shows blacklight
aborting a tampered 32 MiB download after verifying ~16 MB, where the
conventional `curl | sha256sum` pipeline must read the entire file before it can
notice.

## 1. Introduction

### 1.1 A real question, and three tempting wrong answers

Anyone who has watched a host-based firewall light up on an untrusted network —
unexpected connections, requests to domains nothing on the machine should be
contacting — has felt the underlying worry directly: when the network itself may
be actively hostile, how can a download *prove* it arrived intact, automatically,
before it is ever used? Man-in-the-middle attacks on shared and untrusted
networks are well documented, and they are the motivating threat for this work.

This is a question many practitioners have asked in some form: *"I keep hearing
about man-in-the-middle attacks and tampered downloads. Why isn't the download's
checksum just verified automatically, at the network level, so bad bytes are
rejected before they ever reach me?"* It is a good instinct. The reason it does
not already work as imagined is instructive, because each plausible-sounding fix
fails for a different, nameable reason.

*(In plain terms: a "checksum" or "hash" is a short fingerprint computed from a
file's bytes. If two people compute it on the same file they get the same
fingerprint; change one byte and the fingerprint changes completely. The idea is
that a publisher advertises the fingerprint of the real file, and you recompute
it on what you downloaded — if they match, you have the real file. The failures
below are all about why, as usually practiced, that comparison does not actually
stop an attacker.)*

**Wrong answer 1: "Use the MD5 the project publishes."** MD5 collisions have
been practical since 2004, and *chosen-prefix* collisions — where an attacker
crafts a malicious file sharing the MD5 of a benign one — are well within reach.
The Flame malware (2012) exploited exactly this class of weakness to forge a
Microsoft code-signing certificate — using an MD5 chosen-prefix collision that
later cryptanalysis showed was a previously-unknown variant of the technique
[Stevens, CRYPTO 2013; ref. 22]. A defense whose security rests on MD5 gives
zero assurance against the deliberate attacker it is meant to stop. Any serious
design uses a collision-resistant hash; blacklight uses BLAKE3.

*(In plain terms: "collision-broken" means someone can find two different files
that share the same fingerprint. Because there are infinitely many possible
files but only finitely many fingerprints, collisions must exist in principle;
the entire security bet is that finding one on purpose is infeasible. MD5 lost
that bet — a collision takes seconds on a laptop, and a "chosen-prefix"
collision lets an attacker start from a legitimate file and build a malicious
one with the identical MD5. So "the MD5 matches" no longer proves "this is the
real file.")*

Two further problems doom the MD5 workflow even if one imagines the hash were
unbroken, and they matter as much in practice as the cryptographic weakness:

- **It is a manual step, so it is skipped.** Verifying a published checksum by
  hand — copying a hex string, running a command, comparing character by
  character — is tedious enough that in practice almost no one does it. A defense
  that depends on a human reliably performing a chore provides little real
  protection. Verification must be automatic and enforced by the tool.
- **It runs too late.** A flat checksum can only be computed once the *entire*
  file has been downloaded. By the time the comparison happens, the malicious
  bytes are already on disk — possibly already opened, indexed, or auto-executed
  by an eager application. The check, even when performed, comes after the harm
  is possible. The remedy is to verify *during* transfer and abort before the
  bad bytes ever fully land — which is exactly what verified streaming provides
  (Section 2.1) and what motivates blacklight's abort-on-first-bad-byte design.

These three failure modes — *forgeable*, *skipped*, and *too late* — map
directly onto blacklight's three countermeasures: a collision-resistant hash, a
tool that verifies automatically, and streaming verification that stops at the
first bad byte.

**Wrong answer 2: "Deliver the checksum next to the file."** If the attacker can
rewrite the file in transit, it can rewrite the checksum sitting beside it. The
client then dutifully verifies the attacker's file against the attacker's hash
and reports success. This is not a hashing problem; it is a *bootstrapping* (or
trust-anchoring) problem. RFC 9530's `Content-Digest`/`Repr-Digest` headers, for
example, detect accidental corruption but — being in-band and unauthenticated —
do nothing against a MITM unless the digest is independently signed and the
signing key is anchored in something the client already trusts. The fix is a
**digital signature** verifiable against a public key the device trusts a
priori, not a better checksum.

**Wrong answer 3: "Check it at the network level."** Two obstacles. Operationally,
almost all downloads ride inside TLS; the access point or router sees ciphertext
and cannot hash the plaintext artifact without terminating TLS — which is itself
a man-in-the-middle. Architecturally, the deeper problem is that in a MITM
scenario the network *is* the adversary, so putting the integrity check in the
network asks the suspect to vouch for the evidence. This is precisely the
situation the **end-to-end argument** [Saltzer, Reed & Clark 1984] addresses:
a function that can only be completely and correctly implemented with knowledge
held at the endpoints (here, the trusted public key and the expected root hash)
should live at the endpoints. The link layer is not idle in a good design —
WPA3-SAE with protected management frames (802.11w) closes the classic
evil-twin/deauth attacks — but link security is orthogonal to *artifact*
integrity and cannot substitute for it.

**Wrong answer 4 (the ambitious one): "Put it on a blockchain."** The instinct
here is that we want a record an attacker cannot quietly alter. That instinct is
right; the mechanism is over-specified. Blockchain consensus exists so that
mutually distrusting parties can agree on an ordering *without any authority*.
But software has a natural authority — the publisher is the only party entitled
to say what their release should hash to — so the consensus machinery solves a
problem we do not have. What we actually want from "blockchain" is its
*tamper-evident, append-only, publicly auditable* character, and that is exactly
a **Merkle transparency log** (Section 2.2), which delivers non-equivocation and
public auditability without mining, tokens, or global consensus.

### 1.2 What survives, and what we build

Strip the three tempting-but-wrong mechanisms away and three sound requirements
remain, each mapping cleanly to an existing primitive:

1. *Verification should be automatic and enforced, not a manual step users skip.*
   → A signature over a collision-resistant hash, checked by the client before
   the bytes are accepted.
2. *There should be a record of what was published that no one can silently
   rewrite.* → A public append-only Merkle transparency log (Sigstore/Rekor).
3. *Bad bytes should be rejected as early as possible — ideally the tool should
   "stop processing bits" the moment something is wrong.* → **Verified
   streaming**: a signed Merkle tree over the file lets the client verify each
   chunk as it arrives and abort on the first bad one, instead of hashing the
   whole file after the fact.

Blacklight is the tool that puts requirements 2 and 3 into a single trust chain.
The remainder of this paper describes the design (Section 3), the
implementation (Section 4), an evaluation including a reproducible attack demo
(Section 5), how it relates to a substantial body of prior work (Section 6), and
its honest limitations (Section 7).

### 1.3 Contributions

- **A composed trust chain** in which a transparency-logged, keyless signature
  covers a BLAKE3 Merkle *root* that in turn authorizes per-chunk verification
  *during* transfer — closing the gap between "we know who signed this whole
  file" and "we can reject a bad byte before downloading the rest."
- **A working, tested Rust implementation** (`publish`/`fetch`, ~1–2k LOC) built
  on maintained crates (blake3, bao-tree, sigstore-rust) that signs against and
  verifies against the real Sigstore infrastructure.
- **A forward-only, fail-fast streaming verifier** that reproduces BLAKE3's tree
  semantics using the public `blake3::hazmat` API, because the obvious library
  routine (`bao_tree::valid_ranges`) requires seekable data and reports
  corruption as an *omitted range* rather than an error — the wrong shape for
  abort-on-first-bad-byte.
- **A reproducible adversarial demonstration** (a tampering MITM proxy) with
  measured detection latency, contrasted against the conventional
  download-then-hash baseline.

## 2. Background

### 2.1 BLAKE3, Merkle trees, and verified streaming

BLAKE3 [O'Connor, Aumasson, Neves & Wilcox-O'Hearn 2020] is internally a Merkle
tree over 1 KiB input chunks: chunk chaining values are pairwise combined up to a
single root. Because the hash is a tree, a verifier who holds the trusted root
and the interior node hashes can validate any individual chunk or contiguous
range *without* the rest of the file — the property BLAKE3's specification calls
**verified streaming** (§6.4). **Bao** is the reference construction for this,
defining a combined encoding (data interleaved with tree nodes) and an
*outboard* encoding (the tree stored separately from the data). The idea of
verifying subranges of a large file against a signed tree root before the whole
file is present predates BLAKE3: the **Tree Hash EXchange** format (THEX, 2003,
an expired Internet-Draft) used Tiger tree hashes for exactly this in Gnutella
and DC++, and **BitTorrent v2** (BEP 52, shipped 2020) verifies each 16 KiB block
against a per-file SHA-256 Merkle tree during transfer. What all of these share —
and what blacklight adds to — is that the trust root is a bare, unauthenticated
hash: they tell you the bytes match *a* root, not *whose* root.

### 2.2 Transparency logs and Sigstore

A transparency log is a public, append-only Merkle tree of entries that supports
compact *inclusion proofs* ("entry X is in the log") and *consistency proofs*
("the log only grew; nothing was rewritten"), so that even a misbehaving log
operator cannot show different histories to different clients without detection.
The design originates with **Certificate Transparency** [Laurie, Langley & Kasper,
RFC 6962; updated as RFC 9162] and was given a general formal treatment by
**Transparency Overlays** [Chase & Meiklejohn 2016]. Russ Cox's
*Transparent Logs for Skeptical Clients* (2019) and the resulting Go checksum
database (`sum.golang.org`) applied it to software packages at scale.

**Sigstore** [Newman, Meyers & Torres-Arias 2022] combines three services into a
turnkey signing system: an OIDC-federated certificate authority (**Fulcio**) that
issues short-lived certificates binding an ephemeral key to a human/workload
identity, and a transparency log (**Rekor**) that records every signature so it
can be publicly monitored. The output is a self-describing *bundle* containing
the signature, the certificate, and a stapled Rekor inclusion proof — which means
a verifier can check everything **offline** once it holds the trust root.
Blacklight signs the manifest bytes with Sigstore and verifies the resulting
bundle offline against an embedded trust root.

## 3. Design

### 3.1 Threat model

The adversary controls the network path end to end: the WiFi link, the router,
the ISP, the CDN, and any mirror or caching proxy. It can read, drop, reorder,
and — crucially — *rewrite* any bytes of any transfer. It can serve a completely
different file, corrupt selected bytes, truncate, or pad. What it **cannot** do is
forge the publisher's Sigstore signature over the manifest, because that would
require either the publisher's OIDC identity or a Fulcio/Rekor compromise that
would itself be publicly evident.

A separate, weaker adversary is a **compromised publisher signing identity**.
Blacklight does not *prevent* this — no signing scheme can — but because every
signature is recorded in Rekor, a malicious release is publicly detectable by the
publisher and by third-party monitors, giving accountability and a bounded window
of exposure. This is the transparency guarantee: detection and non-equivocation,
not prevention.

Explicitly **out of scope** for this iteration: rollback/freshness attacks (an
adversary replaying an older but validly-signed release — the domain of The
Update Framework's timestamp/snapshot metadata, Section 6); availability of the
outboard tree; and active, continuous log monitoring (delegated to existing
tools such as `rekor-monitor`).

### 3.2 The trust chain

Verification composes into a single unbroken chain from a human-meaningful
identity down to an individual 16 KiB group of bytes:

```
OIDC identity (e.g. you@example.com, verified by an issuer the client pins)
  └─ Fulcio short-lived certificate binding that identity to an ephemeral key
       └─ signature over the exact manifest bytes
            └─ Rekor inclusion proof (this signature is in the public log)
                 └─ blake3_root in the manifest (the file's BLAKE3 Merkle root)
                      └─ outboard tree (interior node hashes), checked to hash
                         up to blake3_root
                           └─ per-16-KiB-group leaf chaining values
                                └─ each streamed group, verified on arrival
```

Every link is checked before the next is trusted. The manifest is verified as
*raw bytes* against the bundle before it is parsed; the outboard is checked to
hash up to the signed root before any artifact byte is streamed; and each group
is checked against the tree the instant it completes.

### 3.3 Artifacts and formats

`publish` emits, alongside the artifact, three sidecar files:

- **Manifest** `<name>.blacklight.json` — a small, versioned JSON document that
  is the object actually signed. It binds the file name, size, the hex BLAKE3
  root, and the chunk-group size (fixed at log₂ = 4, i.e. 16 KiB, in format v1
  because it is baked into the outboard layout). Signing the *manifest* rather
  than the raw file means the Rekor entry's subject digest is `sha256(manifest)`,
  so no BLAKE3-specific entry type is required in the log.
- **Outboard** `<name>.obao` — the pre-order BLAKE3 Merkle tree over the file, at
  16 KiB groups, with no length prefix. Its measured size is ~0.4% of the file.
  Because chunk grouping affects only which interior nodes are stored (not the
  hashing math), the outboard's root equals plain `blake3::hash(file)`.
- **Bundle** `<name>.blacklight.json.sigstore.json` — the Sigstore v0.3 bundle
  (signature + Fulcio certificate + stapled Rekor inclusion proof).

The publisher hosts these four files anywhere — no special server is required.

### 3.4 The fetch state machine

```
1. Load manifest bytes and the bundle.
2. Verify the bundle OFFLINE against the embedded trust root: signature,
   Fulcio certificate chain, Rekor inclusion proof, AND the caller-supplied
   identity policy (exact SAN + issuer). Refuse to continue on any failure.
   -- Only now is the manifest parsed and its blake3_root trusted. --
3. Fetch the (small) outboard. Build a verification plan and CHECK THAT THE
   OUTBOARD HASHES UP TO THE SIGNED ROOT. A tampered outboard dies here.
4. Stream the artifact. Accumulate bytes into 16 KiB groups; the instant a
   group completes, verify its BLAKE3 chaining value against the plan. On the
   first mismatch: abort the transfer, delete the partial file, exit with a
   distinct integrity code, and report the byte offset.
5. On clean completion, check total length equals the signed size (catching
   truncation/padding), then atomically rename the temp file into place.
```

Requiring `--expect-identity` and `--expect-issuer` is a deliberate response to a
known weakness of the closest prior tool (Sigstore's archived `sget`), which
looked up *a* signature for the content without enforcing *whose*. A signature
from an attacker's own valid OIDC identity is still an attacker's signature; the
policy is what makes the check meaningful.

## 4. Implementation

Blacklight is ~1–2k lines of Rust (edition 2024). The dependency choices reflect
what is actually maintained and correct as of mid-2026:

- **`blake3` 1.8.5** for hashing. Its `hazmat` module (stabilized for exactly
  this use) exposes the chunk/subtree chaining-value primitives.
- **`bao-tree` 0.16** (n0-computer) to build the outboard tree on the publish
  side. This is the production verified-streaming engine underneath iroh-blobs,
  and it re-exports the same upstream `blake3`, so there is a single `Hash` type
  across the codebase. We use 16 KiB chunk groups (`BlockSize::from_chunk_log(4)`),
  which keeps outboard overhead near 0.4%.
- **`sigstore-sign` / `-verify` / `-oidc` / `-trust-root` / `-types` 0.10** (the
  sigstore-rust workspace) for keyless signing and offline bundle verification.
  Signing is keyless-only by necessity — this generation of the library has no
  self-managed-key path — using ambient CI credentials when present and an
  interactive browser OIDC flow otherwise, against Sigstore **staging** by
  default (`--production` selects the public-good instance). Verification uses the
  library's **embedded** trust roots, so it needs no network and no live Rekor
  connection.
- **`reqwest` 0.13 + `tokio` 1.52** for streaming HTTP.

**The forward-only verifier.** The natural choice, `bao_tree::valid_ranges`,
turned out to be the wrong shape: it requires *random-access* (seekable) data and
signals a corrupt group by *omitting* its range from the output stream rather
than raising an error — awkward and slow to turn into "stop at the first bad
byte." Instead, the verifier (in `verify.rs`) reconstructs the expected per-group
leaf chaining values from the outboard once (verifying the outboard against the
trusted root in the process), then streams the artifact forward, hashing each
completed 16 KiB group with `blake3::hazmat` (`set_input_offset` +
`finalize_non_root`, or the root hash for a single-group file) and comparing. A
mismatch aborts immediately with the group's byte offset. This hand-rolled walk
is unit-tested for exact round-trip agreement with bao-tree's outboard format
across file sizes from 0 bytes to 200 KB, including files that are empty, a
single group, and non-power-of-two numbers of groups.

## 5. Evaluation

### 5.1 Correctness and tamper detection

The implementation ships with 13 automated tests: 9 unit tests (manifest
round-trip and rejection of malformed/mis-versioned manifests; the verifier's
agreement with bao-tree; single-byte-flip detection in every group with the
correct byte offset; rejection of a tampered outboard and of a wrong root) and 4
integration tests that drive the real compiled binary over a local HTTP server:
a clean download succeeds and is byte-identical to the original; a tampered
artifact aborts at the correct group with the integrity exit code and leaves no
output file; a tampered outboard is rejected before any streaming; and a
truncated stream is rejected on the length check. All pass.

### 5.2 Attack demonstration and detection latency

The repository includes a self-contained demo (`demo/run_demo.sh`) that publishes
a file, serves it from an honest origin, and interposes a **tampering MITM proxy**
(`demo/evil_proxy.py`) that flips one byte at a configurable offset as the bytes
stream through — modeling exactly the in-transit attacker of Section 3.1.

For a 32 MiB artifact with a byte flipped at offset 16,000,000, blacklight
catches the corruption at **chunk group 976 (byte offset 15,990,784)** and aborts,
having *consumed and verified* about 16 MB — the tampered byte's own 16 KiB group
and nothing beyond it. The conventional `curl | sha256sum` pipeline, by contrast,
must download all 33,554,432 bytes before its single flat hash can mismatch. The
detection-latency advantage scales with file size and with how early the
tampering occurs: the tighter the corruption is to the start, the less blacklight
reads before aborting, whereas the flat-hash baseline always pays for the whole
file.

A note on honesty in the measurement: "bytes consumed and verified by the client"
is the security-relevant quantity, and it is bounded by one chunk group past the
tampered byte. The number of bytes the OS actually pulled onto the wire can be
higher, because TCP/HTTP read-ahead buffers eagerly (especially on a
zero-latency loopback); the demo reports both and never conflates them. The
guarantee blacklight makes is not "minimum bytes on the wire" but "no unverified
byte is ever accepted, written as good output, or acted upon."

### 5.3 Overhead

The outboard tree is a fixed, small tax on the publisher and on the client's
initial fetch: measured at **0.39%** of the artifact size at 16 KiB groups
(e.g. ~131 KB for a 32 MiB file), consistent with the theoretical 64 bytes per
16 KiB group. BLAKE3 hashing throughput is high enough that hashing is not the
bottleneck relative to network transfer. Offline verification adds no network
round trips beyond fetching the manifest, bundle, and outboard.

## 6. Related Work

**Software-update frameworks.** *The Update Framework* (TUF) [Samuel, Mathewson,
Cappos & Dingledine 2010] defines the canonical threat taxonomy for update
systems — mirror compromise, rollback/freeze, mix-and-match — and defends with
role separation, threshold signing, and freshness metadata. *Uptane* [Kuppusamy
et al. 2016] adapts TUF to automobiles and is deployed at scale. Blacklight is
narrower and complementary: it does not (yet) address rollback/freshness, which
is TUF's core strength, but it adds public transparency and per-byte transfer-time
verification, which base TUF does not require.

**Transparency logs.** Certificate Transparency [RFC 6962; RFC 9162], the formal
Transparency Overlays model [Chase & Meiklejohn 2016], and the Go checksum
database [Cox 2019] are the lineage blacklight's Rekor anchoring sits in.

**Blockchain-anchored update transparency** — the closest prior art to the
original "put it on a blockchain" instinct, and the work blacklight most directly
supersedes for this use case. *CHAINIAC* [Nikitin et al. 2017] provides proactive
software-update transparency via collectively-signed skipchains and verified
builds, evaluated on PyPI; it verifies *releases and metadata*, not bytes in
flight. *Catena* [Tomescu & Devadas 2017] and *Contour* [Al-Bassam & Meiklejohn
2018] achieve non-equivocation / binary transparency by embedding log digests in
Bitcoin. Blacklight takes the same tamper-evidence goal but obtains it from a
Merkle transparency log with witnessing rather than a blockchain — no consensus,
no tokens — and, unlike all three, drives verification down to the streamed
chunk.

**Verified streaming.** Merkle's original tree-authentication constructions
[Merkle 1987, 1989] underlie everything here. THEX (2003), BitTorrent v2 (BEP 52),
and the BLAKE3 specification with Bao [O'Connor et al. 2020] provide chunk-granular
verified transfer — but against a bare, unauthenticated root. iroh-blobs
(built on the same bao-tree crate blacklight uses) does verified streaming in
production over QUIC, again with a bare BLAKE3 hash as the trust root and no
publisher identity or log. Blacklight's addition is precisely to make that root a
*signed, transparency-logged* object.

**Web integrity mechanisms — useful contrasts.** Subresource Integrity [W3C 2016]
pins a whole-resource hash in HTML but verifies only after the full resource is
fetched and carries no transparency. RFC 9530 Digest Fields [Polli & Pardue 2024]
are in-band and unauthenticated (Section 1.1). Signed HTTP Exchanges with the MICE
encoding combine streaming Merkle verification with a signature and CT-logged
certificates — architecturally the nearest cousin — but are browser-scoped, ride
an expired IETF draft, and log the *certificate*, not the artifact.

**The Sigstore ecosystem and its adoption.** The Sigstore paper [Newman et al.
2022] and *Speranza* [Merrill et al. 2023] define the keyless-signing and
privacy-preserving extensions blacklight builds on. Sigstore's archived `sget`
tool is the closest single existing "transparency-anchored downloader," but it
computed a flat whole-blob digest, verified only after the full download, and did
not enforce a signer-identity policy. Ecosystem deployments — SLSA provenance
(v1.0, 2023; v1.2, 2025), npm provenance (2023), and PyPI PEP 740 attestations
(2024) — show transparency-logged signing at scale, and recent work on catching
malicious package releases via Rekor monitoring [Trail of Bits 2025] is direct
evidence for blacklight's audit-trail claim. Interview studies of signing
adoption [Kalu et al. 2025] motivate blacklight's stance that verification must
be automatic and sit in the transfer path, not be a manual step.

**Operating-system integrity: where verified streaming is already deployed.**
This is the most important context for an honest novelty claim, and it deflates
the "verified streaming" half of the design entirely. The Linux kernel already
implements Merkle-verified access at scale. **dm-verity** builds a Merkle tree
over a read-only block device and verifies each 4 KiB block against a signed root
hash *on page-in*, aborting on mismatch — this is Android Verified Boot,
ChromeOS, and the backbone of immutable distributions. **fs-verity** is the
per-file analogue (a Merkle tree stored past end-of-file, verified per page as
the file is read; the basis of Android APK and Fedora RPM file integrity). Both
are incremental, Merkle-based verification against a signed root — the same
building block as blacklight's streaming verification. (The kernel's **IMA/EVM**
subsystem is a *distinct* mechanism — measurement of files into TPM PCRs plus
signature/HMAC appraisal of file content and metadata, not per-block Merkle
streaming — and we note it only to complete the picture of the kernel integrity
stack, not as another instance of the same technique.) The point stands: relative
to the kernel, blacklight's per-chunk streaming verification is *not a new idea*;
it is a known technique (dm-verity/fs-verity-style Merkle-verified access) applied
to a different deployment shape — a fresh transfer from an untrusted remote,
aborting mid-stream, rather than a local, already-provisioned read-only volume.
The trust anchor of all these kernel mechanisms is, crucially, a local key
(kernel keyring / MOK / TPM), never a public transparency log or an OIDC-bound
identity.

**Distribution systems: content-addressing and signing are solved; transparency
is the gap.** Modern Linux distribution already pairs content-addressed stores
with signatures over roots: OSTree/rpm-ostree (ed25519 or GPG commit signing),
Nix and Guix (ed25519 narinfo/substitute signatures over content-addressed
paths), and Flatpak (OSTree GPG). Package managers verify a strong per-file hash
committed by a signed index against a distro-managed keyring (apt's
`InRelease`→SHA-256 chain, now Sequoia-verified in Debian 13; RPM v6 signatures
in Fedora 43; pacman's offline master-key web of trust). What almost none of them
add is a *transparency log* binding the artifact to a nameable, publicly
auditable identity. The closest deployed "transparency log for software" is Go's
checksum database (`sum.golang.org`), a tiled-Merkle transparency log — but it
guarantees *non-equivocation* (everyone sees the same hash for a given
`module@version`), not *identity*, and is a single operator, not keyless/OIDC.
Identity-bound transparency has landed in language registries (npm provenance,
PyPI PEP 740) and in experimental apt/Rekor plugins, but not in any mainstream
OS-package path as of 2025–2026. Where such work is being *explored*, the OIDC
dependency is treated warily: Debian's exploratory package-transparency notes
from the transparency.dev 2025 summit [Debian Wiki, PackageTransparency] weigh
*sigsum* with independent witnesses against Sigstore — early planning that
signals what these communities value, not a decision or a deployed system. A June
2026 Guix disclosure — code that
wrote substitute files *during download before hash verification*, and signatures
that left substitute URLs unprotected — is direct field evidence that the
"verify-during-transfer, TLS ≠ artifact integrity" failure modes blacklight
targets are live and unsolved in shipping distributions.

**Novelty statement (stated honestly).** Every primitive blacklight uses — BLAKE3,
Bao verified streaming, Merkle transparency logs, Sigstore keyless signing — is
prior work, and, as the two subsections above make explicit, *both halves are
independently and widely deployed*: Merkle-verified streaming in the kernel
(dm-verity/fs-verity), and transparency-log-anchored identity-bound signing in
language registries (npm/PyPI) and apt/Rekor experiments. We therefore do **not**
claim that verified streaming, transparency logs, or identity-bound signing are
new. The narrow contribution is their *composition into one verification path*:
to our knowledge, blacklight is the first tool in which a **transparency-logged,
identity-bound** signature covers a Merkle root that authorizes chunk-granular,
abort-on-first-bad-byte verification of a **fresh transfer from an untrusted
remote mirror**, with a mandatory signer-identity policy enforced before the
first byte is downloaded. Signed HTTP Exchanges (MICE), content-addressed
streamers (iroh/BitTorrent v2), and apt/Rekor plugins are the nearest
architectural relatives; we claim novelty only over uniting these mechanisms in
this deployment shape, and we expect even that gap to close as Sigstore adoption
spreads through OS distribution.

## 7. Limitations and Future Work

- **Rollback/freshness.** An adversary can serve an older, still-validly-signed
  release. Blacklight has no notion of "latest." Adopting TUF-style timestamp and
  snapshot metadata, or a signed monotonic version in the manifest with a
  freshness check, is the natural next step.
- **Unaudited streaming dependencies.** bao-tree and the Bao construction are
  maintained and widely used (iroh) but not formally audited; blacklight inherits
  that caveat. The signing/verification path rests on sigstore-rust 0.x, whose
  API churns; we pin exact versions and isolate it behind a thin module.
- **Outboard availability.** The client needs the outboard to verify; a
  network-level adversary can withhold it (denial of service), though it cannot
  forge it. Serving the Bao *combined* encoding, or embedding the tree, would
  remove the separate fetch at some bandwidth cost.
- **Log monitoring is out of band.** Transparency yields detection only if
  someone watches. Blacklight relies on existing monitors (`rekor-monitor`,
  witness networks) rather than building its own; integrating an
  inclusion-and-consistency-checking monitor into the publisher workflow is
  future work.
- **Verified resume.** Chunk-group-aligned range requests would let an
  interrupted download resume while re-verifying only the trailing partial group;
  the outboard already makes this straightforward and it is planned.

## 8. Conclusion

The desire to "just check the hash so hackers can't tamper with my downloads" is
a good one; it fails only because the usual realizations put the check in the
wrong place, bind it to the wrong hash, or anchor it in nothing an attacker can't
also rewrite. Moving the check to the endpoint, binding it to a collision-resistant
Merkle root, signing that root keylessly, and recording the signature in a public
transparency log turns the instinct into a guarantee — and doing the verification
*as the bytes stream* turns "reject bad downloads" into "stop reading the moment a
byte is wrong." Blacklight shows the combination is buildable today from
maintained parts, and that it catches a real in-transit attack after reading a
single bad chunk group rather than an entire tampered file.

## References

1. J. H. Saltzer, D. P. Reed, D. D. Clark. "End-to-End Arguments in System
   Design." *ACM Transactions on Computer Systems*, 2(4), 1984.
2. R. C. Merkle. "A Digital Signature Based on a Conventional Encryption
   Function." *CRYPTO '87*, LNCS 293. And "A Certified Digital Signature."
   *CRYPTO '89*, LNCS 435.
3. J. O'Connor, J.-P. Aumasson, S. Neves, Z. Wilcox-O'Hearn. "BLAKE3: one
   function, fast everywhere." Specification, 2020.
   https://github.com/BLAKE3-team/BLAKE3
4. J. O'Connor. "Bao: an implementation of BLAKE3 verified streaming."
   Specification. https://github.com/oconnor663/bao
5. J. Chapweske, G. Mohr. "Tree Hash EXchange format (THEX)."
   Internet-Draft draft-jchapweske-thex-02, 2003 (expired).
6. B. Cohen. "The BitTorrent Protocol Specification v2." BEP 52, 2008/2020.
   https://www.bittorrent.org/beps/bep_0052.html
7. B. Laurie, A. Langley, E. Kasper. "Certificate Transparency." RFC 6962, 2013.
   Updated as RFC 9162 (Laurie, Messeri, Stradling), 2021.
8. M. Chase, S. Meiklejohn. "Transparency Overlays and Applications."
   *ACM CCS 2016.*
9. R. Cox. "Transparent Logs for Skeptical Clients." 2019.
   https://research.swtch.com/tlog — and the Go module checksum database,
   go.dev/blog/module-mirror-launch, 2019.
10. J. Samuel, N. Mathewson, J. Cappos, R. Dingledine. "Survivable Key Compromise
    in Software Update Systems." *ACM CCS 2010.*
11. T. K. Kuppusamy et al. "Uptane: Securing Software Updates for Automobiles."
    *escar Europe 2016.*
12. K. Nikitin et al. "CHAINIAC: Proactive Software-Update Transparency via
    Collectively Signed Skipchains and Verified Builds." *USENIX Security 2017.*
13. A. Tomescu, S. Devadas. "Catena: Efficient Non-equivocation via Bitcoin."
    *IEEE S&P 2017.*
14. M. Al-Bassam, S. Meiklejohn. "Contour: A Practical System for Binary
    Transparency." *CBT @ ESORICS 2018* (arXiv:1712.08427).
15. Z. Newman, J. S. Meyers, S. Torres-Arias. "Sigstore: Software Signing for
    Everybody." *ACM CCS 2022.*
16. K. Merrill, Z. Newman, S. Torres-Arias, K. R. Sollins. "Speranza: Usable,
    Privacy-friendly Software Signing." *ACM CCS 2023.*
17. K. Kalu et al. "An Industry Interview Study of Software Signing for Supply
    Chain Security." *USENIX Security 2025.*
18. W3C. "Subresource Integrity." W3C Recommendation, 2016.
19. R. Polli, L. Pardue. "Digest Fields." RFC 9530, 2024.
20. SLSA: "Supply-chain Levels for Software Artifacts," v1.0 (2023), v1.2 (2025).
    https://slsa.dev — npm provenance (GitHub, 2023); PyPI PEP 740 digital
    attestations (2024).
21. Trail of Bits. "Catching malicious package releases using a transparency
    log." 2025. https://blog.trailofbits.com/2025/12/12/
22. Linux kernel documentation. "dm-verity" (device-mapper block integrity via a
    Merkle tree) and "fs-verity: read-only file-based authenticity protection."
    kernel.org, admin-guide/device-mapper/verity and filesystems/fsverity.
    See also Android Verified Boot (source.android.com/docs/security/features/verifiedboot/dm-verity).
23. OSTree, Nix, Guix, Flatpak documentation (content-addressed stores with
    ed25519/GPG root/commit/narinfo signing); Go checksum database
    ("Transparent Logs for Skeptical Clients," ref. 9) as the closest deployed
    software transparency log — non-equivocation without identity binding.
24. Debian Wiki, "ReproducibleBuilds/PackageTransparency,"
    https://wiki.debian.org/ReproducibleBuilds/PackageTransparency (exploratory
    notes from the transparency.dev 2025 summit weighing sigsum + multi-witness
    against Sigstore — planning, not a deployed decision); Sigsum design,
    https://git.sigsum.org (witness-cosigned, no OIDC dependency).
25. GNU Guix. "'guix substitute' and 'guix pull' Vulnerabilities." 2026,
    https://guix.gnu.org/en/blog/2026/guix-substitute-pull-vulnerabilities/
    (files written during download before hash verification; substitute URLs
    unprotected by signatures — field evidence for the verify-during-transfer
    thesis).
26. M. Stevens. "Counter-Cryptanalysis." *CRYPTO 2013*, LNCS 8042, pp. 129–146.
    (Open-access extended version: IACR ePrint 2013/358,
    https://eprint.iacr.org/2013/358.) The analysis proving the Flame malware's
    forged Microsoft code-signing certificate used a previously-unknown variant
    of the MD5 chosen-prefix collision attack. See also M. Fillinger & M.
    Stevens, "Reverse-Engineering of the Cryptanalytic Attack Used in the Flame
    Super-Malware," *ASIACRYPT 2015*, LNCS 9453, pp. 586–611
    (https://eprint.iacr.org/2016/298), and Microsoft Security Advisory 2718704
    (June 3, 2012).
