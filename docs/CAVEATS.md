# Caveats and honest limitations

blacklight is a **research prototype**, and a security tool's credibility comes
from being clear about what it does *not* do. This page collects every
significant caveat in one place. If any of these matters to your use, read the
linked detail before relying on blacklight.

For the positive side — what it *does* guarantee — see the
[README](../README.md) and [DESIGN.md](DESIGN.md). For reporting a
vulnerability, see [SECURITY.md](../SECURITY.md).

## At a glance

| # | Caveat | One-line summary |
|---|--------|------------------|
| 1 | [Pre-1.0 and unaudited](#1-pre-10-and-unaudited) | Experimental; no independent security audit; not for high-stakes sole reliance. |
| 2 | [The verifier is hand-rolled](#2-the-verifier-is-hand-rolled) | The core BLAKE3 tree-walk is bespoke; a bug there could make it *accept* tampered bytes. |
| 3 | [Unaudited crypto dependencies](#3-unaudited-crypto-dependencies) | Bao / `bao-tree` and `sigstore-rust` 0.x are maintained but not audited. |
| 4 | [No rollback / freshness protection](#4-no-rollback--freshness-protection) | An attacker can replay an older, still-validly-signed release. |
| 5 | [No built-in log monitoring](#5-no-built-in-log-monitoring) | A compromised signing identity is *detectable in Rekor*, but blacklight doesn't watch for you. |
| 6 | [Sigstore centralization & OIDC dependency](#6-sigstore-centralization--oidc-dependency) | Trust leans on the public-good Rekor + an OIDC issuer; both are liveness/centralization risks. |
| 7 | [Sigsum / witnessed logs not yet supported](#7-sigsum--witnessed-logs-not-yet-supported) | Only Rekor today; the more decentralization-friendly option isn't wired in yet. |
| 8 | [Identity discovery is on you](#8-identity-discovery-is-on-you) | You must already know the right `--expect-identity`/`--expect-issuer`; there's no sanctioned source. |
| 9 | [Outboard withholding is a DoS vector](#9-outboard-withholding-is-a-dos-vector) | An attacker can *withhold* the `.obao` (can't forge it) to deny a download. |
| 10 | [Streaming abort bounds bytes *consumed*, not bytes *on the wire*](#10-streaming-abort-bounds-bytes-consumed-not-bytes-on-the-wire) | TCP/HTTP read-ahead may pull more bytes than blacklight verifies. |
| 11 | [Self-hosting Sigstore is hard and shifts trust to you](#11-self-hosting-sigstore-is-hard-and-shifts-trust-to-you) | Running your own Rekor/Fulcio removes public-good witnessing; the ops burden is real. |
| 12 | [Not novel — the parts are widely deployed](#12-not-novel--the-parts-are-widely-deployed) | The contribution is a composition; each ingredient already ships elsewhere. |

---

## 1. Pre-1.0 and unaudited

blacklight is 0.x and has had no independent security audit. It's suitable for
experimentation, evaluation, and non-critical use — not as your sole control for
a high-stakes trust decision without your own review. The `sigstore-rust` 0.x
dependency also churns, so APIs and behavior may change between releases.

## 2. The verifier is hand-rolled

The most security-critical code is the forward-only BLAKE3 tree-walk in
[`src/verify.rs`](../src/verify.rs) — hand-derived left/right subtree geometry,
`is_root` handling at the single-vs-multi-group boundary, and (today) a live
`unreachable!()`. A subtle off-by-one or wrong `is_root` would make the verifier
**accept tampered bytes** — the exact failure the whole tool exists to prevent.
It is unit-tested for round-trip equivalence with `bao-tree`'s outboard format,
but that is a handful of hand-picked sizes, not a proof. Hardening this (fuzzing,
property tests, a bounded Kani proof) is tracked as a priority enhancement.

## 3. Unaudited crypto dependencies

The Bao verified-streaming construction (via `bao-tree`, the engine behind
iroh-blobs) and the `sigstore-rust` 0.x libraries are actively maintained and
widely used, but **not formally audited**. blacklight inherits their assurance
level. `blake3` itself is well-reviewed; the *glue* and the streaming construction
are the softer spots.

## 4. No rollback / freshness protection

This is the biggest functional gap. An attacker who controls the mirror can serve
an **older, still-validly-signed** manifest, and `fetch` accepts it — there is no
notion of "latest." The mitigation is TUF-style freshness metadata (version /
timestamp / expiry) or a signed monotonic version, which blacklight does not yet
have. See [DESIGN.md §8](DESIGN.md#8-limitations-and-future-work).

## 5. No built-in log monitoring

blacklight verifies a Rekor inclusion proof (the signature *is* in the public
log), but it does not *monitor* the log for rogue entries under a publisher's
identity. Transparency yields detection only if someone is watching. A compromised
signing identity is therefore **detectable but not automatically caught** —
blacklight relies on external monitors (`rekor-monitor`, witness networks) rather
than watching the log itself.

## 6. Sigstore centralization & OIDC dependency

By default, trust is anchored in Sigstore's public-good Rekor and an OIDC issuer.
Both are real dependencies: the public-good instance is a centralization and
liveness consideration, and requiring an OIDC identity is, to some communities
(notably conservative Linux distributions), a centralization risk they actively
avoid. This is a *governance* property as much as a technical one — see the
adjacent caveat.

## 7. Sigsum / witnessed logs not yet supported

The transparency ecosystem is not just Sigstore. **Sigsum** bakes independent
witness cosigning and gossip into the log (a signed tree head is only valid if
cosigned by a threshold of independent witnesses) and has **no OIDC dependency** —
which is precisely what decentralization-minded distributors prefer. blacklight
supports **only Rekor** today. The tradeoff is genuine, not a popularity contest:
Sigsum gives witnessed non-equivocation *without identity binding*, while
Sigstore/Rekor gives *identity-bound* signatures with a more centralized log — so
the right answer is to support **both**, and let the operator choose which
properties they require. Tracked in
[issue #18 (log-agnostic transparency backend)](https://github.com/greenrobotllc/blacklight/issues/18).

## 8. Identity discovery is on you

Every `fetch` *requires* `--expect-identity` and `--expect-issuer` (this is
deliberate — see [DESIGN.md](DESIGN.md)), but blacklight gives you no sanctioned
way to *know* the correct values. In practice users copy them from a README
(which may itself be untrusted) or reach for `--allow-unsigned` (which defeats the
point). A trust-policy file plus trust-on-first-use pinning would close this; it's
a tracked enhancement. Until then, obtaining the right identity out-of-band is
your responsibility.

## 9. Outboard withholding is a DoS vector

The client needs the `.obao` outboard tree to verify a download. A
network-level attacker **cannot forge** it (a tampered outboard won't hash to the
signed root and is rejected), but they **can withhold** it, denying the download.
This is availability, not integrity — blacklight fails *closed*, never serving
unverified bytes — but it is a real denial-of-service surface. Serving the Bao
*combined* encoding (tree interleaved with data) would remove the separate fetch,
at a bandwidth cost.

## 10. Streaming abort bounds bytes *consumed*, not bytes *on the wire*

blacklight's headline property is "abort at the first bad byte, having read at
most one 16 KiB group past the tampering." That bound is on the bytes blacklight
**consumes and verifies** — the security-relevant quantity. The number of bytes
the OS actually pulls onto the wire can be higher, because TCP/HTTP read-ahead
buffers eagerly (especially on low-latency links). The guarantee is *"no
unverified byte is ever accepted, written as good output, or acted upon,"* **not**
"minimum bytes transferred." The demo reports both numbers and never conflates
them.

## 11. Self-hosting Sigstore is hard and shifts trust to you

Running your own Rekor/Fulcio (see the README's self-hosting section) removes the
public-good instance's witnessing and monitoring ecosystem and makes **you** the
sole operator of your trust root — protecting the Fulcio CA key, monitoring your
Rekor log, and managing TUF keys become your responsibility. It's the right choice
for private/internal distribution, but the operational security burden is real and
easy to underestimate.

## 12. Not novel — the parts are widely deployed

blacklight does not invent Merkle-verified streaming (the Linux kernel's
`dm-verity`/`fs-verity` do exactly this at scale) or transparency-log-anchored,
identity-bound signing (npm provenance, PyPI PEP 740, apt/Rekor plugins). Its
contribution is the *composition* in one deployment shape — a transparency-logged,
identity-bound signature over a Merkle root gating abort-on-first-bad-byte
verification of a fetch from an untrusted mirror — and even that gap is expected to
narrow as Sigstore spreads through OS distribution. See the related-work section
of [`../paper/PAPER.md`](../paper/PAPER.md) and
[DESIGN.md §7](DESIGN.md#7-prior-art-where-this-is-and-is-not-novel).
