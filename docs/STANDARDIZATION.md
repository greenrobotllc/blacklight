# Could blacklight be standardized (IETF)?

Short answer: **you can submit an Internet-Draft tomorrow — that part is free and
ungated — but almost none of blacklight would survive review as-is, and the one
piece that might needs the design changed first.** This page records an honest
assessment so the question doesn't have to be re-litigated from scratch.

## The uncomfortable precedent

The verified-streaming half of blacklight — per-chunk Merkle verification during
an HTTP transfer, aborting on the first bad byte — **was already proposed to the
IETF and failed.** The Merkle Integrity Content Encoding
([`draft-thomson-http-mice`](https://datatracker.ietf.org/doc/draft-thomson-http-mice/),
last revised Aug 2018, expired Feb 2019, never an RFC) defined an `mi-sha256`
content-coding that did exactly this, in SHA-256. It existed mainly to serve
**Signed HTTP Exchanges (SXG) / Web Packaging**, and was abandoned when that
parent effort lost cross-vendor support:

- Mozilla filed a formal **"harmful" standards position** over centralization and
  origin-substitution concerns;
- Firefox never implemented it, Safari was skeptical;
- Cloudflare began **removing** Signed Exchange support in October 2025.

The lesson is the important part: *what killed the effort was governance
(centralization, single-vendor demand), not the cryptography.* Reproposing the
same mechanism with BLAKE3 instead of SHA-256 would re-walk that path — and
blacklight's Sigstore/OIDC dependency is precisely the kind of centralization
concern that sank SXG's reception. There is also older precedent: THEX
(`draft-jchapweske-thex-02`, 2003) floated a Merkle tree-hash exchange format and
likewise expired without becoming an RFC.

## What is already standardized or being standardized elsewhere

| blacklight ingredient | Status in the standards world |
| --- | --- |
| Per-chunk Merkle verified streaming | Dead IETF drafts (MICE 2019, THEX 2003); deployed non-IETF (Bao, BitTorrent v2, dm-verity/fs-verity). Not an open standardization opportunity. |
| Whole-object integrity digest over HTTP | **Done:** RFC 9530 Digest Fields (2024) — but deliberately in-band and *unauthenticated*. |
| Binding a key to a fetched web resource | Being done at **W3C/WICG**: signature-based SRI (Ed25519 + RFC 9421), shipped in Chrome 2025 — but no transparency log, no streaming abort. |
| Transparency log + inclusion proofs | CT (RFC 6962/9162); and the **active** IETF SCITT + COSE Receipts work. |
| A signed statement about an artifact, with a receipt | **Active IETF work:** SCITT `draft-ietf-scitt-architecture` (Proposed Standard, 2025) + `draft-ietf-cose-merkle-tree-proofs` (COSE Receipts). |

The recurring theme: the individual pieces have homes, and reviewers would fairly
ask *"which working group owns this, and what new bits-on-the-wire are you
actually defining?"* — the standard "this is a composition of existing standards"
critique. blacklight's own README already admits it is a composition.

## The one plausibly-standardizable slice

Not the streaming. Not the log. The **binding layer**:

1. A **log-agnostic, signed manifest/receipt format** binding an *identity* to a
   *streaming-verifiable BLAKE3 Merkle root*, expressed as a COSE/SCITT signed
   statement rather than a Sigstore-specific bundle.
2. A **verify-before-consume policy**: the client MUST confirm the manifest was
   signed under the required identity/issuer, evidenced by a transparency
   receipt, *before* consuming any bytes — and MUST NOT assert an identity the
   backend cannot prove.
3. A **BLAKE3/Bao verifiable-data-structure proof type** registered into the COSE
   Receipts / verifiable-data-structure registry, so "streaming-verify a range
   against a signed root" is expressed in existing IETF terms. Registry additions
   are concrete, tractable IETF deliverables — probably the least-contested thing
   blacklight could actually land.

## What it would take (in order)

1. **De-Sigstore-ify the design.** Non-negotiable for IETF viability: recast
   "Fulcio cert + Rekor inclusion proof" as SCITT signed statements + COSE
   Receipts, so Rekor, sigsum, a CT-style log, or a private log are all valid
   backends. This is the same log-agnostic direction already tracked for the
   codebase — see the sigsum backend issue — so it is worth doing regardless of
   whether a draft is ever filed.
2. **Write the manifest as a spec** in RFCXML over COSE/CBOR, with proper IANA
   registration sections (media type, registry entries). Substantial writing work,
   distinct from the code.
3. **Register a BLAKE3/Bao proof type** in the COSE verifiable-data-structure
   registry.
4. **Post an individual I-D** named to signal the target WG
   (`draft-<name>-cose-blake3-…` or `draft-<name>-scitt-…`). Easy; proves nothing.
5. **Socialize on the COSE and SCITT mailing lists** and present at an
   interim/IETF meeting before expecting traction. Working-group adoption is the
   real bar: consensus-driven, drafts expire every 6 months and must be refreshed,
   typically **multiple years**, multiple independent implementations expected.
   (SCITT and COSE Receipts are themselves still drafts after years; roughly 1 in
   10 I-Ds ever become RFCs.)

## Honest recommendation

- A full "blacklight protocol" RFC: **no.** No single WG owns it; it reads as a
  composition of things with existing homes.
- A narrow contribution — a log-agnostic COSE/SCITT profile registering a BLAKE3
  streaming-verifiable proof type with verify-before-consume semantics, framed as
  a supply-chain distribution use case, with blacklight as the reference
  implementation: **plausible, multi-year, governance-gated.**
- The cheapest high-value first move is **not** filing a draft — it's emailing the
  SCITT or COSE mailing list to ask whether a BLAKE3 streaming-verifiable proof
  type is in scope, and getting a real read from the people who would decide. See
  the tracking issues for (a) the standardization-readiness work and (b) the
  scoping email.
