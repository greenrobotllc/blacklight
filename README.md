# blacklight

**Verified-streaming downloads anchored in the Sigstore transparency log —
tamper is caught mid-transfer, at the first bad byte, by a publisher you can
name.**

## Why

**The short version.** When you download a file over a network you don't
control — café WiFi, a mirror, a CDN — someone in the middle can quietly swap
the file for a tampered one. This isn't hypothetical: a host firewall flagging
unexpected connections on an untrusted network is a real experience, and
man-in-the-middle attacks on shared networks are well documented. The usual
advice is "check the file's hash so you know it wasn't tampered with." Good
instinct. But the way it's normally done doesn't actually protect you, for three
separate reasons:

> *Author's note: the author experienced unexpected network connections while at
> home during the COVID-19 pandemic and during other periods — noticed in part thanks to the [Little
> Snitch](https://www.obdev.at/products/littlesnitch/index.html) firewall. That
> experience is part of what motivated building a tool that verifies downloads
> end-to-end.*

1. **The hash people publish (MD5) is forgeable.** A "hash" is a short
   fingerprint of a file. MD5 is *collision-broken*: an attacker can craft a
   **malicious** file that has the **same** MD5 as the real one, so "the hash
   matches" no longer means "this is the real file." (This is how the [Flame
   malware](https://en.wikipedia.org/wiki/Flame_(malware)) forged a Microsoft
   code-signing certificate in 2012, using an MD5 chosen-prefix collision —
   analyzed in [Stevens, *Counter-Cryptanalysis*, CRYPTO
   2013](https://eprint.iacr.org/2013/358).)
2. **Nobody actually checks it.** Verifying a hash by hand is a manual,
   tedious step, so almost everyone skips it. Protection that depends on a
   human remembering to do a chore isn't protection.
3. **Even if you check, it's already too late.** You compute the hash *after*
   the whole file has downloaded — which means the malware is already sitting
   on your disk, and may have already been opened or auto-run before you ever
   compare fingerprints.

**blacklight fixes all three:** it uses a strong, non-forgeable hash (BLAKE3);
it verifies **automatically**, with no manual step; and it verifies the file
**as it streams in**, stopping at the very first bad byte so tampered data
never fully lands on your machine. And it proves *who* published the file, using
a signature recorded in a public, tamper-evident log.

<details>
<summary><b>The precise version</b> (for the security-minded)</summary>

The folk instinct — *"check the hash and a hacker can't tamper with your
download"* — is right. The usual realizations of it are not:

- **MD5 is collision-broken.** Collisions (two different files with the same
  hash) have been computable in seconds for years, and *chosen-prefix*
  collisions let an attacker craft a malicious file matching a benign file's
  MD5. Even SHA-256 doesn't save you if the checksum is delivered the wrong way
  (next point).
- **An in-band checksum is replaceable by the same MITM.** If the `SHA256SUMS`
  file sits next to the artifact on the same mirror, whoever can rewrite the
  artifact can rewrite the checksum too. Both ride the same untrusted channel;
  there's no independent anchor. The fix is a *signature* verifiable against a
  public key your machine already trusts.
- **TLS blinds the network layer instead of securing the artifact.** TLS
  authenticates *the server you reached* and encrypts the hop — but a malicious
  or compromised CDN edge or mirror serves tampered bytes over perfectly valid
  TLS, and TLS gives you no way to check what actually arrived.

So integrity has to be **end-to-end** — verified at *your* machine against an
out-of-band anchor — and the signature over the reference hash has to be
**publicly auditable**, so you can name who published it and detect a
compromised key after the fact.

blacklight does exactly that: a Sigstore-transparency-logged signature covers a
BLAKE3 Merkle root, and every 16 KiB chunk of the download is checked against
that signed root **as it streams in**.

</details>

## How it works

- **Verified streaming.** The file's BLAKE3 Merkle tree is precomputed into a
  tiny `.obao` sidecar (~0.4% overhead). On download, each 16 KiB chunk group is
  hashed and checked against the signed root the instant it arrives — the bytes
  from the untrusted mirror are never trusted, only verified.
- **Transparency-logged signature.** The root lives in a small JSON manifest,
  keyless-signed via Sigstore (OIDC → Fulcio short-lived cert → **Rekor public
  transparency log**). The client verifies the signature, cert chain, and Rekor
  inclusion proof **offline** against an embedded trusted root, and enforces the
  exact signer identity + issuer you demand *before downloading a single byte*.
- **Abort on the first bad byte.** On the first tampered chunk group, blacklight
  aborts the transfer (exit code 3), deletes the partial file, and reports the
  byte offset — having read at most one 16 KiB group past the tampering. A naive
  `curl | sha256sum` must download the *entire* file before its hash can
  mismatch.

## New to this? Every piece explained

If you're early in your software journey and/or some of the words above are
unfamiliar, this section is for you. Nothing here is as complicated as it sounds.

### The story, in everyday terms

Imagine a publisher wants to give you a file, but it has to travel across roads
(the internet) that thieves can tamper with. Here's the whole idea:

1. **Fingerprint the file.** The publisher runs the file through a *hash* — a
   function that turns any file into a short, unique-looking string of
   characters. Change one byte of the file and the fingerprint changes
   completely. blacklight uses a hash called **BLAKE3**.
2. **Fingerprint the pieces, not just the whole.** Instead of one fingerprint
   for the entire file, BLAKE3 internally hashes the file as a *tree* of
   fingerprints — fingerprints of small pieces, then fingerprints of those
   fingerprints, up to a single "root" fingerprint at the top. blacklight
   verifies that tree in 16 KiB pieces. This is what lets us check the file
   piece-by-piece *while it downloads*, instead of only at the very end.
3. **Sign the fingerprint so nobody can fake it.** A thief could swap the file
   *and* its fingerprint. To stop that, the publisher **signs** the root
   fingerprint — like a wax seal only they can make — and their identity (e.g.
   their email or a CI system) is baked into that seal by **Sigstore**.
4. **Write the signature in a public ledger.** The signature is recorded in
   **Rekor**, a public, append-only logbook that anyone can read and that nobody
   can secretly edit. So even if the publisher's "seal" were ever stolen, the
   theft leaves a permanent, visible trace.
5. **You verify everything on your own computer.** When you download, blacklight
   checks the seal (is this really from the publisher I named?), checks the log
   (is this signature really in the public ledger?), and then verifies each
   16 KiB piece against the signed tree *as it arrives*. The moment one piece doesn't
   match, it stops and throws the download away. The network delivered the bytes,
   but your computer is the only thing that decides whether to trust them.

### Glossary (with links to learn more)

| Term | What it means, plainly |
| --- | --- |
| **[Hash](https://en.wikipedia.org/wiki/Cryptographic_hash_function)** | A function that turns any file into a short fixed-length fingerprint. Same file → same fingerprint; change anything → totally different fingerprint. |
| **[MD5](https://en.wikipedia.org/wiki/MD5)** | An old, *broken* hash. Attackers can now make two different files share one MD5 fingerprint, so it can't be trusted for security. |
| **[BLAKE3](https://github.com/BLAKE3-team/BLAKE3)** | A modern, fast, secure hash. It's built as a *tree* internally, which is what makes streaming verification possible. blacklight uses it. |
| **[Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree)** | A tree of hashes: leaves are hashes of data chunks, each parent is a hash of its children, and the single top hash (the "root") represents the whole file. Lets you verify one chunk without the whole file. |
| **Root hash** | The single fingerprint at the top of the Merkle tree. If you trust the root, and a chunk hashes correctly up to that root, the chunk is genuine. |
| **Chunk group** | blacklight verifies the file in 16 KiB pieces. Each piece is one "chunk group." Smaller pieces = catch tampering sooner; 16 KiB is a good balance. |
| **[Bao](https://github.com/oconnor663/bao) / `.obao` file** | *Bao* is the format for BLAKE3 "verified streaming." The **`.obao`** file is the *outboard* Merkle tree — all the tree's internal fingerprints stored in a small separate file (about 0.4% of the file's size) so the client can check chunks as they stream. |
| **[Sidecar file](https://en.wikipedia.org/wiki/Sidecar_file)** | A small companion file that lives next to a main file and carries extra data about it. The `.obao` tree, the manifest, and the signature are all sidecars next to your artifact. |
| **Manifest (`.blacklight.json`)** | A tiny text file (JSON) that records the file's name, size, and root hash. It's the thing that actually gets signed. |
| **[Digital signature](https://en.wikipedia.org/wiki/Digital_signature)** | Math that proves "the holder of a private key approved this data," verifiable by anyone with the matching public key. Can't be forged without the private key. |
| **[Sigstore](https://www.sigstore.dev/)** | A free system for signing software *keyless* — you sign using your existing identity (Google/GitHub/etc.) instead of managing a private key file yourself. |
| **[OIDC](https://openid.net/developers/how-connect-works/)** | "OpenID Connect" — the standard way to prove who you are with an existing account (the "Sign in with Google" flow). Sigstore uses it to tie a signature to your identity. |
| **[Fulcio](https://docs.sigstore.dev/certificate_authority/overview/)** | Sigstore's certificate authority. It takes your proven OIDC identity and issues a short-lived *certificate* saying "this key belongs to this identity, briefly." |
| **[Rekor](https://docs.sigstore.dev/logging/overview/)** | Sigstore's public **transparency log**: an append-only, tamper-evident ledger of every signature. Anyone can audit it; nobody can rewrite its history. |
| **[Transparency log](https://transparency.dev/)** | A public logbook where entries can only be added, never changed or deleted, and math proofs let anyone confirm both facts. Certificate Transparency (which protects HTTPS) works the same way. |
| **[Inclusion proof](https://transparency.dev/verifiable-data-structures/)** | A short cryptographic receipt proving "this specific entry really is in the log," checkable without downloading the whole log. |
| **[MITM (man-in-the-middle)](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)** | An attacker positioned between you and a server who can read and rewrite what passes through — the exact threat blacklight defends against. |
| **[TLS / HTTPS](https://en.wikipedia.org/wiki/Transport_Layer_Security)** | Encrypts the connection to a server and confirms *which server* you reached — but it does **not** guarantee the *file* that server hands you wasn't swapped by a bad mirror or CDN. That gap is why blacklight exists. |
| **[End-to-end verification](https://en.wikipedia.org/wiki/End-to-end_principle)** | The principle that a correctness check belongs at the endpoints (your machine), not in the untrusted middle (the network). blacklight verifies on *your* computer. |
| **[CDN](https://en.wikipedia.org/wiki/Content_delivery_network)** | Content Delivery Network — servers spread worldwide that host copies of files for speed. Convenient, but you're trusting all of them not to tamper — unless you verify, which is the point here. |
| **Outboard** | Means "stored separately from the data." An *outboard* Merkle tree (the `.obao`) lives in its own file rather than being interleaved with the file's bytes. |
| **[Rust](https://www.rust-lang.org/)** | The programming language blacklight is written in — chosen for speed and memory safety, which matter for security tools. |

## Architecture

### The big picture

The publisher signs once; the four resulting files can be hosted anywhere —
including hosts you assume are hostile — because the downloader verifies
everything locally:

```mermaid
flowchart TB
    A["artifact"] --> P["blacklight publish"]

    subgraph SIG["Sigstore infrastructure"]
        direction LR
        F["Fulcio CA\nshort-lived cert\nfor OIDC identity"] -. "signature\nlogged" .-> R["Rekor\npublic transparency log"]
    end
    P -. "sign manifest keyless (OIDC)" .-> F

    P --> OUT["4 published files:\nartifact  ·  .obao (Merkle tree, ~0.4%)\nmanifest .blacklight.json {size, blake3_root}\nSigstore bundle .sigstore.json"]
    R -. "inclusion proof stapled into bundle" .-> OUT

    OUT ==> HOST["Any host / mirror / CDN\nUNTRUSTED — can rewrite any byte in transit"]

    HOST ==> C["blacklight fetch\nverifies EVERYTHING locally,\ntrusts no byte from the host\n(aborts on the first bad 16 KiB group)"]

    classDef untrusted fill:#fde2e2,stroke:#d33,color:#000;
    classDef trusted fill:#e2f0d9,stroke:#4a7,color:#000;
    class HOST untrusted;
    class C trusted;
```

### The trust chain

Every link is verified before the next is trusted, from a human-meaningful
identity all the way down to each 16 KiB group of bytes:

```mermaid
flowchart TD
    I["OIDC identity\n(e.g. you@example.com,\nor a CI workflow)"]
    C["Fulcio short-lived certificate\nbinds identity to an ephemeral key"]
    S["Signature over the exact\nmanifest bytes"]
    R["Rekor inclusion proof\nsignature is in the public,\nappend-only transparency log"]
    RT["blake3_root\nthe file's BLAKE3 Merkle root,\ninside the signed manifest"]
    OBV["Outboard tree (.obao)\nchecked to hash up to the\nsigned root before streaming"]
    L["Per-group leaf hashes\none per 16 KiB chunk group"]
    G["Each streamed 16 KiB group\nverified the instant it arrives\nfirst mismatch = abort, exit 3"]

    I -->|"issuer + SAN pinned by\n--expect-identity / --expect-issuer"| C
    C --> S
    S --> R
    R --> RT
    RT --> OBV
    OBV --> L
    L --> G
```

### What `fetch` actually does

```mermaid
sequenceDiagram
    autonumber
    participant BL as blacklight fetch
    participant M as Mirror / CDN (untrusted)
    participant D as Local disk

    BL->>M: GET manifest + bundle
    M-->>BL: manifest bytes + Sigstore bundle
    Note over BL: Verify bundle OFFLINE:<br/>signature over manifest bytes,<br/>Fulcio cert chain, Rekor inclusion<br/>proof, pinned identity + issuer.<br/>Any failure → stop before<br/>downloading a single artifact byte.

    BL->>M: GET .obao (outboard tree)
    M-->>BL: outboard bytes
    Note over BL: Check the outboard hashes up<br/>to the signed blake3_root.<br/>Tampered tree dies here.

    BL->>M: GET artifact (streamed)
    loop every 16 KiB chunk group
        M-->>BL: group bytes
        Note over BL: hash group (BLAKE3 chaining value),<br/>compare against the verified tree
        BL->>D: append verified group to temp file
    end

    alt a group does not match (tampering)
        Note over BL,M: ABORT transfer immediately —<br/>at most one 16 KiB group read past<br/>the tampered byte
        BL->>D: delete temp file
        Note over BL: exit code 3, report byte offset
    else all groups match + length equals signed size
        BL->>D: atomic rename into place
        Note over BL: exit 0 — every byte verified
    end
```

## Install

```sh
cargo build --release
# binary at ./target/release/blacklight
```

Rust edition 2024 (MSRV ~1.85+).

## Quickstart

### Publish

Hash a file, build its outboard tree, write the manifest, and keyless-sign it:

```sh
# Signs via Sigstore STAGING by default (add --production for the public-good
# instance). Signing is keyless: ambient CI OIDC if present, else a browser.
blacklight publish demo.bin --url https://mirror.example.org/demo.bin
```

This produces four files to host — the artifact plus three sidecars:

```text
demo.bin                                 # the artifact (unchanged)
demo.bin.obao                            # outboard BLAKE3 Merkle tree
demo.bin.blacklight.json                 # signed manifest {root, size, geometry}
demo.bin.blacklight.json.sigstore.json   # Sigstore v0.3 bundle
```

For local testing without signing: `blacklight publish demo.bin --unsigned`
(emits only the `.obao` + manifest).

### Fetch

Download and verify, pinning *who* must have signed the root:

```sh
blacklight fetch https://mirror.example.org/demo.bin.blacklight.json \
    --expect-identity you@example.com \
    --expect-issuer https://accounts.google.com \
    -o demo.bin
```

blacklight verifies the bundle offline, enforces the identity + issuer policy
**before** touching the artifact, then streams and verifies every group. Use
`--production` to verify against the Sigstore production trust root, and
`--allow-unsigned` to skip signature verification entirely (**dangerous** — the
download is still integrity-checked against the manifest root, but nothing proves
*who* published that root).

## Private / self-hosted Sigstore

By default blacklight uses Sigstore's public infrastructure, which logs every
signature to a **public** transparency log. Sometimes you want your own
**private** Rekor and Fulcio instead — a company distributing software over a
VPN, a nonprofit running its own infrastructure, or just someone who wants to
stand it all up locally to see how it works. In any of these cases your
artifacts are recorded in a private, auditable log rather than a public one.
blacklight supports pointing at a self-hosted Sigstore deployment: the trust
chain, the offline verification, and the identity policy are all identical —
only the endpoints and trust root change.

**Publish** against your private Rekor/Fulcio (and your own OIDC issuer, e.g.
your corporate SSO). All three endpoints must be given **together** — mixing a
private log with the public CA (or vice versa) would be an inconsistent trust
setup, so blacklight rejects a partial set:

```sh
blacklight publish demo.bin \
    --rekor-url  https://rekor.corp.internal \
    --fulcio-url https://fulcio.corp.internal \
    --oidc-url   https://sso.corp.internal/oauth
```

**Fetch** and verify against that deployment's trust root — a JSON file you
export from your Sigstore deployment's TUF root and distribute to clients (it is
the public anchor, so it is safe to hand out):

```sh
blacklight fetch https://vpn.corp.internal/demo.bin.blacklight.json \
    --trust-root ./corp-sigstore-trust-root.json \
    --expect-identity ci@corp.internal \
    --expect-issuer https://sso.corp.internal/oauth \
    -o demo.bin
```

Notes:

- Verification stays **fully offline** — the trust root plus the bundle's
  stapled inclusion proof are enough; `fetch` never contacts your Rekor at
  download time.
- `--trust-root` is required to verify private-deployment bundles (blacklight
  refuses to guess), and it conflicts with `--production` so you can't
  accidentally check a private artifact against the public root.
- See [`docs/DESIGN.md`](docs/DESIGN.md) for how the trust root is obtained and
  what each endpoint is responsible for.

### Security considerations if you host your own log

Running your own Rekor and Fulcio is a real operational responsibility, not a
config change. The public Sigstore instance is trustworthy largely because of
things a single operator does **not** automatically have — a cross-organization
TUF root, an on-call team from several companies, and independent third parties
watching the logs. When you self-host, you take those jobs on. The big ones:

- **The Fulcio CA key is now the crown jewel.** Fulcio is a certificate
  authority; whoever holds its signing key can mint a valid certificate for
  **any** identity your deployment accepts, and short-lived certs have no
  per-cert revocation — recovery is only via your TUF root. Keep the root CA key
  **offline** (hardware token) and the online signing key **non-exportable in an
  HSM/KMS**, isolated from the rest of your infrastructure.
- **A private log you don't watch proves nothing.** A transparency log's whole
  value is that a *misbehaving operator gets caught*. But a single operator can
  show different versions of the log to different clients (a "split-view" or
  fork attack), and inclusion/consistency proofs alone don't catch that. You
  must run **monitoring** ([`rekor-monitor`](https://github.com/sigstore/rekor-monitor):
  consistency-proof checking + watching for unexpected certs issued to your
  identities), and ideally add **independent witnesses** that co-sign
  checkpoints — or **dual-log** to the public Rekor so its watchers anchor you.
  As Sigstore's own guidance puts it, an unmonitored private deployment is
  "just a project without any ROI."
- **Lock down the OIDC issuer.** Fulcio trusts a valid OIDC token as proof of
  identity, so a misconfigured or compromised issuer lets an attacker get certs.
  Require the `sigstore` audience, pin the exact issuer, verify identity claims
  (e.g. `email_verified`), and enforce 2FA on human identities.
- **Protect and rotate the TUF root.** The TUF root is what distributes your
  `trust-root.json` and the **only** way to revoke a compromised Fulcio or
  Rekor. Use **threshold signing across several offline, separately-held keys**
  (never 1-of-1), with a documented rotation ceremony.
- **Also plan for:** an RFC 3161 **timestamp authority** (so short-lived certs
  stay verifiable after they expire), redundancy/DoS protection, and external,
  integrity-protected backups of the log to catch rollback.

**The honest bottom line:** a single-organization private log gives you
*internal auditability, privacy for non-public artifacts, and independence from
the public instance's availability* — genuine benefits. It does **not** give you
the public log's key property of *many independent watchers*. A private log is
only as trustworthy as the party running it; the mitigations above (independent
witnesses, third-party monitoring, dual-logging, threshold-held offline keys)
exist to buy back as much of that distributed trust as a self-hoster can. See
Sigstore's [threat model](https://docs.sigstore.dev/about/threat-model/) and
[security model](https://docs.sigstore.dev/about/security/) before you rely on a
self-hosted deployment for anything that matters.

## See it catch an attack

```sh
bash demo/run_demo.sh
```

The demo publishes a file, serves it from an honest origin, and fetches it twice:
once directly (succeeds, byte-identical) and once through a tampering MITM proxy
that flips one byte mid-stream. blacklight aborts at the first bad 16 KiB group,
leaving no output file — and it's contrasted against `curl | sha256sum`, which
must read the whole file first. Sample metrics (32 MiB file, byte flipped at
offset 16,000,000):

```text
==================  DETECTION METRICS  ==================
tampered byte offset                            16000000
total artifact size (bytes)                     33554432
blacklight: bytes consumed before               16007168
  detection (one 16 KiB group)
curl+sha256: bytes consumed before              33554432
  detection (whole file)
data blacklight avoided reading                  2.1x less
```

The tampered byte at offset 16,000,000 lands in **chunk group 976** (byte offset
15,990,784); blacklight aborts there, having verified only ~16 MB, while
`curl | sha256sum` reads all 32 MB before its hash mismatches. Measured outboard
overhead: **0.39%**. The test suite (`cargo test`) is 13 tests — 9 unit plus 4
integration that drive the real binary over a local HTTP server, including
tampered-artifact, tampered-outboard, and truncated-stream attacks.

## What it does NOT do yet

- **No rollback/freshness protection.** A validly signed *older* version replays
  cleanly — that's TUF's domain.
- **No active log monitoring.** A compromised signing identity is *detectable*
  (every signature is in Rekor) but blacklight doesn't watch the log for you.
- **Keyless signing only.** sigstore-rust 0.10 has no self-managed-key path.
- **No outboard redundancy.** A withheld `.obao` fails the fetch closed.

## Design & background

- [`docs/DESIGN.md`](docs/DESIGN.md) — full threat model, the end-to-end trust
  chain, on-disk/on-wire formats, and the `fetch` state machine.
- [`paper/PAPER.md`](paper/PAPER.md) — the write-up and motivation.

## Honesty note

Every cryptographic primitive here pre-exists and is battle-tested: BLAKE3 for
hashing and tree math, `bao-tree` (n0-computer, the engine behind iroh-blobs) for
the outboard tree, and Sigstore (Fulcio + Rekor, via sigstore-rust) for keyless
transparency-logged signatures. **blacklight's contribution is the
composition** — wiring a transparency-logged signature over a BLAKE3 root into a
forward-only, fail-fast, abort-on-first-bad-byte streaming verifier.

## License

Dual-licensed under either [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
