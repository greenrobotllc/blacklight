# Security Policy

blacklight is a security tool — its whole job is to reject tampered downloads —
so security reports are especially welcome. Thank you for helping keep it honest.

## Project maturity (please read)

blacklight is **pre-1.0 (0.x) and has not been independently audited.** It also
builds on cryptographic components that are themselves maintained but unaudited
(the [Bao](https://github.com/oconnor663/bao) verified-streaming construction via
`bao-tree`, and the `sigstore-rust` 0.x libraries). Treat it accordingly: it is
suitable for experimentation, evaluation, and non-critical use, but do not rely
on it as your sole control for a high-stakes trust decision without your own
review. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full threat model and
[`docs/CAVEATS.md`](docs/CAVEATS.md) for the consolidated list of every known
limitation.

## Supported versions

As a 0.x project, blacklight does **not** maintain multiple release lines.
Security fixes land on the `main` branch and in the next release; older tagged
versions do not receive backports.

| Version            | Supported          |
| ------------------ | ------------------ |
| `main` (latest)    | :white_check_mark: |
| latest release     | :white_check_mark: |
| any older tag      | :x:                |

Please confirm an issue still reproduces against `main` before reporting.

## Reporting a vulnerability

**Please report privately — do not open a public issue for a security bug.**

Use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue with enough detail to reproduce it (see below).

This keeps the report confidential until a fix and advisory are ready. If
private reporting is unavailable to you for any reason, open a minimal public
issue that says *only* "requesting a security contact" (no details), and a
private channel will be arranged.

A good report includes:

- the blacklight version or commit (`blacklight --version`, or the `main` SHA),
- your OS and how you built/installed it,
- exact steps or a minimal proof-of-concept, and
- the impact you believe it has (what an attacker gains).

### What to expect

- **Acknowledgement:** within about 3 business days.
- **Assessment:** an initial severity/validity call within about 7 days.
- **Fix & disclosure:** coordinated. We aim to release a fix and publish a
  GitHub Security Advisory (crediting you, if you wish) within 90 days of a
  confirmed report, sooner for actively-exploited or high-severity issues.
  If a report is declined, we will explain why.

## Scope

Because blacklight is a verification tool, the highest-impact bugs are those
that let bad data be **accepted as good**. In scope, most-severe first:

- **Verification bypass** — any way to make `fetch` accept an artifact whose
  bytes do not match the signed BLAKE3 root, or to write a tampered/partial file
  as if it were a good download.
- **Signature or identity-policy bypass** — accepting a bundle that is
  unsigned, wrongly signed, replayed, or signed by an identity/issuer other than
  the one required by `--expect-identity` / `--expect-issuer`; accepting an
  invalid or absent Rekor inclusion proof.
- **Trust-anchor confusion** — verifying a private-deployment artifact against
  the public trust root (or vice versa), or otherwise mixing trust roots.
- **Path traversal / unsafe writes** — a hostile manifest or server causing
  writes outside the intended output path.
- **Memory-safety or DoS** in blacklight's own code (panics, unbounded
  allocation, etc.) reachable from untrusted input.

### Out of scope

- **`--allow-unsigned`** is documented as dangerous and disables signature
  verification **by design**; behavior under it is not a vulnerability.
- **`demo/evil_proxy.py`** is an intentionally malicious man-in-the-middle used
  to demonstrate the defense; its behavior is not a bug.
- **Vulnerabilities in dependencies** (e.g. `sigstore-rust`, `bao-tree`,
  `blake3`, `reqwest`) should be reported to those projects. If a dependency
  flaw is exploitable *specifically through* the way blacklight uses it, that is
  in scope here — please note the dependency and the blacklight code path.
- **Operational security of a self-hosted Sigstore** (protecting your Fulcio CA
  key, monitoring your Rekor log, TUF key management, etc.) is the operator's
  responsibility; see the "Security considerations if you host your own log"
  section of the [README](README.md). blacklight cannot enforce these for you.
- Missing hardening that is already tracked as future work in
  [`docs/DESIGN.md`](docs/DESIGN.md) §7 (e.g. rollback/freshness protection) is a
  known limitation, not a vulnerability — though a *concrete exploit* of one is
  still worth reporting.

## Safe harbor

Good-faith security research that respects others' privacy and data, avoids
service disruption, and follows this policy is welcome, and we will not pursue
action against researchers who report responsibly under it.
