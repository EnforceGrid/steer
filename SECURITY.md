# Security Policy

Steer is an open-source proxy that enforces Cedar policies on LLM traffic.
Operators deploy it on the trust boundary between coding agents and model
providers, which makes its integrity, its release pipeline, and its policy
evaluator security-critical. This document describes how the Steer
maintainers handle vulnerability reports, what is in scope, and the
supply-chain commitments that ship with every release.

If you are unsure whether something is in scope, report it anyway. The
maintainers would rather triage a non-issue than miss a real one.

## Reporting a vulnerability

**Do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Use one of the following private channels, in order of preference:

1. **GitHub Security Advisories (preferred).**
   [Open a private report](https://github.com/enforcegrid/steer/security/advisories/new)
   on `github.com/enforcegrid/steer`. This is the fastest path because it
   gives the maintainers a private fork to develop the patch in.

2. **Email.** Send to `security@enforcegrid.com`. Avoid including exploit
   code or sensitive reproduction data in the email body — attach them
   as files, or wait for the maintainers to acknowledge and request a
   secure channel.

A useful report includes:

- A description of the issue and the affected component (binary, install
  script, release workflow, policy evaluator, audit emission, detection
  pipeline).
- The Steer version (`steer --version`) and target triple where the
  issue reproduces.
- Reproduction steps or a proof-of-concept. For dependency-derived
  CVEs, include the call chain from Steer code to the affected symbol —
  see "Third-party dependencies" below.
- Your assessment of impact and any suggested remediation.

## Response targets

The maintainers commit to the following timelines. All targets are
measured in business days from receipt of a well-formed report.

| Stage                      | Target            |
| -------------------------- | ----------------- |
| Initial acknowledgement    | 2 business days   |
| Triage and severity rating | 5 business days   |
| Status updates             | Weekly thereafter |

Remediation targets are set per severity using CVSS v3.1 base score:

| Severity (CVSS)  | Fix target from triage             |
| ---------------- | ---------------------------------- |
| Critical (9.0+)  | 7 days, or coordinated workaround  |
| High (7.0–8.9)   | 30 days                            |
| Medium (4.0–6.9) | 60 days                            |
| Low (<4.0)       | Next scheduled minor release       |

These are targets, not contractual SLAs. If the maintainers cannot meet
a target — for example, because a fix requires an upstream change in
Cedar or `tokio` — the reporter will be told why and given a revised
date.

## Coordinated disclosure

Steer follows a **90-day coordinated disclosure** model, consistent with
industry practice (Project Zero, CERT/CC).

- The clock starts when the maintainers acknowledge the report.
- The maintainers will request an extension only if a fix is in active
  development and additional time is necessary to ship it safely.
- When a fix ships, the maintainers publish a GitHub Security Advisory,
  request a CVE if warranted, and credit the reporter (with consent).
- The reporter is asked not to disclose the issue publicly until the
  advisory is published or 90 days have passed, whichever comes first.

## Safe harbor

The Steer maintainers consider security research conducted under this
policy to be:

- Authorized under the Computer Fraud and Abuse Act (and equivalent
  laws), and exempt from anti-circumvention claims under DMCA §1201;
- Conducted in good faith, such that the maintainers will not initiate
  or support legal action against the researcher;
- Compatible with the project's license obligations.

The maintainers expect researchers to:

- Stop and report immediately upon encountering user data, credentials,
  or any production system;
- Not exfiltrate, modify, or destroy data;
- Not degrade availability for other users;
- Give the maintainers a reasonable opportunity to remediate before
  public disclosure.

This safe harbor applies to the Steer open-source project only.
EnforceGrid Enterprise and any production deployments operated by
EnforceGrid customers are out of scope; see "Prohibited testing" below.

## Scope

**In scope:**

- The `steer` binary and its proxy runtime.
- Cedar policy evaluation, the policy hot-reload path, and policy
  schema validation.
- The detection pipeline (PII, prompt injection, exfiltration,
  tool-call governance).
- Audit log emission and the integrity of audit records.
- The `install.sh` install script and the documented install paths.
- Release artifacts (`steer-vX.Y.Z-<target>.tar.gz`, `SHA256SUMS`,
  attestation bundles) and the GitHub Actions release workflow that
  produces them.
- The repository's GitHub Actions configuration (workflow injection,
  privilege escalation in CI, token scoping).

**Out of scope:**

- Vulnerabilities in upstream LLM providers (OpenAI, Anthropic, etc.).
- Bugs in user-authored Cedar policies. Policy logic is the
  operator's responsibility; the evaluator's correctness is the
  maintainers'.
- Denial of service achieved by legitimate-shape traffic at high
  volume. Rate limiting and capacity planning are the operator's
  responsibility.
- Issues that require a malicious operator who already controls the
  Steer host or has root on the runtime.
- Social engineering of maintainers, contributors, or EnforceGrid
  staff.
- Findings that depend on running an outdated, unsupported Steer
  release (see "Supported versions").

## Prohibited testing

The following are not authorized under this policy. Engaging in them
forfeits safe harbor:

- Denial-of-service testing against any host you do not control.
- Any testing against production deployments operated by EnforceGrid
  or EnforceGrid customers. Stand up your own instance.
- Accessing, exfiltrating, modifying, or destroying data that is not
  your own test data.
- Physical attacks, social engineering, or attacks against
  EnforceGrid infrastructure outside the GitHub repository.
- Automated scanning that generates substantial load against
  EnforceGrid-operated hosts.

## Supported versions

During the `v0.x` series, only the most recent minor release line
receives security fixes. Once Steer reaches `v1.0`, a longer support
window will be defined here.

| Version line | Status                                    |
| ------------ | ----------------------------------------- |
| `v0.x` (latest minor) | Supported. Patches issued as `v0.x.y`. |
| `v0.x` (older minors) | Unsupported. Upgrade to the latest minor. |
| Pre-release / nightly | Best-effort. Report regressions, expect rapid iteration. |

Operators are expected to track the latest minor release.

## Supply-chain commitments

Every Steer release ships with the following, produced by the
`release.yml` GitHub Actions workflow on tag push:

- **SHA256 checksums** (`SHA256SUMS`) covering every per-target
  archive.
- **GitHub Actions build provenance attestations** generated by
  `actions/attest-build-provenance`, providing **SLSA Build Level 2**
  today. The roadmap to Build Level 3 (Sigstore-signed artifacts and
  Rekor transparency log entries via `cosign`) is tracked in the
  binary-distribution plan.
- **Pinned action versions.** Every action referenced in the release
  workflow is pinned to a tagged release or commit SHA — no `@main`,
  no floating references.
- **HTTPS-only downloads** from `github.com` release assets, enforced
  in `install.sh` (strict-mode bash, quoted variables, TLS 1.2+).
- **Weekly Dependabot** scanning of Cargo and GitHub Actions
  dependencies.
- **Reproducible-build work in progress.** Deterministic output is a
  v0.2 commitment; today the maintainers do not claim bit-for-bit
  reproducibility.

The maintainers do not currently publish to crates.io as the primary
distribution channel. The canonical install path is the GitHub
Releases page or the install script, both of which are covered by the
attestations above.

## Verifying releases

Verify the checksum:

```sh
curl -LO https://github.com/enforcegrid/steer/releases/download/vX.Y.Z/SHA256SUMS
curl -LO https://github.com/enforcegrid/steer/releases/download/vX.Y.Z/steer-vX.Y.Z-aarch64-apple-darwin.tar.gz
sha256sum -c SHA256SUMS --ignore-missing
```

Verify the build provenance attestation (requires `gh` ≥ 2.49):

```sh
gh attestation verify steer-vX.Y.Z-aarch64-apple-darwin.tar.gz \
  --owner enforcegrid \
  --repo  enforcegrid/steer
```

Both checks should succeed for any artifact produced by the official
release workflow. Failures should be reported via the channels in
"Reporting a vulnerability" above.

## Threat model and security boundaries

Steer's security model assumes:

- The operator controls the host on which Steer runs and has not been
  compromised. Steer does not defend against root-level adversaries on
  its own host.
- The upstream LLM provider is **untrusted by default**. Steer treats
  model output as adversarial input: prompt-injection,
  tool-call-injection, and exfiltration channels are surfaced for
  policy evaluation rather than passed through implicitly.
- The agent (Cursor, Claude Code, Aider, etc.) is **untrusted by
  default**. Steer's role is to constrain what the agent can do, not
  to vouch for it.
- Policy authors are trusted to write correct Cedar policies. Steer
  is responsible for evaluating policies faithfully and for surfacing
  evaluation errors to operators; it is not responsible for the
  outcome of a policy that says `permit(...)` when it should not.
- Audit emission is best-effort durable: Steer commits to emitting an
  audit record for every policy decision, but operators are
  responsible for the durability and integrity of the downstream
  audit sink.

Violations of these assumptions are not vulnerabilities in Steer, but
the maintainers welcome reports that surface places where the
assumptions are unclear in documentation or weaker than advertised.

## Third-party dependencies

Steer depends on a small set of widely-used Rust crates including
`tokio`, `hyper`, `cedar-policy`, and `serde`. Vulnerabilities are
handled as follows:

- Dependabot opens PRs against the repository within hours of an
  advisory landing in the GitHub Advisory Database.
- Patch-version bumps are merged after CI passes. Minor-version bumps
  are reviewed for behavioural changes before merge.
- A CVE in a dependency does **not** automatically constitute a
  vulnerability in Steer. Reports of the form "CVE-XXXX-YYYYY affects
  crate Z version A.B.C, which Steer depends on" will be closed
  unless they include a demonstration that Steer's use of the
  affected symbol is reachable and exploitable. This mirrors the
  approach used by the GitHub CLI maintainers.

## Past advisories and recognition

Confirmed vulnerabilities will be published as **GitHub Security
Advisories** at
[`github.com/enforcegrid/steer/security/advisories`](https://github.com/enforcegrid/steer/security/advisories).
CVE identifiers will be requested for any issue meeting the standard
CVE criteria.

As of this writing the advisory list is empty.

Researchers who responsibly disclose confirmed vulnerabilities are
credited — with their consent — in the relevant advisory and in a
"Security acknowledgements" section that will be added to this file
once the first disclosure lands.

## Bug bounty

The Steer project **does not currently offer a monetary bug bounty.**
The maintainers commit to:

- Public credit in the GitHub Security Advisory for the issue.
- A direct line to the maintainer team for follow-up.
- Re-evaluating bounty status as adoption grows.

Researchers who would benefit from a bounty program should consider
reporting issues that affect EnforceGrid Enterprise through that
product's channel instead; eligibility and reward criteria there are
managed separately.

## Procurement and enterprise security review

For procurement teams evaluating Steer as part of an enterprise
deployment:

- The OSS project itself does not undergo third-party audit.
- **EnforceGrid Enterprise** — the commercial distribution — pursues
  SOC 2 Type 2 and is the appropriate vehicle for signed security
  questionnaires, MSAs, and data processing agreements.
- Contact `security@enforcegrid.com` for questionnaire requests,
  security review meetings, or to start an enterprise security review.

The maintainers will respond to OSS-scoped security questions on a
best-effort basis through the same address.

## Document history

This policy is versioned with the repository. Material changes are
tracked in the commit history of `SECURITY.md`. The maintainers will
announce material changes in release notes.

— The Steer maintainers
