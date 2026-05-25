# Staged release workflow (Phase A)

This directory is a **staging area**, not a live GitHub Actions location.
GitHub only honours workflow files under `.github/workflows/` at the repo
root. Anything here is invisible to Actions until promoted.

## What `release.yml` does

On push of a tag matching `v*.*.*`:

1. Builds five binaries in parallel via a matrix (`fail-fast: false`):
   - `aarch64-apple-darwin` (macos-latest, native)
   - `x86_64-apple-darwin` (macos-13, native)
   - `x86_64-unknown-linux-gnu` (ubuntu-latest, native)
   - `aarch64-unknown-linux-gnu` (ubuntu-latest, via `cargo-zigbuild`)
   - `x86_64-pc-windows-msvc` (windows-latest, native)
2. Smoke-tests each native binary with `--version`. The aarch64 Linux
   binary is cross-compiled and cannot run on the x86_64 runner, so its
   smoke test is deferred to Phase D / Phase F runtime validation.
3. Stages the documented tarball layout (binary + `steer.example.yaml`
   + `dsl/policies/default.cedar` + `LICENSE` + a short `README.md`).
4. Computes a per-artifact SHA256 and attaches a GitHub-native build
   provenance attestation (`actions/attest-build-provenance@v1`,
   SLSA Level 2).
5. The aggregate `release` job downloads all five artifacts, concatenates
   the SHA256 fragments into a single `SHA256SUMS`, and publishes a
   GitHub Release containing all five archives plus `SHA256SUMS`. Release
   notes auto-generate from commits since the previous tag.

## How to test before promoting

Order from cheapest to most realistic:

1. **Lint locally:** `actionlint stage/.github/workflows/release.yml`.
2. **Dry-run with `act`:** limited usefulness — `act` does not run the
   macOS or Windows matrix legs, and provenance attestation requires
   GitHub OIDC. Useful only for the Linux x86_64 leg.
3. **Promote to a fork + tag:** the highest-fidelity test. Push a tag
   like `v0.0.0-test1` on a personal fork and watch all five legs.
   GitHub Releases on a fork is free and disposable.
4. **First real release:** tag `v0.1.0-rc1` on the canonical repo. The
   `prerelease: true` flag fires automatically because the tag contains
   a hyphen.

## How to promote

```bash
mkdir -p .github/workflows
git mv stage/.github/workflows/release.yml .github/workflows/release.yml
# Optional: keep this README in stage/ for posterity, or delete it.
git commit -m "ci: add binary release workflow (Phase A)"
```

After promotion, the workflow fires on the next `v*.*.*` tag push.

## Known limitations / TODO before first real release

- **`steer --version` is not currently wired.** `src/main.rs` derives
  `clap::Parser` on `Cli` with `#[command(name = "steer", about = ...)]`
  but does not set `version = ...`, so clap does not expose `--version`.
  The smoke-test step will fail until `Cli` is updated to either
  `#[command(name = "steer", version, ...)]` or
  `#[command(name = "steer", version = env!("CARGO_PKG_VERSION"), ...)]`.
  This is a one-line source change in a separate PR.
- **Action versions are pinned by tag, not commit SHA.** Tags are
  mutable. For supply-chain hardening (per spec §9, §13), replace each
  `@v4` with `@<commit-sha> # v4.x.y` before the first real release. A
  comment next to each action call notes this.
- **`cargo-zigbuild` install adds 1–2 min** to the aarch64 Linux leg.
  If the 15-minute SLA tightens, cache `~/.cargo/bin/cargo-zigbuild` and
  the Zig tarball.
- **No `Cargo.lock` cache.** Cold builds. Add `Swatinem/rust-cache@v2`
  if wall time creeps. Out of scope for Phase A.

## What to check on the first real release

- All five matrix legs green; aggregate job green.
- Release page shows exactly 5 archives + `SHA256SUMS` + 5 attestations.
- `gh attestation verify --owner enforcegrid <tarball>` succeeds.
- `tar -tzf` each tarball; confirm the documented file set.
- `sha256sum -c SHA256SUMS` passes against the downloaded archives.
- Wall time under 15 minutes (spec §14).
