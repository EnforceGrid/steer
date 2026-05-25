# steer-llm

**This crate is a placeholder name reservation on crates.io.**

The canonical install path for Steer is the prebuilt binary release on
GitHub, not `cargo install`.

---

## What is Steer?

Steer is open-source runtime enforcement for AI agents. It sits between
your agent and the LLM as a drop-in proxy: inspects requests, governs tool
calls, blocks unsafe actions, and emits audit evidence. Cedar policies run
on every request and response with sub-millisecond overhead. One
`base_url` change to wire it in.

See <https://github.com/enforcegrid/steer> for the full README, demo, and
policy reference.

## Why is this crate a placeholder?

The `steer-llm` binary is currently distributed as a signed,
prebuilt artifact via GitHub Releases — not via `cargo install`. The
binary install path is reviewed, checksummed, and ships with the default
policy bundle and example config alongside the binary, which `cargo
install` cannot replicate cleanly.

This crate exists to reserve the name on crates.io. It contains no
functional code.

## Canonical install

```sh
curl -fsSL https://raw.githubusercontent.com/enforcegrid/steer/main/install.sh | sh
```

For a reviewable install:

```sh
curl -fsSL https://raw.githubusercontent.com/enforcegrid/steer/main/install.sh -o install.sh
less install.sh
sh install.sh
```

## Source builds

```sh
git clone https://github.com/enforcegrid/steer
cd steer
cargo build --release --bin steer
```

## License

Apache-2.0. See the `LICENSE` file in this crate or the repository root.

## Links

- Source: <https://github.com/enforcegrid/steer>
- Issues: <https://github.com/enforcegrid/steer/issues>
- Releases: <https://github.com/enforcegrid/steer/releases>
