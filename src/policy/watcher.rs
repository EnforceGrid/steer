//! File-system watcher for hot-reloading Cedar policy files.
//!
//! When `policy.watch: true` is set in `steer.yaml`, [`PolicyWatcher`] monitors
//! the configured `policy_dir` (or the parent dir of `policy_file`) for changes
//! to `.cedar` files.  On any change it rebuilds the [`CedarEngine`] and atomically
//! swaps it into the shared [`ArcSwap`] — zero downtime, zero lock contention on
//! the hot path.
//!
//! If the reload fails (e.g. a syntax error in an edited file) the old engine is
//! kept and a warning is emitted.  This makes the watcher fail-safe.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::RecursiveMode;
use notify::Watcher as NotifyWatcher;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::cedar::CedarEngine;
use crate::config::PolicyConfig;

/// Watches a policy directory and hot-reloads on `.cedar` file changes.
pub struct PolicyWatcher {
    config: PolicyConfig,
    swap: Arc<ArcSwap<CedarEngine>>,
    watch_path: PathBuf,
}

impl PolicyWatcher {
    /// Create a new watcher.  Does not start watching until [`run`] is called.
    pub fn new(config: PolicyConfig, swap: Arc<ArcSwap<CedarEngine>>) -> anyhow::Result<Self> {
        // Watch the dir that contains the policies
        let watch_path = if let Some(ref file) = config.policy_file {
            PathBuf::from(file)
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."))
        } else {
            PathBuf::from(&config.policy_dir)
        };

        Ok(Self {
            config,
            swap,
            watch_path,
        })
    }

    /// Start watching.  This is an async loop that runs until the channel is
    /// dropped (i.e. the notify watcher is dropped).  Intended to be spawned
    /// with `tokio::spawn`.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let (tx, mut rx) = mpsc::channel::<()>(32);

        // notify::recommended_watcher runs on a background OS thread; we bridge
        // it to the tokio world with a mpsc channel.
        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                match res {
                    Ok(event) => {
                        // Only care about .cedar files
                        let is_cedar = event
                            .paths
                            .iter()
                            .any(|p| p.extension().is_some_and(|ext| ext == "cedar"));
                        if is_cedar {
                            let _ = tx.try_send(());
                        }
                    }
                    Err(e) => warn!(error = %e, "policy watcher notify error"),
                }
            })?;

        if self.watch_path.exists() {
            watcher.watch(&self.watch_path, RecursiveMode::NonRecursive)?;
            info!(path = %self.watch_path.display(), "policy watcher started");
        } else {
            warn!(
                path = %self.watch_path.display(),
                "policy watch path does not exist — watcher idle"
            );
            // Park forever; watcher will be cancelled when the runtime shuts down.
            std::future::pending::<()>().await;
            return Ok(());
        }

        // Debounce: drain all pending signals, then wait 200 ms before reloading.
        loop {
            // Block until at least one change arrives
            if rx.recv().await.is_none() {
                break; // channel closed
            }

            // Drain any additional events that pile up during the debounce window
            tokio::time::sleep(Duration::from_millis(200)).await;
            while rx.try_recv().is_ok() {}

            // Attempt reload
            match CedarEngine::load_from_config(&self.config) {
                Ok(new_engine) => {
                    let count = new_engine.policy_count();
                    self.swap.store(Arc::new(new_engine));
                    info!(policy_count = count, "policy hot-reload succeeded");
                }
                Err(e) => {
                    warn!(error = %e, "policy hot-reload failed — keeping old policy set");
                }
            }
        }

        Ok(())
    }
}
