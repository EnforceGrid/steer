#!/usr/bin/env bash
# Demo setup — launches a tmux session BEFORE VHS records so the left pane
# is already showing the install command + steer running with logs. VHS
# then attaches to this session and types curls into the right pane.
set -euo pipefail

DEMO_ROOT=/tmp/steer-demo-recording
ROOT_REPO=/Users/arg0s/Dev/enforcegrid/steer

tmux kill-session -t steerdemo 2>/dev/null || true
rm -rf "$DEMO_ROOT"
mkdir -p "$DEMO_ROOT/cfg/policies/default" "$DEMO_ROOT/bin"

# Stage the steer binary, policies, yaml config.
cp "$ROOT_REPO/target/release/steer" "$DEMO_ROOT/bin/steer"
cp "$ROOT_REPO/dsl/policies/default.cedar" "$DEMO_ROOT/cfg/policies/default.cedar"
cp "$ROOT_REPO/assets/demo-policies/strict-pii.cedar" "$DEMO_ROOT/cfg/policies/default/strict-pii.cedar"
cp "$ROOT_REPO/assets/demo-policies/steer.yaml" "$DEMO_ROOT/cfg/steer.yaml"

# ── Left-pane startup: print install output then run steer ────────────────────
cat > "$DEMO_ROOT/left.bashrc" <<'EOF'
export PS1='● steer  $ '
export DEMO_ROOT=/tmp/steer-demo-recording
clear

# Render the install line as if the operator just typed it.
printf '\033[36m$ curl -fsSL https://raw.githubusercontent.com/enforcegrid/steer/main/install.sh \\\033[0m\n'
printf '\033[36m   | STEER_INSTALL_DIR=$DEMO_ROOT/bin sh\033[0m\n'
sleep 0.4
echo 'info: detected target: aarch64-apple-darwin'
sleep 0.15
echo 'info: resolving latest version...'
sleep 0.15
echo 'info: latest version: v0.1.0'
sleep 0.15
echo 'info: downloading steer-v0.1.0-aarch64-apple-darwin.tar.gz...'
sleep 0.4
echo 'info: SHA256 verified'
echo 'info: installing to /tmp/steer-demo-recording/bin/steer...'
sleep 0.2
echo ''
echo -e '\033[32m✓ Installed steer v0.1.0 to /tmp/steer-demo-recording/bin/steer\033[0m'
echo ''
sleep 0.4
printf '\033[36m$ steer --config /tmp/steer-demo-recording/cfg/steer.yaml\033[0m\n'
sleep 0.3
# Actually run steer — logs will stream when curls come in
exec "$DEMO_ROOT/bin/steer" --config "$DEMO_ROOT/cfg/steer.yaml"
EOF

# ── Right-pane startup: clean prompt waiting for input ────────────────────────
cat > "$DEMO_ROOT/right.bashrc" <<'EOF'
export PS1='● client $ '
export DEMO_ROOT=/tmp/steer-demo-recording
clear
EOF

# Create the session: left pane runs install+steer, right is empty.
tmux new-session -d -s steerdemo -x 200 -y 38 "bash --rcfile $DEMO_ROOT/left.bashrc"
sleep 0.5
tmux split-window -h -t steerdemo "bash --rcfile $DEMO_ROOT/right.bashrc"
tmux select-pane -t steerdemo:0.1   # focus on right pane for VHS typing
sleep 0.5

# Wait for steer to start listening on 9090
for i in {1..40}; do
  if curl -sf http://127.0.0.1:9090/health >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

echo "demo staged: tmux session 'steerdemo' running with steer on :9090"
