#!/usr/bin/env bash
# Single-purpose launcher invoked by the VHS tape — keeps the long tmux
# argument string out of the recorded session.
set -e

DEMO_ROOT=/tmp/steer-demo-recording

tmux kill-session -t steerdemo 2>/dev/null || true
tmux new-session -d -s steerdemo -x 200 -y 38 "bash --rcfile $DEMO_ROOT/left.bashrc"
tmux split-window -h -t steerdemo "bash --rcfile $DEMO_ROOT/right.bashrc"
tmux select-pane -t steerdemo:0.0
exec tmux attach -t steerdemo
