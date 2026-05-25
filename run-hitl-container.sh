#!/usr/bin/env bash
# Starts a Steer container with handover (HITL) enabled.
# Uses the local image tagged 'steer' — run 'docker build -t steer .' first.
#
# Usage: ./run-hitl-container.sh
set -euo pipefail

docker stop steer-hitl 2>/dev/null || true
docker rm   steer-hitl 2>/dev/null || true

# Assemble tenant policy dir from the source file — not committed to avoid
# baking the HITL policy into every regular container image.
mkdir -p .hitl-policies
cp dsl/policies/demo-hitl.cedar .hitl-policies/

# Patch handover.enabled in a temp config — everything else stays the same.
python3 - <<'PY'
lines = open('steer.example.yaml').readlines()
in_handover = False
out = []
for line in lines:
    if line.rstrip() == 'handover:':
        in_handover = True
    elif in_handover and line.startswith('  enabled:'):
        line = '  enabled: true\n'
        in_handover = False
    elif not line.startswith(' '):
        in_handover = False
    out.append(line)
open('/tmp/steer-hitl.yaml', 'w').writelines(out)
PY

docker run -d \
  --name steer-hitl \
  -p 8080:8080 \
  -e OPENAI_API_KEY="${OPENAI_API_KEY}" \
  -v /tmp/steer-hitl.yaml:/app/steer.yaml:ro \
  -v "$(pwd)/.hitl-policies:/app/dsl/policies/default:ro" \
  steer

echo "Waiting for health..."
until curl -sf localhost:8080/health > /dev/null 2>&1; do sleep 1; done
echo "steer-hitl ready on :8080 — handover enabled, demo-hitl.cedar loaded"
