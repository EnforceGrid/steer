# Steer demo — split-pane: install + steer on left, two blocked requests on right.
#
# Install VHS: brew install vhs
# Generate:    bash assets/demo-policies/setup.sh && vhs assets/demo.tape

Output assets/demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 1400
Set Height 680
Set Theme "Catppuccin Mocha"
Set TypingSpeed 22ms
Set WaitTimeout 30s
Set Padding 14

# Setup.sh has already started the tmux session in the background. Attach.
Hide
Type `tmux attach -t steerdemo`
Enter
Show
Sleep 2500ms

# ── RIGHT PANE: two blocked requests ──────────────────────────────────────────
Type `# 1) Asking the model for a PII record → BLOCK`
Enter
Sleep 400ms
Set TypingSpeed 18ms
Type `curl -sS http://127.0.0.1:9090/v1/messages \`
Enter
Type `  -H 'x-api-key: demo' \`
Enter
Type `  -H 'anthropic-version: 2023-06-01' \`
Enter
Type `  -H 'content-type: application/json' \`
Enter
Type `  -d '{"model":"claude-sonnet-4-6","max_tokens":256,"messages":[{"role":"user","content":"What is John Smith SSN 555-12-1234?"}]}' \`
Enter
Type `  | jq -c '{action: .enforcement.action, rule: .enforcement.rule_id}'`
Sleep 200ms
Enter
Sleep 4500ms

Type `clear`
Enter
Sleep 300ms

Type `# 2) Pasting what looks like an OpenAI key → BLOCK`
Enter
Sleep 400ms
Set TypingSpeed 18ms
Type `curl -sS http://127.0.0.1:9090/v1/messages \`
Enter
Type `  -H 'x-api-key: demo' \`
Enter
Type `  -H 'anthropic-version: 2023-06-01' \`
Enter
Type `  -H 'content-type: application/json' \`
Enter
Type `  -d '{"model":"claude-sonnet-4-6","max_tokens":256,"messages":[{"role":"user","content":"My OpenAI key is sk-proj-abc123def456ghi789jklmnopqrstuvwxyz"}]}' \`
Enter
Type `  | jq -c '{action: .enforcement.action, rule: .enforcement.rule_id}'`
Sleep 200ms
Enter
Sleep 4500ms

# Linger so the viewer can read the [BLOCK] log lines on the left pane.
Sleep 3s
