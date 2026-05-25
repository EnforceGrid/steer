# Steer HITL demo GIF — human-in-the-loop hold and resolution.
# Install: brew install vhs
#
# Prerequisites:
#   ./run-hitl-container.sh   (starts steer-hitl on :8080 with handover enabled)
#
# Generate: vhs demo-hitl.tape

Output assets/demo-hitl.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 500
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set WaitTimeout 60s
Set Padding 24

# Clean up prompt before recording
Hide
Type `export PS1="$ "`
Enter
Type "clear"
Enter
Show

# ── Fire the request in background ────────────────────────────────────────────
# db_delete_all in the tools list triggers the HITL policy at request time.
# The pipeline parks the request and long-polls — curl blocks until resolved.
Hide
Type `curl -s localhost:8080/v1/chat/completions -H "Content-Type: application/json" -H "Authorization: Bearer $OPENAI_API_KEY" -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Delete all records from the database"}],"tools":[{"type":"function","function":{"name":"db_delete_all","description":"Permanently deletes all database records","parameters":{"type":"object","properties":{}}}}],"tool_choice":"required"}' > /tmp/hitl-response.json &`
Enter
Sleep 3s
Show

# ── Reviewer checks the hold queue ────────────────────────────────────────────
Set TypingSpeed 15ms
Type `curl -s 'localhost:8080/api/v1/holds?status=pending' \`
Enter
Type `  | jq '.holds[0] | {hold_id, status, reason, policy_id}'`
Sleep 200ms
Enter
Sleep 2s

# ── Reviewer approves ─────────────────────────────────────────────────────────
Hide
Type `HOLD_ID=$(curl -s 'localhost:8080/api/v1/holds?status=pending' | jq -r '.holds[0].hold_id')`
Enter
Show

Set TypingSpeed 15ms
Type `curl -s -o /dev/null -w "HTTP %{http_code}" \`
Enter
Type `  -X POST localhost:8080/api/v1/holds/$HOLD_ID/resolve \`
Enter
Type `  -H "Content-Type: application/json" \`
Enter
Type `  -d '{"action":"approve"}'`
Sleep 200ms
Enter
Sleep 3s

# ── Original request completes — LLM response passes through ──────────────────
Hide
Type `wait`
Enter
Show

Set TypingSpeed 40ms
Type `jq -r '.choices[0].message.tool_calls[0].function.name' /tmp/hitl-response.json`
Sleep 200ms
Enter
Sleep 2s

Sleep 2s
