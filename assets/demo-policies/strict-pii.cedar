// Demo-only override that upgrades the shipped `default-pii-flag` policy
// from flag to block. Used by assets/demo.tape so the recorded GIF shows
// both example requests (PII record and OpenAI key) being blocked.
//
// To opt into stricter PII handling on your own deployment, copy this
// file into <policy_dir>/default/ (default ~/.config/steer/policies/default/).
// See docs/policies.md §7 for context.

@id("demo-strict-pii-block")
@category("data_protection")
@enforcement("block")
@description("Personal data detected in prompt — blocked (demo policy)")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when {
  context.pii_findings.containsAny([
    "credit_card", "ssn", "email", "phone", "phone_intl",
    "ip_address", "iban"
  ])
};
