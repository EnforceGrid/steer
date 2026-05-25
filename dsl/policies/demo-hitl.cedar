// Demo HITL policy — human-in-the-loop review for production database operations.
// Used only in demo/GIF recording. Not loaded in production (not in default.cedar).
//
// Requires: handover.enabled: true in steer.yaml
//
// Fires at request time (llm.request) so the pipeline parks the request before
// the LLM is called. Tool-call-side evaluation happens post-response and does
// not trigger hold creation — only the request path does.

@id("demo-db-delete-review")
@category("tool_governance")
@regulatory_mapping("INTERNAL_REVIEW")
@enforcement("steer")
@description("Destructive database operation — held for reviewer approval")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context has requested_tools && context.requested_tools.contains("db_delete_all") };
