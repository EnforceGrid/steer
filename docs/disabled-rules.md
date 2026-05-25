# Disabling baseline policies

*Stub — the disable-rules manifest is on the v0.2 roadmap.*

## The gap

Cedar requires a unique `@id` per policy in the loaded set. This means you **cannot** override or disable a baseline rule by re-declaring its `@id` in your tenant overlay directory — Cedar will reject the duplicate at load time.

In v0.1.0, the workarounds for an operator who wants a baseline rule to *not* fire:

| Goal | Today's workaround | Upgrade-safe? |
|---|---|---|
| Disable a baseline rule outright | Fork `default.cedar` into your own directory and point `policy.policy_dir` at the fork | **no** — loses automatic baseline upgrades |
| Make a flag-rule never log (effective disable) | Author a tenant override that fires on the inverse condition and pre-empts the flag | partial; relies on Cedar evaluation order |
| Replace a baseline rule with stronger logic | Tenant override with a stricter `forbid` — "first forbid wins" semantics let it preempt | partial |

None of these is great. The fork breaks upgrade tracking; the inverse-condition trick is fragile.

## What v0.2 adds

A manifest file at `<policy_dir>/default/disabled-rules.yaml` that lists baseline `@id` values to skip at load time:

```yaml
# disabled-rules.yaml — example
disabled:
  - default-pii-flag                  # we have a stricter custom-pii-block
  - default-data-residency-flag       # not applicable to our deployment
```

The loader will:

1. Read the baseline `default.cedar`.
2. Parse the disabled-rules manifest.
3. Strip the listed `@id`s from the baseline policy set before handing to Cedar.
4. Load tenant overlays on top.
5. Log every disabled rule at startup so the auditor can see what was skipped.

The disabled list is **versioned with the operator's overlay directory**, so it survives binary upgrades and is auditable as part of the policy package.

## Compliance implications

Disabling a baseline rule is an operator choice with audit consequences. The startup log records every disabled rule:

```
INFO steer: rule default-pii-flag disabled by <policy_dir>/default/disabled-rules.yaml
INFO steer: rule default-data-residency-flag disabled by <policy_dir>/default/disabled-rules.yaml
```

A regulator or internal auditor reviewing policy posture should grep the startup log for `disabled by` to enumerate every baseline rule that was opted out. The manifest is the artifact of the decision; the startup log is the evidence the decision is in effect.

## Until v0.2 ships

If you absolutely need to silence a specific baseline rule today, the lowest-friction options:

1. **Fork the file.** Copy `dsl/policies/default.cedar` to your overlay, comment out the rule, point `policy.policy_dir` at the fork. Track upstream changes by hand.
2. **Edit in place.** Edit your installed `default.cedar` (`~/.config/steer/policies/default.cedar` on a `install.sh` install) directly. The installer skips writing this file if a copy already exists, so an in-place edit survives a re-run of `install.sh`. A fresh tarball extraction or a `cargo install` reinstall *will* replace it — keep a copy in version control.
3. **Live with the noise.** Filter it out in your SIEM downstream rather than at evaluation time. The audit entry is cheap; the regex was going to run anyway.

For most v0.1.0 deployments, **option 3 is the right answer**. The cost of a flag-action audit entry you ignore is ~10 µs of CPU and a JSON line you `jq | grep -v` out of the dashboard.

If you have a use case where this isn't acceptable — particularly if a baseline rule produces false positives at a rate that breaks your audit-review workflow — open an [issue](https://github.com/EnforceGrid/steer/issues). We're using that input to prioritize the v0.2 manifest design.

---

## Related

- [docs/policies.md#1-the-overlay-model](policies.md#1-the-overlay-model) — current overlay semantics
