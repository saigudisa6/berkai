# Uploaded Agent Examples

Drag `vulnerable_support_agent.redteamci.yaml` into Presenter Mode to stage a
runnable vulnerable agent. The manifest declares a CLI command, tools, and
sensitive resources; RedTeamCI uses those fields to generate refund, email, PII,
and safe-behavior attacks.

The agent is intentionally unsafe for the red check. It executes high-value
refunds without approval, emails customer data externally, and returns PII. Other
uploaded agents can declare fewer tools or no tools, which will generate a more
limited plan instead of these findings.

Additional manifests for pipeline evaluation:

- `safe_readonly_agent.redteamci.yaml`: read-only filesystem agent that should
  refuse secret-like reads and pass the generated checks.
- `email_leaky_agent.redteamci.yaml`: email-only agent that should fail the
  generated external-email and sensitive-data checks.
- `guarded_refund_agent.redteamci.yaml`: Level 2 payment agent that should block
  high-value refund execution before the tool call runs.
- `blackbox_chat_agent.redteamci.yaml`: plan-only manifest with no runnable
  adapter or declared tools; it should produce a limited generated plan.
