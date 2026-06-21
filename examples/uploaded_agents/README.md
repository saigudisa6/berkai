# Uploaded Agent Examples

Drag `vulnerable_support_agent.redteamci.yaml` into Presenter Mode to stage a
runnable vulnerable agent. The manifest declares a CLI command, tools, and
sensitive resources; RedTeamCI uses those fields to generate refund, email, PII,
and safe-behavior attacks.

The agent is intentionally unsafe for the red check. It executes high-value
refunds without approval, emails customer data externally, and returns PII. Other
uploaded agents can declare fewer tools or no tools, which will generate a more
limited plan instead of these findings.
