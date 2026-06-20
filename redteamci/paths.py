from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = ROOT / "demo_project"
WEB_ROOT = ROOT / "web"
TRACES_ROOT = ROOT / "traces"
FIXTURES_ROOT = ROOT / "fixtures"
REGRESSIONS_ROOT = ROOT / "regressions"
REGRESSION_TESTS_ROOT = REGRESSIONS_ROOT
GENERATED_REGRESSIONS_PATH = REGRESSIONS_ROOT / "generated_attacks.json"
PATCHES_ROOT = ROOT / "patches"
DEFAULT_BEFORE_SUMMARY_PATH = ROOT / "before.json"
DEFAULT_AFTER_SUMMARY_PATH = ROOT / "after.json"
DEFAULT_REPORT_PATH = ROOT / "redteamci_report.md"
DEFAULT_MANIFEST_PATH = ROOT / "redteamci.yml"

DEFAULT_GUARDRAILS_PATH = ROOT / "guardrails.yml"
UNSAFE_GUARDRAILS_PATH = ROOT / "guardrails.unsafe.yml"
PATCHED_GUARDRAILS_PATH = ROOT / "guardrails.patched.fixture.yml"
