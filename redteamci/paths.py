from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = ROOT / "demo_project"
WEB_ROOT = ROOT / "web"
TRACES_ROOT = ROOT / "traces"
FIXTURES_ROOT = ROOT / "fixtures"
REGRESSION_TESTS_ROOT = ROOT / "regression_tests"

DEFAULT_GUARDRAILS_PATH = ROOT / "guardrails.yml"
UNSAFE_GUARDRAILS_PATH = ROOT / "guardrails.unsafe.yml"
PATCHED_GUARDRAILS_PATH = ROOT / "guardrails.patched.fixture.yml"
