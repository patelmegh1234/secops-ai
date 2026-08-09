"""
Phase 3.1 — Unit tests for guardrail patch scope validation.

Tests validate_patch_scope() which runs before any LLM call.
Zero external dependencies — pure function tests, runs offline.
"""

import pytest

from src.agents.guardrail_agent import validate_patch_scope, MAX_DIFF_LINES


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_diff(added: int, removed: int) -> str:
    """Generate a synthetic unified diff with the given line counts."""
    lines = ["--- a/file.py", "+++ b/file.py"]
    lines += [f"+added line {i}" for i in range(added)]
    lines += [f"-removed line {i}" for i in range(removed)]
    return "\n".join(lines)


# ── Extension whitelist ────────────────────────────────────────────────────────

class TestExtensionWhitelist:
    def test_python_allowed(self):
        ok, reason = validate_patch_scope("src/auth.py", _make_diff(5, 5), "code")
        assert ok is True
        assert reason == ""

    def test_yaml_allowed(self):
        ok, _ = validate_patch_scope("config.yaml", _make_diff(1, 1), "code")
        assert ok is True

    def test_json_allowed(self):
        ok, _ = validate_patch_scope("package.json", _make_diff(1, 1), "code")
        assert ok is True

    def test_toml_allowed(self):
        ok, _ = validate_patch_scope("pyproject.toml", _make_diff(1, 1), "code")
        assert ok is True

    def test_md_allowed(self):
        ok, _ = validate_patch_scope("README.md", _make_diff(1, 1), "code")
        assert ok is True

    def test_binary_rejected(self):
        ok, reason = validate_patch_scope("image.png", _make_diff(1, 1), "")
        assert ok is False
        assert ".png" in reason

    def test_compiled_so_rejected(self):
        ok, reason = validate_patch_scope("lib/fast.so", _make_diff(1, 1), "")
        assert ok is False
        assert ".so" in reason

    def test_compiled_pyc_rejected(self):
        ok, reason = validate_patch_scope("auth/__pycache__/auth.pyc", _make_diff(1, 1), "")
        assert ok is False

    def test_exe_rejected(self):
        ok, reason = validate_patch_scope("runner.exe", _make_diff(1, 1), "")
        assert ok is False

    def test_no_extension_passes(self):
        # Files without extension (Makefile, Dockerfile) are not rejected by extension check
        ok, _ = validate_patch_scope("Makefile", _make_diff(1, 1), "code")
        assert ok is True


# ── Path blocklist ─────────────────────────────────────────────────────────────

class TestPathBlocklist:
    def test_dotenv_blocked(self):
        ok, reason = validate_patch_scope(".env", _make_diff(1, 1), "code")
        assert ok is False
        assert "blocked" in reason.lower()

    def test_dotenv_with_suffix_blocked(self):
        ok, reason = validate_patch_scope(".env.production", _make_diff(1, 1), "code")
        assert ok is False

    def test_secret_in_name_blocked(self):
        ok, reason = validate_patch_scope("config/secret_keys.py", _make_diff(1, 1), "code")
        assert ok is False

    def test_credential_in_name_blocked(self):
        ok, reason = validate_patch_scope("utils/credentials.py", _make_diff(1, 1), "code")
        assert ok is False

    def test_password_in_name_blocked(self):
        ok, reason = validate_patch_scope("passwords.py", _make_diff(1, 1), "code")
        assert ok is False

    def test_private_key_in_name_blocked(self):
        ok, _ = validate_patch_scope("auth/private_key.py", _make_diff(1, 1), "code")
        assert ok is False

    def test_settings_py_blocked(self):
        ok, reason = validate_patch_scope("settings.py", _make_diff(1, 1), "code")
        assert ok is False

    def test_config_py_blocked(self):
        ok, _ = validate_patch_scope("config.py", _make_diff(1, 1), "code")
        assert ok is False

    def test_git_path_blocked(self):
        ok, _ = validate_patch_scope(".git/config", _make_diff(1, 1), "code")
        assert ok is False

    def test_migrations_blocked(self):
        ok, reason = validate_patch_scope("alembic/migrations/001_init.py", _make_diff(1, 1), "code")
        assert ok is False

    def test_normal_path_allowed(self):
        ok, _ = validate_patch_scope("src/api/auth/handler.py", _make_diff(5, 5), "code")
        assert ok is True

    def test_windows_separator_normalised(self):
        # Windows paths with backslashes should be blocked too
        ok, _ = validate_patch_scope(r"config\secret_keys.py", _make_diff(1, 1), "code")
        assert ok is False


# ── Diff line count ────────────────────────────────────────────────────────────

class TestDiffLineLimit:
    def test_small_diff_allowed(self):
        ok, _ = validate_patch_scope("src/auth.py", _make_diff(10, 10), "code")
        assert ok is True

    def test_exactly_at_limit_allowed(self):
        # MAX_DIFF_LINES lines of changes (75 added + 75 removed = 150 total)
        diff = _make_diff(MAX_DIFF_LINES // 2, MAX_DIFF_LINES // 2)
        ok, _ = validate_patch_scope("src/auth.py", diff, "code")
        assert ok is True

    def test_one_over_limit_rejected(self):
        diff = _make_diff(MAX_DIFF_LINES // 2 + 1, MAX_DIFF_LINES // 2)
        ok, reason = validate_patch_scope("src/auth.py", diff, "code")
        assert ok is False
        assert "exceeds" in reason

    def test_far_over_limit_rejected(self):
        diff = _make_diff(200, 200)
        ok, reason = validate_patch_scope("src/auth.py", diff, "code")
        assert ok is False
        assert "400" in reason  # Should mention the actual count

    def test_diff_header_lines_not_counted(self):
        # +++ and --- header lines must NOT be counted as changed lines
        diff = "--- a/file.py\n+++ b/file.py\n+actual change\n-actual removal"
        ok, _ = validate_patch_scope("src/auth.py", diff, "code")
        assert ok is True  # Only 2 changed lines

    def test_empty_diff_allowed(self):
        ok, _ = validate_patch_scope("src/auth.py", "", "code")
        assert ok is True

    def test_rejection_message_contains_file_path(self):
        diff = _make_diff(200, 200)
        ok, reason = validate_patch_scope("src/auth.py", diff, "code")
        assert ok is False
        assert "maximum" in reason
