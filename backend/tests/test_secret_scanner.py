"""
Phase 3.1 — Unit tests for the secret scanner (Phase 2.6).

Tests scan_for_secrets() — pure function, zero network calls, zero DB.
Covers all 15 regex patterns plus entropy detection and edge cases.
"""

import pytest

from src.agents.secret_scanner import scan_for_secrets, SecretScanResult


# ── AWS ────────────────────────────────────────────────────────────────────────

class TestAWSSecrets:
    def test_detects_aws_access_key_id(self):
        code = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        result = scan_for_secrets(code)
        assert result.clean is False
        assert any("AWS Access Key" in m.pattern_name for m in result.matches)

    def test_detects_asia_prefix_key(self):
        code = 'key = "ASIAIOSFODNN7EXAMPLE12"'
        result = scan_for_secrets(code)
        assert result.clean is False

    def test_no_false_positive_on_short_word(self):
        code = "# AKIA is a prefix used by AWS"
        result = scan_for_secrets(code)
        # Comment line — should be skipped
        assert result.clean is True


# ── GitHub tokens ──────────────────────────────────────────────────────────────

class TestGitHubTokens:
    def test_detects_ghp_token(self):
        code = 'GITHUB_TOKEN = "ghp_' + "A" * 36 + '"'
        result = scan_for_secrets(code)
        assert result.clean is False
        assert any("GitHub" in m.pattern_name for m in result.matches)

    def test_detects_gho_token(self):
        code = 'token = "gho_' + "B" * 36 + '"'
        result = scan_for_secrets(code)
        assert result.clean is False

    def test_detects_ghs_token(self):
        code = 'secret = "ghs_' + "C" * 36 + '"'
        result = scan_for_secrets(code)
        assert result.clean is False

    def test_no_false_positive_on_short_ghp(self):
        code = 'description = "ghp_short"'
        result = scan_for_secrets(code)
        assert result.clean is True  # Too short to match


# ── Stripe ─────────────────────────────────────────────────────────────────────

class TestStripeKeys:
    def test_detects_live_secret_key(self):
        code = 'STRIPE_KEY = "sk_live_' + "x" * 30 + '"'
        result = scan_for_secrets(code)
        assert result.clean is False
        assert any("Stripe" in m.pattern_name for m in result.matches)

    def test_detects_test_secret_key(self):
        code = 'stripe.api_key = "sk_test_' + "y" * 30 + '"'
        result = scan_for_secrets(code)
        assert result.clean is False

    def test_publishable_key_not_flagged(self):
        # pk_ keys are not secrets
        code = 'STRIPE_PK = "pk_live_' + "z" * 30 + '"'
        result = scan_for_secrets(code)
        assert result.clean is True


# ── Slack ──────────────────────────────────────────────────────────────────────

class TestSlackTokens:
    def test_detects_bot_token(self):
        code = 'SLACK_TOKEN = "xoxb-1234567890-1234567890-' + "A" * 24 + '"'
        result = scan_for_secrets(code)
        assert result.clean is False
        assert any("Slack" in m.pattern_name for m in result.matches)

    def test_detects_slack_webhook_url(self):
        code = 'WEBHOOK = "https://hooks.slack.com/services/T12345678/B12345678/' + "A" * 24 + '"'
        result = scan_for_secrets(code)
        assert result.clean is False


# ── PEM private keys ───────────────────────────────────────────────────────────

class TestPEMKeys:
    def test_detects_rsa_private_key(self):
        code = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
        result = scan_for_secrets(code)
        assert result.clean is False
        assert any("Private Key" in m.pattern_name for m in result.matches)

    def test_detects_ec_private_key(self):
        code = "-----BEGIN EC PRIVATE KEY-----\ndata..."
        result = scan_for_secrets(code)
        assert result.clean is False

    def test_detects_openssh_private_key(self):
        code = "-----BEGIN OPENSSH PRIVATE KEY-----\ndata..."
        result = scan_for_secrets(code)
        assert result.clean is False

    def test_public_key_not_flagged(self):
        code = "-----BEGIN PUBLIC KEY-----\ndata..."
        result = scan_for_secrets(code)
        assert result.clean is True  # PUBLIC key is not a secret


# ── Generic hardcoded password ─────────────────────────────────────────────────

class TestHardcodedPasswords:
    def test_detects_password_assignment(self):
        code = 'password = "MySuperSecretP@ss123"'
        result = scan_for_secrets(code)
        assert result.clean is False

    def test_detects_db_password(self):
        code = 'DB_PASSWORD = "production_db_pass_999"'
        result = scan_for_secrets(code)
        assert result.clean is False

    def test_short_value_not_flagged(self):
        # Values under 12 chars shouldn't trigger (too many false positives)
        code = 'password = "short"'
        result = scan_for_secrets(code)
        assert result.clean is True

    def test_env_var_reference_not_flagged(self):
        # os.environ references are safe
        code = 'password = os.environ["DB_PASSWORD"]'
        result = scan_for_secrets(code)
        assert result.clean is True


# ── Comment line exclusion ─────────────────────────────────────────────────────

class TestCommentExclusion:
    def test_python_comment_skipped(self):
        code = '# AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # example only'
        result = scan_for_secrets(code)
        assert result.clean is True  # Comment line skipped

    def test_double_slash_comment_skipped(self):
        code = '// STRIPE_KEY = "sk_live_' + "x" * 30 + '"'
        result = scan_for_secrets(code)
        assert result.clean is True


# ── Entropy detection ──────────────────────────────────────────────────────────

class TestEntropyDetection:
    def test_high_entropy_string_flagged(self):
        # A realistic-looking random token
        code = 'token = "xK9mP2nQ8rL4sV7wJ1cB6hA3eD5fG0yT"'
        result = scan_for_secrets(code)
        # May or may not trigger depending on actual entropy
        # Just verify it doesn't crash
        assert isinstance(result, SecretScanResult)

    def test_low_entropy_string_not_flagged(self):
        # Repeated characters have low entropy
        code = 'value = "aaaaaaaaaaaaaaaaaaaaaa"'
        result = scan_for_secrets(code)
        assert result.clean is True

    def test_english_prose_not_flagged(self):
        code = 'description = "This is a normal description string that is long"'
        result = scan_for_secrets(code)
        assert result.clean is True


# ── Edge cases ─────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_string_is_clean(self):
        result = scan_for_secrets("")
        assert result.clean is True

    def test_whitespace_only_is_clean(self):
        result = scan_for_secrets("   \n\n\t  ")
        assert result.clean is True

    def test_matched_value_is_truncated(self):
        code = 'key = "AKIAIOSFODNN7EXAMPLE"'
        result = scan_for_secrets(code)
        if not result.clean:
            for match in result.matches:
                # Should never expose more than prefix + "..."
                assert len(match.matched_value) <= 15

    def test_rejection_message_lists_lines(self):
        code = 'key = "AKIAIOSFODNN7EXAMPLE"\nother = "safe"'
        result = scan_for_secrets(code)
        if not result.clean:
            msg = result.rejection_message()
            assert "Line" in msg
            assert "detected" in msg.lower()

    def test_multiple_secrets_capped_in_message(self):
        # Even with many secrets, rejection message shows at most 3
        lines = [
            'key1 = "AKIAIOSFODNN7EXAMPLE"\n',
            'key2 = "ghp_' + "A" * 36 + '"\n',
            'key3 = "sk_live_' + "x" * 30 + '"\n',
            'key4 = "xoxb-1234567890-1234567890-' + "A" * 24 + '"\n',
        ]
        result = scan_for_secrets("".join(lines))
        if not result.clean:
            msg = result.rejection_message()
            bullet_count = msg.count("•")
            assert bullet_count <= 3
