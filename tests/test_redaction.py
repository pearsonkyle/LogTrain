"""Tests for the redaction module."""

from logtrain.redaction.anonymizer import Anonymizer
from logtrain.redaction.secrets import redact_text, scan_text


def test_anthropic_api_key_detected():
    text = "key=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "anthropic_api_key" in names


def test_openai_api_key_detected():
    text = "Authorization: sk-abcdefghijklmnopqrstuvwx"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "openai_api_key" in names


def test_github_token_detected():
    text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "github_token" in names


def test_jwt_token_detected():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # noqa: E501
    findings = scan_text(jwt)
    names = [f.pattern_name for f in findings]
    assert "jwt_token" in names


def test_email_detected():
    text = "Contact alice@somecompany.io for details"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "email" in names


def test_email_allowlist_skipped():
    text = "noreply@github.com should not be flagged"
    findings = scan_text(text)
    email_findings = [f for f in findings if f.pattern_name == "email"]
    assert len(email_findings) == 0


def test_pem_private_key_detected():
    key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA1234567890abcdef\n"
        "-----END RSA PRIVATE KEY-----"
    )
    findings = scan_text(key)
    names = [f.pattern_name for f in findings]
    assert "private_key" in names


def test_redact_text_replaces_secrets():
    text = "My key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
    redacted, count = redact_text(text)
    assert count >= 1
    assert "sk-ant-api03" not in redacted
    assert "[REDACTED_ANTHROPIC_API_KEY]" in redacted


def test_redact_text_no_secrets():
    text = "Hello world, this is a normal sentence."
    redacted, count = redact_text(text)
    assert count == 0
    assert redacted == text


def test_anonymizer_username_replacement(monkeypatch):
    monkeypatch.setenv("USER", "johndoe")
    anon = Anonymizer()
    result = anon.text("Hello from johndoe on this machine")
    assert "johndoe" not in result
    assert "user_" in result


def test_anonymizer_home_dir_replacement():
    home = str(__import__("pathlib").Path.home())
    anon = Anonymizer()
    result = anon.text(f"file is at {home}/config.yaml")
    assert home not in result
    assert "REDACTED_USER" in result


def test_anonymizer_short_username_not_replaced(monkeypatch):
    monkeypatch.setenv("USER", "ab")
    anon = Anonymizer()
    result = anon.text("user ab logged in")
    assert result == "user ab logged in"


def test_anonymizer_extra_usernames():
    anon = Anonymizer(extra_usernames=["secretuser"])
    result = anon.text("path /home/secretuser/data")
    assert "secretuser" not in result


def test_huggingface_token_detected():
    text = "HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "huggingface_token" in names


def test_aws_access_key_detected():
    text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "aws_access_key" in names


def test_prefixed_hub_token_var_redacted():
    text = "HUGGING_FACE_HUB_TOKEN=zzkdmflerkjf83jrkemfkemr8348"
    redacted, count = redact_text(text)
    assert count == 1
    assert "zzkdmflerkjf83jrkemfkemr8348" not in redacted
    assert "HUGGING_FACE_HUB_TOKEN=" in redacted


def test_prefixed_api_key_var_redacted():
    text = "OPENAI_API_KEY=sk-proj-aaaaaaaaaaaaaaaaaaaabbbbbbbbb1234"
    redacted, count = redact_text(text)
    assert count == 1
    assert "sk-proj-aaaaaaaaaaaaaaaaaaaa" not in redacted
    assert "OPENAI_API_KEY=" in redacted


def test_client_secret_with_colon_separator():
    text = "AZURE_CLIENT_SECRET: aBcD1234EfGh5678IjKl9012MnOpQrSt"
    redacted, count = redact_text(text)
    assert count == 1
    assert "aBcD1234EfGh5678IjKl9012MnOpQrSt" not in redacted


def test_github_fine_grained_pat_detected():
    text = "GITHUB_PAT=github_pat_11ABCDEFG0abcdefghijklZyXwVuTsRqPoNmLkJiHgFeDcBa"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "github_fine_pat" in names


def test_google_oauth_client_secret_detected():
    text = "GOOGLE_CLIENT_SECRET=GOCSPX-aBcDeFgHiJkLmNoPqRsTuVwXyZ"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "google_oauth_client_secret" in names


def test_stripe_secret_key_detected():
    text = "STRIPE_SECRET=" + "sk_" + "live_" + "abcdefghijklmnopqrstuvwx"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "stripe_secret_key" in names


def test_json_style_api_key_redacted():
    text = '{"api_key": "sk-fakefakefakefakefakefake"}'
    redacted, count = redact_text(text)
    assert count >= 1
    assert "sk-fakefakefakefakefakefake" not in redacted


def test_password_with_special_chars_redacted():
    text = 'MY_DB_PASSWORD = "superSecret123!"'
    redacted, count = redact_text(text)
    assert count == 1
    assert "superSecret123!" not in redacted


def test_env_secret_value_only_replaced():
    """Var name should be preserved; only the value is redacted."""
    text = "GOOGLE_CLIENT_SECRET=GOCSPX-aBcDeFgHiJkLmNoPqRsTuVwXyZ"
    redacted, _ = redact_text(text)
    assert redacted.startswith("GOOGLE_CLIENT_SECRET=")


def test_low_entropy_value_not_flagged():
    text = "SOME_TOKEN=aaaaaaaa"
    redacted, count = redact_text(text)
    assert count == 0
    assert redacted == text


def test_normal_text_not_flagged():
    text = "the cat sat on the keyboard near the door"
    _, count = redact_text(text)
    assert count == 0


# --- Crypto wallet keys ---------------------------------------------------


def test_ethereum_private_key_detected():
    text = "PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    redacted, count = redact_text(text)
    assert count >= 1
    assert "ac0974bec39a17e36ba4a6b4d238ff94" not in redacted


def test_bitcoin_wif_compressed_detected():
    text = "wif: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "bitcoin_wif" in names


def test_bitcoin_wif_uncompressed_detected():
    text = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "bitcoin_wif" in names


def test_bip39_mnemonic_12_words_detected():
    text = (
        "seed: abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    redacted, count = redact_text(text)
    assert count == 1
    assert "[REDACTED_BIP39_MNEMONIC]" in redacted
    assert "abandon abandon" not in redacted


def test_bip39_mnemonic_24_words_detected():
    text = (
        "legal winner thank year wave sausage worth useful legal winner "
        "thank year wave sausage worth useful legal winner thank year "
        "wave sausage worth title"
    )
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "bip39_mnemonic" in names


def test_bip39_wrong_length_not_flagged():
    # 13 words — not a valid mnemonic length.
    text = " ".join(["abandon"] * 13)
    findings = scan_text(text)
    assert all(f.pattern_name != "bip39_mnemonic" for f in findings)


def test_bip39_non_wordlist_prose_not_flagged():
    # 12 lowercase short words but not all in the BIP-39 wordlist.
    text = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor"
    findings = scan_text(text)
    assert all(f.pattern_name != "bip39_mnemonic" for f in findings)


# --- PEM / PGP private keys ----------------------------------------------


def test_pgp_private_key_block_detected():
    text = (
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
        "lQHYBGabcdEF...\n"
        "-----END PGP PRIVATE KEY BLOCK-----"
    )
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "pgp_private_key" in names


def test_encrypted_pem_private_key_detected():
    text = (
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" "MIIE...\n" "-----END ENCRYPTED PRIVATE KEY-----"
    )
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "private_key" in names


# --- Service tokens -------------------------------------------------------


def test_pypi_token_detected():
    text = "pypi-AgEIcHlwaS5vcmcCJDEyMzQ1Njc4LWFiY2QtZWZnaC1pamtsLW1ub3BxcnN0dXZ3eA"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "pypi_token" in names


def test_sendgrid_api_key_detected():
    text = "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "sendgrid_api_key" in names


def test_gitlab_pat_detected():
    text = "GL=glpat-abcdefghij1234567890"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "gitlab_pat" in names


# --- HTTP auth / SSH ------------------------------------------------------


def test_basic_auth_header_detected():
    text = "Authorization: Basic dXNlcjpwYXNzd29yZA=="
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "basic_auth" in names


def test_ssh_public_key_detected():
    text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBabcdefghijklmnopqrstuvwxyz user@host"
    findings = scan_text(text)
    names = [f.pattern_name for f in findings]
    assert "ssh_public_key" in names


# --- Credit cards (Luhn) --------------------------------------------------


def test_valid_credit_card_redacted():
    text = "card: 4532015112830366"  # passes Luhn
    redacted, count = redact_text(text)
    assert count == 1
    assert "4532015112830366" not in redacted


def test_invalid_credit_card_not_flagged():
    text = "card: 4532015112830367"  # one digit off, fails Luhn
    _, count = redact_text(text)
    assert count == 0


def test_long_digit_id_not_flagged_as_card():
    text = "transaction id: 123456789012345"
    findings = scan_text(text)
    assert all(f.pattern_name != "credit_card" for f in findings)
