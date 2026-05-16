import math
import re
from dataclasses import dataclass
from importlib import resources


@dataclass
class Finding:
    pattern_name: str
    matched_text: str
    redacted_text: str


_BIP39_WORDS: frozenset[str] | None = None


def _bip39_words() -> frozenset[str]:
    """Lazy-load the BIP-39 English wordlist (2048 words)."""
    global _BIP39_WORDS
    if _BIP39_WORDS is None:
        data = resources.files("logtrain.redaction").joinpath("bip39_wordlist.txt")
        _BIP39_WORDS = frozenset(
            line.strip() for line in data.read_text().splitlines() if line.strip()
        )
    return _BIP39_WORDS


def _luhn_valid(digits: str) -> bool:
    """Validate a numeric string with the Luhn checksum."""
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if d < 0 or d > 9:
            return False
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _find_mnemonics(text: str) -> list[tuple[int, int]]:
    """Find BIP-39 mnemonic seed phrases (12/15/18/21/24 words from the wordlist).

    Returns list of (start, end) char offsets. A run is only flagged when *all*
    words in a contiguous lowercase-word sequence belong to the BIP-39 list
    and the run length is exactly one of the standard mnemonic sizes.
    """
    words = _bip39_words()
    matches: list[tuple[int, int]] = []
    # Iterate over runs of lowercase words separated by single ASCII spaces.
    for run in re.finditer(r"(?:[a-z]{3,8})(?:[ \t]+[a-z]{3,8})+", text):
        tokens = run.group(0).split()
        if len(tokens) not in (12, 15, 18, 21, 24):
            continue
        if not all(t in words for t in tokens):
            continue
        matches.append((run.start(), run.end()))
    return matches


# Identifier-name keywords that signal a secret. Matched at the end of an
# identifier (after optional prefix like HUGGING_FACE_HUB_) and followed by
# `=` or `:` and a value.
_SECRET_KEYWORD_GROUP = (
    r"(?:API[_-]?KEYS?|SECRET[_-]?KEYS?|ACCESS[_-]?KEYS?"
    r"|CLIENT[_-]?SECRETS?|PRIVATE[_-]?KEYS?|ENCRYPTION[_-]?KEYS?"
    r"|SIGNING[_-]?KEYS?|ACCOUNT[_-]?KEYS?"
    r"|REFRESH[_-]?TOKENS?|HUB[_-]?TOKENS?|AUTH[_-]?TOKENS?"
    r"|BEARER[_-]?TOKENS?|SESSION[_-]?TOKENS?|ACCESS[_-]?TOKENS?"
    r"|PASSWORDS?|PASSWDS?|CREDENTIALS?"
    r"|SECRETS?|TOKENS?|AUTH|PAT|KEY)"
)

# Value chars: broad enough to catch real secrets (incl. punctuation like
# `!@#$%^&*~`), but stops at whitespace, quotes, and structural delimiters
# so we don't run past the end of a JSON/YAML value.
_SECRET_VALUE = r"[^\s'\"`,;}\])]{8,}"

_ENV_SECRET_RX = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"([A-Za-z][A-Za-z0-9_-]*?)?"
    + _SECRET_KEYWORD_GROUP
    + r"(?![A-Za-z0-9])"
    + r"\s*[:=]\s*"
    + r"['\"]?("
    + _SECRET_VALUE
    + r")['\"]?",
    re.IGNORECASE,
)

PATTERNS = [
    (
        "jwt_token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    (
        # OpenAI: sk-..., sk-proj-..., sk-svcacct-..., sk-admin-...
        "openai_api_key",
        re.compile(r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    ),
    ("google_api_key", re.compile(r"AIzaSy[A-Za-z0-9_-]{33}")),
    ("google_oauth_client_secret", re.compile(r"GOCSPX-[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(r"gh[posr]_[A-Za-z0-9]{36}")),
    # Fine-grained PATs: github_pat_<22 chars>_<59 chars>
    ("github_fine_pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("gitlab_pat", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("huggingface_token", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[A-Z0-9]{16}")),
    ("slack_token", re.compile(r"xox[bpsa]-[A-Za-z0-9-]{10,}")),
    ("stripe_secret_key", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36,}")),
    ("pypi_token", re.compile(r"\bpypi-AgE[A-Za-z0-9_-]{50,}")),
    ("sendgrid_api_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{40,50}\b")),
    (
        "bearer_token",
        re.compile(r"Bearer\s+[A-Za-z0-9._\-+/]{20,}", re.IGNORECASE),
    ),
    (
        "basic_auth",
        re.compile(r"Basic\s+[A-Za-z0-9+/]{16,}={0,2}", re.IGNORECASE),
    ),
    (
        "db_url",
        re.compile(r"(?:postgres|mysql|mongodb|redis)://[^:]+:[^@\s]+@[^\s]+"),
    ),
    # PEM-encoded private keys: RSA/EC/DSA/OPENSSH/PKCS#8 (incl. ENCRYPTED).
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (
        "pgp_private_key",
        re.compile(
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----",
            re.DOTALL,
        ),
    ),
    # SSH public keys are not strictly secret, but they identify the user/host
    # and are usually unwanted in shared logs.
    (
        "ssh_public_key",
        re.compile(
            r"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521))\s+"
            r"[A-Za-z0-9+/]{20,}={0,3}(?:\s+\S+)?"
        ),
    ),
    # Crypto wallet keys.
    # Ethereum private key: 32 bytes hex, with required 0x prefix to avoid
    # matching SHA-256 hashes and similar bare-hex strings.
    ("ethereum_private_key", re.compile(r"\b0x[a-fA-F0-9]{64}\b")),
    # Bitcoin WIF (Wallet Import Format) private key.
    # Uncompressed: starts with 5, length 51. Compressed: starts with K/L, length 52.
    (
        "bitcoin_wif",
        re.compile(r"\b(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})\b"),
    ),
    # Credit card numbers (13-19 digits, validated with Luhn in scan/redact).
    (
        "credit_card",
        re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"),
    ),
    ("env_secret", _ENV_SECRET_RX),
]

ALLOWLIST = [
    re.compile(r"noreply@"),
    re.compile(r"@example\.(com|org|net)$"),
    re.compile(r"@github\.com$"),
    re.compile(r"@users\.noreply\.github\.com$"),
    re.compile(r"email@"),
    re.compile(r"test@"),
    re.compile(r"user@"),
    re.compile(r"example@"),
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_allowlisted(text: str) -> bool:
    return any(pattern.search(text) for pattern in ALLOWLIST)


def scan_text(text: str) -> list[Finding]:
    """Scan text and return a list of findings."""
    findings = []
    for name, pattern in PATTERNS:
        for match in pattern.finditer(text):
            matched = match.group(0)
            if name == "email" and _is_allowlisted(matched):
                continue
            if name == "env_secret":
                val = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
                if _shannon_entropy(val) < 3.0:
                    continue
            if name == "credit_card":
                digits = re.sub(r"[ -]", "", matched)
                if not (13 <= len(digits) <= 19) or not _luhn_valid(digits):
                    continue
            findings.append(
                Finding(
                    pattern_name=name,
                    matched_text=matched,
                    redacted_text=f"[REDACTED_{name.upper()}]",
                )
            )
    for _start, _end in _find_mnemonics(text):
        findings.append(
            Finding(
                pattern_name="bip39_mnemonic",
                matched_text=text[_start:_end],
                redacted_text="[REDACTED_BIP39_MNEMONIC]",
            )
        )
    return findings


def redact_text(text: str) -> tuple[str, int]:
    """Redact secrets from text. Returns (redacted_text, count).

    Findings are applied from right to left by position to avoid offset
    issues caused by earlier replacements changing string length.
    """
    # Collect all match positions with their replacement strings
    replacements: list[tuple[int, int, str]] = []
    for name, pattern in PATTERNS:
        for match in pattern.finditer(text):
            matched = match.group(0)
            if name == "email" and _is_allowlisted(matched):
                continue
            if name == "env_secret":
                val = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
                if _shannon_entropy(val) < 3.0:
                    continue
                # Redact only the value, preserve the variable name.
                replacements.append((match.start(2), match.end(2), f"[REDACTED_{name.upper()}]"))
                continue
            if name == "credit_card":
                digits = re.sub(r"[ -]", "", matched)
                if not (13 <= len(digits) <= 19) or not _luhn_valid(digits):
                    continue
            replacements.append((match.start(), match.end(), f"[REDACTED_{name.upper()}]"))

    for m_start, m_end in _find_mnemonics(text):
        replacements.append((m_start, m_end, "[REDACTED_BIP39_MNEMONIC]"))

    if not replacements:
        return text, 0

    # Sort by start position descending so later matches don't shift earlier ones
    replacements.sort(key=lambda r: r[0], reverse=True)

    # Deduplicate overlapping matches (keep the rightmost/outermost)
    deduped: list[tuple[int, int, str]] = []
    last_start = len(text)
    for start, end, replacement in replacements:
        if end <= last_start:
            deduped.append((start, end, replacement))
            last_start = start

    result = list(text)
    for start, end, replacement in deduped:
        result[start:end] = list(replacement)

    return "".join(result), len(deduped)
