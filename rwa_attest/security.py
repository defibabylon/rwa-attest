"""
Security layer for the Cardano DeFi MCP server.

The threat model: an AI assistant (or its user) connects to this MCP server
and attempts to extract data that doesn't belong to the public DeFi domain —
private keys, API secrets, vault notes, CVs, job pipeline data, anything under
TV's filesystem that's not explicitly public.

This module enforces — by construction, not by convention — the following:

  1. ALLOWED_HOSTS         — only these HTTPS endpoints may be contacted upstream
  2. ALLOWED_FILE_READS    — exhaustive list of files any tool may read
  3. validate_protocol_name — rejects path traversal, shell metacharacters, oversize
  4. scan_for_secrets       — refuses to emit a response containing secret-shaped data
  5. RateLimiter            — per-client request budget (in-memory, defense-in-depth)

Every tool MUST route its outbound HTTP through `safe_get`, route its file
reads through `safe_read`, validate any string argument through
`validate_protocol_name` (or a similar named validator), and finalize its
response through `safe_response`. Failure to do so is a security defect.
"""
import hashlib
import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import requests

# ──────────────────────────────────────────────────────────────────────────────
# Allowlists — by construction
# ──────────────────────────────────────────────────────────────────────────────

ALLOWED_HOSTS: frozenset[str] = frozenset({
    "api.llama.fi",
    "stablecoins.llama.fi",
    "coins.llama.fi",
    "api.coingecko.com",
    "gamma-api.polymarket.com",
})

# Exhaustive list of files this MCP server may read. Tool inputs are NEVER
# concatenated into a path; every read is against a constant from this set.
ALLOWED_FILE_READS: frozenset[Path] = frozenset({
    Path("/root/hermes-rwa-catalyst/data/signed_rwa_attestation.json"),
    Path("/root/hermes-rwa-catalyst/data/signed_rwa_attestation.json.prev"),
    Path("/root/hermes-rwa-catalyst/config/policy_profile_signed_v0_1.yaml"),
    # Per-protocol attestations + manifest
    Path("/root/hermes-rwa-catalyst/data/attestations/manifest.json"),
    Path("/root/hermes-rwa-catalyst/data/attestations/centrifuge.json"),
    Path("/root/hermes-rwa-catalyst/data/attestations/blackrock-buidl.json"),
    Path("/root/hermes-rwa-catalyst/data/attestations/ondo-ousg.json"),
    Path("/root/hermes-rwa-catalyst/data/attestations/ondo-usdy.json"),
    Path("/root/hermes-rwa-catalyst/data/attestations/maple.json"),
    Path("/root/hermes-rwa-catalyst/data/attestations/hashnote-usyc.json"),
    Path("/root/hermes-rwa-catalyst/data/attestations/superstate.json"),
    Path("/root/hermes-rwa-catalyst/data/attestations/spiko.json"),
})

# Subprocess invocations: absolute-path executables only, no shell, fixed argv shape.
ALLOWED_SUBPROCESS_EXEC: frozenset[str] = frozenset({
    "/usr/bin/python3",
})

# Working directory whitelist for subprocess invocations
ALLOWED_SUBPROCESS_CWDS: frozenset[Path] = frozenset({
    Path("/tmp"),
    Path("/root/hermes-rwa-catalyst"),
})


# ──────────────────────────────────────────────────────────────────────────────
# Input validators
# ──────────────────────────────────────────────────────────────────────────────

_PROTOCOL_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_. ]{0,63}$")


def validate_protocol_name(name: str) -> str:
    """Strict validator for a protocol slug arg. Returns the validated name
    or raises ValueError. Defends against path traversal, shell injection,
    and oversize inputs."""
    if not isinstance(name, str):
        raise ValueError("protocol name must be a string")
    if len(name) == 0 or len(name) > 64:
        raise ValueError("protocol name must be 1..64 chars")
    if not _PROTOCOL_NAME_RE.match(name):
        raise ValueError("protocol name has invalid characters (allowed: alphanumeric, dash, underscore, dot, space)")
    if ".." in name or "\x00" in name:
        raise ValueError("protocol name contains forbidden sequence")
    return name


def validate_positive_int(value: Any, max_val: int = 100) -> int:
    """Validator for limit / count style ints."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ValueError("expected an integer")
    if v < 1 or v > max_val:
        raise ValueError(f"value must be in [1, {max_val}]")
    return v


# Recognised chain names (DefiLlama nomenclature). Allowlist-based — unknown
# chains rejected to prevent typo-driven unexpected behavior.
_KNOWN_CHAINS: frozenset[str] = frozenset({
    "Ethereum", "Cardano", "Solana", "Arbitrum", "Optimism", "Base", "Polygon",
    "Avalanche", "BSC", "Sui", "Aptos", "Tron", "Stellar", "Bitcoin", "Cosmos",
    "Mantle", "Linea", "Blast", "Scroll", "zkSync Era", "Starknet",
    "Hyperliquid L1", "Berachain", "Sei", "Celo", "Mantra", "Plume",
})


def validate_chain_name(name: str) -> str:
    """Strict allowlist of chain names. Case-insensitive match; returns the
    canonical-cased name."""
    if not isinstance(name, str) or not name:
        raise ValueError("chain name must be a non-empty string")
    if len(name) > 32:
        raise ValueError("chain name must be ≤ 32 chars")
    name_lc = name.strip().lower()
    for canonical in _KNOWN_CHAINS:
        if canonical.lower() == name_lc:
            return canonical
    raise ValueError(
        f"unknown chain: {name!r}. Examples of allowed chains: "
        f"Ethereum, Cardano, Solana, Arbitrum, Optimism, Base, Polygon"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Secrets scanner — fail-closed if a response could leak credentials
# ──────────────────────────────────────────────────────────────────────────────

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pem_private_key",  re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("ssh_private_key",  re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    ("anthropic_key",    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key",       re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("xai_key",          re.compile(r"xai-[A-Za-z0-9]{20,}")),
    ("replicate_key",    re.compile(r"r8_[A-Za-z0-9_-]{20,}")),
    ("composio_key",     re.compile(r"ak_[A-Za-z0-9_-]{20,}")),
    ("airtable_key",     re.compile(r"pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{32,}")),
    ("hf_key",           re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("slack_app",        re.compile(r"xapp-[A-Za-z0-9-]{20,}")),
    ("slack_bot",        re.compile(r"xoxb-[A-Za-z0-9-]{20,}")),
    ("linkedin_li_at",   re.compile(r"LINKEDIN_LI_AT[=:]\s*[A-Za-z0-9]{20,}")),
    ("env_dotenv",       re.compile(r"^[A-Z_]+(API_KEY|TOKEN|SECRET|PASSWORD)=\S+", re.MULTILINE)),
    # Sensitive filesystem paths — should never appear in a response
    ("tv_keys_path",     re.compile(r"/root/\.hermes/keys/")),
    ("tv_env_path",      re.compile(r"/root/career-ops/[^\s]*\.env")),
    ("tv_vault_path",    re.compile(r"/root/Obsidian Vault/")),
    ("tv_session_path",  re.compile(r"/root/\.hermes/sessions/")),
    ("tv_memory_path",   re.compile(r"/root/\.claude/projects/-root/memory/")),
    ("tv_cv_path",       re.compile(r"/root/CVs/")),
)


def scan_for_secrets(text: str) -> list[str]:
    """Return the list of secret-pattern names found in `text`.
    Empty list = clean. Non-empty = response must NOT be emitted."""
    hits = []
    for name, pat in _SECRET_PATTERNS:
        if pat.search(text):
            hits.append(name)
    return hits


def safe_response(payload: Any) -> Any:
    """Final outbound sanitizer. Serializes the payload, scans for secrets,
    and either returns it intact (if clean) or raises a ResponseBlocked error
    that the server converts to a generic "internal error" — never leaking
    the leaking content itself."""
    import json
    serialized = json.dumps(payload, default=str) if not isinstance(payload, str) else payload
    hits = scan_for_secrets(serialized)
    if hits:
        raise ResponseBlocked(f"response blocked by secret scanner: {sorted(set(hits))}")
    return payload


class ResponseBlocked(Exception):
    pass


# ──────────────────────────────────────────────────────────────────────────────
# Allowlisted HTTP client
# ──────────────────────────────────────────────────────────────────────────────

class UpstreamHostBlocked(Exception):
    pass


def safe_get(url: str, timeout: int = 15) -> dict | list | None:
    """HTTPS GET that refuses to contact any host not on ALLOWED_HOSTS.
    Returns JSON-decoded body or None on transport error.
    NEVER returns response.text or raw bytes — JSON-only contract."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise UpstreamHostBlocked(f"only https scheme is permitted, got {parsed.scheme!r}")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise UpstreamHostBlocked(f"host {parsed.hostname!r} is not in ALLOWED_HOSTS")
    try:
        r = requests.get(url, headers={"User-Agent": "cardano-defi-mcp/0.1"}, timeout=timeout)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Allowlisted file reads
# ──────────────────────────────────────────────────────────────────────────────

class FileAccessBlocked(Exception):
    pass


def safe_read(path: Path) -> str:
    """Reads only paths in ALLOWED_FILE_READS. Refuses anything else."""
    if not isinstance(path, Path):
        path = Path(path)
    resolved = path.resolve()
    if resolved not in {p.resolve() for p in ALLOWED_FILE_READS}:
        raise FileAccessBlocked(f"path not in ALLOWED_FILE_READS: {resolved}")
    return resolved.read_text(encoding="utf-8")


# ──────────────────────────────────────────────────────────────────────────────
# Rate limiter (per-client, in-memory)
# ──────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    """Sliding-window per-client rate limiter. Client is identified by the
    arbitrary opaque key the server passes in (e.g. the MCP session id, or
    'stdio' for the local stdio transport which has one logical client)."""
    def __init__(self, max_per_minute: int = 30, max_per_day: int = 1000):
        self.max_per_minute = max_per_minute
        self.max_per_day = max_per_day
        self._minute: dict[str, deque[float]] = defaultdict(deque)
        self._day: dict[str, deque[float]] = defaultdict(deque)

    def check(self, client_id: str) -> tuple[bool, str | None]:
        """Returns (ok, reason). Updates counters on a successful check."""
        now = time.time()
        # purge windows
        minute_window = self._minute[client_id]
        while minute_window and minute_window[0] < now - 60:
            minute_window.popleft()
        day_window = self._day[client_id]
        while day_window and day_window[0] < now - 86400:
            day_window.popleft()
        if len(minute_window) >= self.max_per_minute:
            return False, f"rate limited: {self.max_per_minute} requests/minute exceeded"
        if len(day_window) >= self.max_per_day:
            return False, f"rate limited: {self.max_per_day} requests/day exceeded"
        minute_window.append(now)
        day_window.append(now)
        return True, None


# ──────────────────────────────────────────────────────────────────────────────
# Audit logging (privacy-preserving)
# ──────────────────────────────────────────────────────────────────────────────

def audit_log(tool_name: str, args: dict) -> str:
    """Returns an audit-log line. Anonymizes args by hashing — we record THAT
    a tool was called and WITH some args, but never the literal arg values."""
    arg_hash = hashlib.sha256(repr(sorted(args.items())).encode()).hexdigest()[:12]
    return f"[mcp-audit] tool={tool_name} args_hash={arg_hash} ts={time.time():.0f}"
