"""
Wrapped RWA attestation tools — the credibility differentiator.

Three tools:
  - list_signed_rwa_attestations() — what's available on this server
  - get_signed_rwa_attestation(protocol_slug?) — summary view (default: most recent)
  - get_signed_rwa_attestation_full(protocol_slug?) — full signed document

No write side effects. No subprocess execution. All reads route through
ALLOWED_FILE_READS; tool inputs are validated and NEVER concatenated into paths.
Private keys are never serialized (defense in depth: the secrets scanner in
safe_response blocks any response containing a private-key marker).
"""
import json
from pathlib import Path

from rwa_attest.security import (
    safe_read, safe_response, ALLOWED_FILE_READS, validate_protocol_name,
)


# Tool inputs choose WHICH KEY, never WHICH PATH. Path mapping is hard-coded.
PROTOCOL_FILES: dict[str, Path] = {
    "centrifuge":       Path("/root/hermes-rwa-catalyst/data/attestations/centrifuge.json"),
    "blackrock-buidl":  Path("/root/hermes-rwa-catalyst/data/attestations/blackrock-buidl.json"),
    "ondo-ousg":        Path("/root/hermes-rwa-catalyst/data/attestations/ondo-ousg.json"),
    "ondo-usdy":        Path("/root/hermes-rwa-catalyst/data/attestations/ondo-usdy.json"),
    "maple":            Path("/root/hermes-rwa-catalyst/data/attestations/maple.json"),
    "hashnote-usyc":    Path("/root/hermes-rwa-catalyst/data/attestations/hashnote-usyc.json"),
    "superstate":       Path("/root/hermes-rwa-catalyst/data/attestations/superstate.json"),
    "spiko":            Path("/root/hermes-rwa-catalyst/data/attestations/spiko.json"),
}
MANIFEST_PATH = Path("/root/hermes-rwa-catalyst/data/attestations/manifest.json")
LEGACY_PATH = Path("/root/hermes-rwa-catalyst/data/signed_rwa_attestation.json")


def _resolve_path(protocol_slug: str | None) -> tuple[Path | None, str | None]:
    if not protocol_slug:
        return LEGACY_PATH, None
    try:
        slug = validate_protocol_name(protocol_slug).lower()
    except ValueError as e:
        return None, str(e)
    if slug not in PROTOCOL_FILES:
        return None, (
            f"no attestation available for protocol_slug={slug!r}. "
            f"Available: {sorted(PROTOCOL_FILES)}"
        )
    return PROTOCOL_FILES[slug], None


def list_signed_rwa_attestations() -> dict:
    """List every protocol this server has a signed RWA attestation for."""
    if MANIFEST_PATH in ALLOWED_FILE_READS:
        try:
            return safe_response(json.loads(safe_read(MANIFEST_PATH)))
        except Exception:
            pass
    available = []
    for slug, path in PROTOCOL_FILES.items():
        if path.exists() and path in ALLOWED_FILE_READS:
            available.append({"protocol_slug": slug, "file": f"attestations/{slug}.json"})
    return safe_response({
        "schema_version": 1,
        "total_attestations": len(available),
        "attestations": available,
        "note": "Manifest unavailable; list reflects file existence + allowlist only.",
    })


def get_signed_rwa_attestation(protocol_slug: str | None = None) -> dict:
    """SUMMARY view of one signed RWA attestation. Default: most recent."""
    path, err = _resolve_path(protocol_slug)
    if err:
        return safe_response({"error": err})
    if path not in ALLOWED_FILE_READS:
        return safe_response({"error": "attestation path not on server allowlist"})
    try:
        att = json.loads(safe_read(path))
    except Exception as e:
        return safe_response({"error": "attestation unavailable", "detail": type(e).__name__})

    return safe_response({
        "attestation_id": att.get("attestation_id"),
        "attestation_seq": att.get("attestation_seq"),
        "attestation_schema_version": att.get("attestation_schema_version"),
        "protocol_slug": att.get("protocol_slug"),
        "policy_id": att.get("policy_id"),
        "policy_version": att.get("policy_version"),
        "policy_content_hash": att.get("policy_content_hash"),
        "supersedes_attestation_hash": att.get("supersedes_attestation_hash"),
        "timestamp": att.get("timestamp"),
        "segmented_risk_scores": att.get("segmented_risk_scores"),
        "results_count": len(att.get("results") or []),
        "results_summary": [
            {"rule_id": r.get("rule_id"), "policy_category": r.get("policy_category"), "status": r.get("status")}
            for r in (att.get("results") or [])
        ],
        "verification": {
            "scheme": "ed25519",
            "canonical_form": "JSON, sorted keys, separators=(',', ':')",
            "verify_steps": [
                "Strip orchestrator_public_key + orchestrator_signature from the body",
                "Canonical-JSON the rest",
                "Verify orchestrator_signature with the embedded orchestrator_public_key",
                "Each proof_element verifies the same way against its agent_public_key",
            ],
        },
        "proof_provenance": (
            "demo: schema + cryptography are production-grade; proof_value contents "
            "are placeholders until Sprint 3 wires real fetchers (oracle prices, "
            "contract bytecode, audit URLs)."
        ),
        "upsell": (
            "For a real proof-grade attestation of a specific protocol or a custom "
            "trust policy, DM @tashomavilini on X."
        ),
    })


def get_signed_rwa_attestation_full(protocol_slug: str | None = None) -> dict:
    """FULL signed attestation JSON for one protocol."""
    path, err = _resolve_path(protocol_slug)
    if err:
        return safe_response({"error": err})
    if path not in ALLOWED_FILE_READS:
        return safe_response({"error": "attestation path not on server allowlist"})
    try:
        return safe_response(json.loads(safe_read(path)))
    except Exception as e:
        return safe_response({"error": "attestation unavailable", "detail": type(e).__name__})
