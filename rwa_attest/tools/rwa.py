"""
RWA (Real-World Assets) focused tools — where most of the action is.

These tools target the actual RWA landscape: tokenized US treasuries on Ethereum
(BlackRock BUIDL, Ondo OUSG/USDY, Hashnote USYC, Superstate, Spiko), private credit
(Maple, Centrifuge, Goldfinch, Clearpool), and the long tail.

Cardano RWA presence is small but tracked too (KAIO, Mehen, etc.) — TV's Cardano
operator background informs the "what to look for" lens even though the
chain-of-money is mostly Ethereum.
"""
from rwa_attest.security import (
    safe_get, safe_response, validate_protocol_name, validate_positive_int,
)

UPSELL_CTA = (
    "RWA trust attestation: this server can return a cryptographically signed "
    "trust evaluation (ed25519, canonical JSON, fail-closed verification) for "
    "RWA protocols via `get_signed_rwa_attestation`. For a custom attestation "
    "covering a protocol you care about, DM @tashomavilini on X."
)

RWA_CATEGORIES = {"RWA", "RWA Lending", "Real World Assets"}

# Name-based bucketing for issuer types
TREASURY_NAMES = {
    "buidl", "blackrock buidl", "ousg", "usdy", "ondo", "hashnote", "usyc",
    "spiko", "openeden", "tbill", "treasury", "matrixdock", "stbt", "backed",
    "blocktower", "usdm", "mountain", "wisdomtree", "franklin", "benji", "superstate",
}
CREDIT_NAMES = {
    "maple", "centrifuge", "goldfinch", "clearpool", "credix", "tinlake",
    "huma", "ribbon", "obligate", "truefi",
}


def _classify(p: dict) -> str:
    name_lc = (p.get("name") or "").lower()
    if any(h in name_lc for h in TREASURY_NAMES):
        return "tokenized_treasury"
    if any(h in name_lc for h in CREDIT_NAMES):
        return "private_credit"
    return "other"


def get_rwa_landscape() -> dict:
    """Overview of the RWA category: total TVL, split by sub-segment (tokenized
    treasuries vs private credit vs other), top issuers per segment, chain
    distribution. The RWA category lives primarily on Ethereum."""
    protocols = safe_get("https://api.llama.fi/protocols") or []
    rwa = [
        p for p in protocols
        if p.get("category") in RWA_CATEGORIES
        and (p.get("tvl") or 0) > 1_000_000  # filter sub-$1M dust
    ]
    rwa.sort(key=lambda x: x.get("tvl") or 0, reverse=True)

    # Bucket by issuer type
    treasuries = [p for p in rwa if _classify(p) == "tokenized_treasury"]
    credit = [p for p in rwa if _classify(p) == "private_credit"]
    other = [p for p in rwa if _classify(p) == "other"]

    # Chain distribution across RWA protocols
    chain_tvl: dict[str, float] = {}
    for p in rwa:
        chain_tvls = p.get("chainTvls") or {}
        if isinstance(chain_tvls, dict) and chain_tvls:
            for chain, val in chain_tvls.items():
                if chain.endswith("-borrowed") or chain.endswith("-staking"):
                    continue
                chain_tvl[chain] = chain_tvl.get(chain, 0) + float(val or 0)
        else:
            for chain in (p.get("chains") or []):
                chain_tvl[chain] = chain_tvl.get(chain, 0) + float(p.get("tvl") or 0)
    chain_dist = sorted(chain_tvl.items(), key=lambda x: -x[1])[:8]

    total = sum(p.get("tvl", 0) for p in rwa)

    return safe_response({
        "category": "RWA (Real-World Assets)",
        "total_tvl_usd": total,
        "protocols_tracked": len(rwa),
        "segments": {
            "tokenized_treasuries": {
                "tvl_usd": sum(p.get("tvl", 0) for p in treasuries),
                "count": len(treasuries),
                "top_5": [
                    {"name": p.get("name"), "tvl_usd": p.get("tvl"), "change_7d_pct": p.get("change_7d")}
                    for p in treasuries[:5]
                ],
            },
            "private_credit": {
                "tvl_usd": sum(p.get("tvl", 0) for p in credit),
                "count": len(credit),
                "top_5": [
                    {"name": p.get("name"), "tvl_usd": p.get("tvl"), "change_7d_pct": p.get("change_7d")}
                    for p in credit[:5]
                ],
            },
            "other_rwa": {
                "tvl_usd": sum(p.get("tvl", 0) for p in other),
                "count": len(other),
                "top_5": [
                    {"name": p.get("name"), "tvl_usd": p.get("tvl"), "change_7d_pct": p.get("change_7d")}
                    for p in other[:5]
                ],
            },
        },
        "chain_distribution_top_8": [
            {"chain": c, "tvl_usd": v} for c, v in chain_dist
        ],
        "data_source": "https://api.llama.fi (DefiLlama public API)",
        "note": UPSELL_CTA,
    })


def list_top_rwa_protocols(limit: int = 15) -> dict:
    """Top RWA protocols ranked by TVL, with chain + segment annotation."""
    lim = validate_positive_int(limit, max_val=50)
    protocols = safe_get("https://api.llama.fi/protocols") or []
    rwa = [
        p for p in protocols
        if p.get("category") in RWA_CATEGORIES
        and (p.get("tvl") or 0) > 100_000
    ]
    rwa.sort(key=lambda x: x.get("tvl") or 0, reverse=True)
    return safe_response({
        "category": "RWA (Real-World Assets)",
        "count": len(rwa[:lim]),
        "note": "Most RWA TVL lives on Ethereum. The chain field shows where each protocol's TVL is concentrated.",
        "protocols": [
            {
                "rank": i + 1,
                "name": p.get("name"),
                "segment": _classify(p),
                "primary_chain": (p.get("chains") or ["?"])[0],
                "all_chains": p.get("chains") or [],
                "tvl_usd": p.get("tvl"),
                "change_7d_pct": p.get("change_7d"),
                "change_30d_pct": p.get("change_1m"),
            }
            for i, p in enumerate(rwa[:lim])
        ],
        "data_source": "https://api.llama.fi (DefiLlama public API)",
        "upsell": UPSELL_CTA,
    })


def get_rwa_protocol_detail(protocol_name: str) -> dict:
    """Detailed view of a specific RWA protocol: TVL, momentum, chain spread,
    segment classification, and whether this server has a signed attestation
    for it."""
    name = validate_protocol_name(protocol_name)
    protocols = safe_get("https://api.llama.fi/protocols") or []
    name_lc = name.lower()
    # Exact lowercase match first; fall back to "starts-with" then substring
    match = next((p for p in protocols if p.get("name", "").lower() == name_lc), None)
    if not match:
        match = next((p for p in protocols if p.get("name", "").lower().startswith(name_lc)), None)
    if not match:
        match = next((p for p in protocols if name_lc in p.get("name", "").lower()), None)
    if not match:
        return safe_response({
            "error": "RWA protocol not found on DefiLlama",
            "queried": name,
            "hint": "use list_top_rwa_protocols for discovery",
        })

    # Check if this protocol has a current signed attestation on this server
    import json
    from pathlib import Path
    from rwa_attest.security import safe_read, ALLOWED_FILE_READS
    ATT_PATH = Path("/root/hermes-rwa-catalyst/data/signed_rwa_attestation.json")
    has_attestation = False
    attestation_id = None
    if ATT_PATH in ALLOWED_FILE_READS:
        try:
            att = json.loads(safe_read(ATT_PATH))
            if att.get("protocol_slug", "").lower() == name_lc:
                has_attestation = True
                attestation_id = att.get("attestation_id")
        except Exception:
            pass

    return safe_response({
        "name": match.get("name"),
        "segment": _classify(match),
        "category": match.get("category"),
        "chains": match.get("chains") or [],
        "primary_chain": (match.get("chains") or ["?"])[0],
        "tvl_usd": match.get("tvl"),
        "change_1d_pct": match.get("change_1d"),
        "change_7d_pct": match.get("change_7d"),
        "change_30d_pct": match.get("change_1m"),
        "tvl_by_chain_usd": match.get("chainTvls") or {},
        "description": (match.get("description") or "")[:600],
        "attestation": {
            "available_on_this_server": has_attestation,
            "attestation_id": attestation_id,
            "fetch_via": "get_signed_rwa_attestation" if has_attestation else None,
        },
        "data_source": "https://api.llama.fi (DefiLlama public API)",
        "upsell": UPSELL_CTA,
    })
