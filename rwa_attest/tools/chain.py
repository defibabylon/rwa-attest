"""
Multi-chain DeFi data tools — all wrap defillama public endpoints.
Default chain is Ethereum (where most TVL and most RWAs live), but every tool
accepts a `chain` parameter that supports Cardano, Solana, Arbitrum, etc.

Every tool routes outbound HTTP through `safe_get` and outputs through `safe_response`.
"""
from rwa_attest.security import (
    safe_get, safe_response, validate_protocol_name, validate_positive_int,
    validate_chain_name,
)

UPSELL_CTA = (
    "Built by Tashoma Vilini (Liqwid Finance co-founder & DeFi PMM, $81M TVL on Cardano). "
    "For a full positioning teardown of any DeFi protocol, DM @defibabylon on X "
    "or call this server's `score_protocol_positioning` tool."
)

# Categories to filter out when ranking "DeFi protocols" — these are infra,
# not user-facing DeFi
SKIP_CATEGORIES = {"CEX", "Chain", "Bridge", "Cross Chain Bridge"}


def get_chain_defi_status(chain: str = "Ethereum") -> dict:
    """High-level DeFi chain stats: total TVL, top protocols by TVL, native token.
    Default chain is Ethereum; supports Cardano, Solana, Arbitrum, etc."""
    chain = validate_chain_name(chain)

    chains = safe_get("https://api.llama.fi/v2/chains") or []
    chain_lc = chain.lower()
    match = next((c for c in chains if c.get("name", "").lower() == chain_lc), None)
    if not match:
        return safe_response({"error": f"chain not found on DefiLlama: {chain}"})

    protocols = safe_get("https://api.llama.fi/protocols") or []
    chain_protos = [
        p for p in protocols
        if chain in (p.get("chains") or [])
        and p.get("category") not in SKIP_CATEGORIES
        and (p.get("tvl") or 0) > 100_000
    ]
    chain_protos.sort(key=lambda x: x.get("tvl") or 0, reverse=True)

    return safe_response({
        "chain": match.get("name"),
        "total_defi_tvl_usd": match.get("tvl"),
        "native_token": match.get("tokenSymbol"),
        "protocols_tracked": len(chain_protos),
        "top_5_by_tvl": [
            {
                "name": p.get("name"),
                "category": p.get("category"),
                "tvl_usd": p.get("tvl"),
                "change_7d_pct": p.get("change_7d"),
            }
            for p in chain_protos[:5]
        ],
        "data_source": "https://api.llama.fi (DefiLlama public API)",
        "note": UPSELL_CTA,
    })


def get_protocol_tvl(protocol_name: str, chain: str | None = None) -> dict:
    """TVL + 1d/7d/30d changes for any DefiLlama-listed protocol.
    `chain` is an optional filter — if provided, the protocol must be on that chain."""
    name = validate_protocol_name(protocol_name)
    if chain is not None:
        chain = validate_chain_name(chain)

    protocols = safe_get("https://api.llama.fi/protocols") or []
    name_lc = name.lower()
    candidates = [p for p in protocols if p.get("name", "").lower() == name_lc]
    if chain is not None:
        candidates = [p for p in candidates if chain in (p.get("chains") or [])]
    if not candidates:
        return safe_response({
            "error": "protocol not found on DefiLlama" + (f" for chain={chain}" if chain else ""),
            "queried": name,
            "hint": "use list_top_protocols to discover valid names",
        })
    match = candidates[0]
    return safe_response({
        "name": match.get("name"),
        "category": match.get("category"),
        "chains": match.get("chains") or [],
        "tvl_usd": match.get("tvl"),
        "change_1d_pct": match.get("change_1d"),
        "change_7d_pct": match.get("change_7d"),
        "tvl_by_chain_usd": (match.get("chainTvls") or {}),
        "data_source": "https://api.llama.fi (DefiLlama public API)",
        "note": UPSELL_CTA,
    })


def list_top_protocols(chain: str = "Ethereum", limit: int = 10) -> dict:
    """List top DeFi protocols by TVL on a given chain. Default Ethereum."""
    chain = validate_chain_name(chain)
    lim = validate_positive_int(limit, max_val=50)

    protocols = safe_get("https://api.llama.fi/protocols") or []
    chain_protos = [
        p for p in protocols
        if chain in (p.get("chains") or [])
        and p.get("category") not in SKIP_CATEGORIES
        and (p.get("tvl") or 0) > 1_000
    ]
    chain_protos.sort(key=lambda x: x.get("tvl") or 0, reverse=True)
    return safe_response({
        "chain": chain,
        "count": len(chain_protos[:lim]),
        "protocols": [
            {
                "rank": i + 1,
                "name": p.get("name"),
                "category": p.get("category"),
                "tvl_usd": p.get("tvl"),
                "change_7d_pct": p.get("change_7d"),
            }
            for i, p in enumerate(chain_protos[:lim])
        ],
        "data_source": "https://api.llama.fi (DefiLlama public API)",
        "note": UPSELL_CTA,
    })
