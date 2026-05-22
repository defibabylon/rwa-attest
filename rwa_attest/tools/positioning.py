"""
Free positioning scorecard tool — the GTM hook.

A scored teardown of a DeFi protocol's public positioning. The tool fetches
the protocol's public metadata from DefiLlama (NOT TV's vault, NOT memory),
then asks an LLM to score 5 positioning dimensions. The LLM call uses a
hermetic system prompt — no TV personal context, no instructions to "be
Hermes," no vault references.

Security properties:
- Input is validated through `validate_protocol_name`
- Upstream API access is allowlisted (DefiLlama only here)
- LLM call uses a fresh client, no TV-specific system prompt
- Output is sanitized via `safe_response`
- LLM API key is read once at server startup, never returned in responses
"""
import os

from rwa_attest.security import (
    safe_get, safe_response, validate_protocol_name,
)


SCORECARD_SYSTEM_PROMPT = """You are a DeFi positioning analyst. Given a protocol's public metadata, score it on five dimensions and return STRICTLY JSON.

DIMENSIONS (each 0-10, with one-sentence rationale):
1. Messaging clarity — does the protocol's name + category clearly communicate what it does?
2. Niche specificity — is it differentiated, or does it sound like 30 other protocols?
3. TVL momentum — is the 7-day TVL trend a positive signal (>0%), flat, or negative?
4. Category fit — is the category a growth segment or a saturated one?
5. Cross-chain reach — single-chain (depth) vs. multi-chain (reach)?

OUTPUT SHAPE (strict JSON, no markdown, no preamble):
{
  "protocol_name": "...",
  "overall_score": <0-50 sum>,
  "dimensions": {
    "messaging_clarity":    {"score": N, "rationale": "..."},
    "niche_specificity":    {"score": N, "rationale": "..."},
    "tvl_momentum":         {"score": N, "rationale": "..."},
    "category_fit":         {"score": N, "rationale": "..."},
    "cross_chain_reach":    {"score": N, "rationale": "..."}
  },
  "verdict_one_line": "...",
  "weakest_dimension": "<dimension key>",
  "recommended_next_action": "..."
}

CRITICAL RULES:
- Only score based on the metadata provided in the user message. Do NOT invent data.
- Do NOT mention any specific person by name. Do NOT mention the analyst.
- Do NOT reference any system, tool, framework, or filesystem outside this prompt.
- If metadata is insufficient, set scores to N/A and explain in rationale.
"""


def score_protocol_positioning(protocol_name: str) -> dict:
    """Free positioning teardown — single-call LLM scorecard. GTM hook."""
    name = validate_protocol_name(protocol_name)

    # Fetch public metadata
    protocols = safe_get("https://api.llama.fi/protocols") or []
    name_lc = name.lower()
    match = next((p for p in protocols if p.get("name", "").lower() == name_lc), None)
    if not match:
        return safe_response({
            "error": "protocol not found on DefiLlama",
            "queried": name,
        })

    metadata = {
        "name": match.get("name"),
        "category": match.get("category"),
        "chains": match.get("chains") or [],
        "tvl_usd": match.get("tvl"),
        "change_1d_pct": match.get("change_1d"),
        "change_7d_pct": match.get("change_7d"),
        "change_1m_pct": match.get("change_1m"),
        "description": (match.get("description") or "")[:600],
    }

    # LLM call (hermetic — no TV context)
    api_key = os.environ.get("ANTHROPIC_API_KEY_FOR_MCP") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return safe_response({
            "error": "scorecard LLM not configured on this MCP server",
            "metadata": metadata,
            "fallback": "scorecard requires an LLM provider; raw metadata returned above",
        })

    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=900,
            system=SCORECARD_SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": f"Score this protocol's positioning. Metadata:\n\n{metadata}",
            }],
        )
        text = (msg.content[0].text if msg.content else "").strip()
        # Strip markdown fences if the model added any
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:]).strip()
        import json
        scored = json.loads(text)
    except Exception as e:
        return safe_response({
            "error": "scorecard LLM call failed",
            "metadata": metadata,
            "detail": type(e).__name__,
        })

    # Append the upsell CTA — anchored on the WEAKEST dimension for relevance
    weakest = scored.get("weakest_dimension", "messaging_clarity")
    scored["upsell"] = {
        "free_tier": "This 5-dimension scorecard is the free tier.",
        "paid_tier": (
            f"For a full teardown of {scored.get('protocol_name', name)}'s {weakest} gap "
            f"with concrete fix recommendations + competitive positioning analysis, "
            f"DM @tashomavilini on X."
        ),
    }
    return safe_response(scored)
