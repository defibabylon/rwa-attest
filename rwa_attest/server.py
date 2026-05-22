"""
Cardano DeFi MCP server — entry point.

Transport: stdio (the default for local AI assistants like Claude Desktop).
HTTP/SSE transport intentionally NOT enabled by default — running this as a
public HTTP service requires explicit deployment work + CORS allowlist and is
out of scope for the MVP.

Run with:
    /usr/local/lib/hermes-agent/venv/bin/python -m cardano_defi_mcp.server

(requires the `mcp` package, available in the hermes-agent venv.)
"""
import asyncio
import logging
import sys
import json
from typing import Any

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
import mcp.types as types

from rwa_attest import __version__
from rwa_attest.security import (
    RateLimiter, ResponseBlocked, UpstreamHostBlocked, FileAccessBlocked,
    audit_log,
)
from rwa_attest.tools.chain import (
    get_chain_defi_status, get_protocol_tvl, list_top_protocols,
)
from rwa_attest.tools.rwa import (
    get_rwa_landscape, list_top_rwa_protocols, get_rwa_protocol_detail,
)
from rwa_attest.tools.positioning import score_protocol_positioning
from rwa_attest.tools.attestation import (
    list_signed_rwa_attestations,
    get_signed_rwa_attestation,
    get_signed_rwa_attestation_full,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("rwa-attest")


# ──────────────────────────────────────────────────────────────────────────────
# Tool registry — defines the public API
# ──────────────────────────────────────────────────────────────────────────────

TOOLS: dict[str, dict[str, Any]] = {
    # ── Chain-level data (multi-chain, defaults Ethereum) ──────────────────
    "get_chain_defi_status": {
        "description": (
            "High-level DeFi stats for any major chain (default: Ethereum). "
            "Returns total TVL, native token, top 5 protocols by TVL. "
            "Supports Ethereum, Cardano, Solana, Arbitrum, Optimism, Base, Polygon, etc."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string", "default": "Ethereum",
                          "description": "Chain name (canonical DefiLlama casing, e.g. 'Ethereum', 'Cardano')"},
            },
            "additionalProperties": False,
        },
        "fn": lambda args: get_chain_defi_status(args.get("chain", "Ethereum")),
    },
    "get_protocol_tvl": {
        "description": (
            "TVL + 1d/7d/30d changes for any DefiLlama-listed protocol. "
            "Optional `chain` filter narrows to protocols deployed on that chain."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "protocol_name": {"type": "string", "description": "DefiLlama protocol name (e.g. 'Aave V3', 'Liqwid', 'Maple')"},
                "chain": {"type": "string", "description": "Optional chain filter (e.g. 'Ethereum')"},
            },
            "required": ["protocol_name"],
            "additionalProperties": False,
        },
        "fn": lambda args: get_protocol_tvl(args["protocol_name"], args.get("chain")),
    },
    "list_top_protocols": {
        "description": (
            "Top DeFi protocols by TVL on a given chain. Default: Ethereum top 10. "
            "Use this for discovery before calling get_protocol_tvl."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string", "default": "Ethereum",
                          "description": "Chain to rank within (default: Ethereum)"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "additionalProperties": False,
        },
        "fn": lambda args: list_top_protocols(args.get("chain", "Ethereum"), args.get("limit", 10)),
    },
    # ── RWA-focused tools (most of the action lives on Ethereum) ──────────
    "get_rwa_landscape": {
        "description": (
            "Overview of the RWA (Real-World Assets) category: total TVL, split "
            "by sub-segment (tokenized treasuries / private credit / other), top "
            "issuers per segment, chain distribution. Most RWA TVL is on Ethereum."
        ),
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
        "fn": lambda args: get_rwa_landscape(),
    },
    "list_top_rwa_protocols": {
        "description": (
            "Top RWA protocols by TVL — ranked across all chains. Annotates each "
            "with its segment (tokenized_treasury / private_credit / other) and "
            "primary chain. Returns BUIDL, OUSG, Ondo, Maple, Centrifuge, etc."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 15},
            },
            "additionalProperties": False,
        },
        "fn": lambda args: list_top_rwa_protocols(args.get("limit", 15)),
    },
    "get_rwa_protocol_detail": {
        "description": (
            "Detailed view of a specific RWA protocol: TVL, momentum, chain spread, "
            "segment classification, and whether a signed trust attestation is "
            "available for it on this server."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "protocol_name": {"type": "string", "description": "RWA protocol name (e.g. 'BlackRock BUIDL', 'Ondo OUSG', 'Maple', 'Centrifuge')"},
            },
            "required": ["protocol_name"],
            "additionalProperties": False,
        },
        "fn": lambda args: get_rwa_protocol_detail(args["protocol_name"]),
    },
    "score_protocol_positioning": {
        "description": (
            "FREE positioning teardown — scores a DeFi protocol on 5 dimensions "
            "(messaging clarity, niche specificity, TVL momentum, category fit, "
            "cross-chain reach). Returns a structured scorecard + recommended next "
            "action. This is the free tier; for a full teardown ask the upsell CTA in the response."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "protocol_name": {"type": "string", "description": "DefiLlama protocol name"},
            },
            "required": ["protocol_name"],
            "additionalProperties": False,
        },
        "fn": lambda args: score_protocol_positioning(args["protocol_name"]),
    },
    "list_signed_rwa_attestations": {
        "description": (
            "List every RWA protocol this server has a signed trust attestation for. "
            "Returns the manifest: 8+ protocols (BlackRock BUIDL, Ondo OUSG/USDY, "
            "Maple, Centrifuge, Hashnote USYC, Superstate, Spiko, …) with attestation "
            "IDs, timestamps, policy version, and proof_provenance."
        ),
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
        "fn": lambda args: list_signed_rwa_attestations(),
    },
    "get_signed_rwa_attestation": {
        "description": (
            "Signed RWA trust attestation (summary view) for a specific protocol or "
            "the most recent if no protocol_slug is given. Includes ed25519 "
            "verification metadata (canonical JSON, sub-agent + orchestrator "
            "signatures, supersedes-chain hash)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "protocol_slug": {
                    "type": "string",
                    "description": "Optional. e.g. 'blackrock-buidl', 'ondo-ousg', 'maple', 'centrifuge', 'hashnote-usyc', 'superstate', 'spiko'. Defaults to most recent.",
                },
            },
            "additionalProperties": False,
        },
        "fn": lambda args: get_signed_rwa_attestation(args.get("protocol_slug")),
    },
    "get_signed_rwa_attestation_full": {
        "description": (
            "Full signed RWA attestation document for a specific protocol — every "
            "proof_element, agent_signature, and orchestrator_signature. Use this "
            "when you want to independently verify the chain cryptographically."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "protocol_slug": {
                    "type": "string",
                    "description": "Optional. See list_signed_rwa_attestations for available slugs. Defaults to most recent.",
                },
            },
            "additionalProperties": False,
        },
        "fn": lambda args: get_signed_rwa_attestation_full(args.get("protocol_slug")),
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Server
# ──────────────────────────────────────────────────────────────────────────────

server = Server("rwa-attest")
rate_limiter = RateLimiter(max_per_minute=30, max_per_day=1000)
# Single-client by default for stdio transport — HTTP transport would use session ID
CLIENT_ID = "stdio"


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name=name, description=spec["description"], inputSchema=spec["input_schema"])
        for name, spec in TOOLS.items()
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    args = arguments or {}

    # Rate limit defense-in-depth
    ok, reason = rate_limiter.check(CLIENT_ID)
    if not ok:
        logger.warning(f"rate_limit tool={name}")
        return [types.TextContent(type="text", text=json.dumps({"error": reason}))]

    # Tool dispatch
    if name not in TOOLS:
        return [types.TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]

    logger.info(audit_log(name, args))
    try:
        # Tool fns are sync and quick (HTTP-bound) — run them as-is
        result = TOOLS[name]["fn"](args)
    except (UpstreamHostBlocked, FileAccessBlocked) as e:
        # Security-policy refusals: explicit but generic
        logger.warning(f"security_block tool={name} type={type(e).__name__}")
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": "request blocked by server security policy"}),
        )]
    except ResponseBlocked as e:
        # Response contained secret-shaped data — refuse, log details only server-side
        logger.error(f"response_blocked tool={name} hits={e}")
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": "response blocked by server safety scanner"}),
        )]
    except ValueError as e:
        # Input validation failure: safe to surface message (validators don't echo PII)
        return [types.TextContent(type="text", text=json.dumps({"error": str(e)}))]
    except Exception as e:
        # Any other failure: generic message, log full detail server-side only
        logger.exception(f"tool_error tool={name}")
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": "internal error", "detail": type(e).__name__}),
        )]

    return [types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))]


async def run_stdio():
    """stdio transport — for local AI assistants (Claude Desktop, Cursor, Cline)."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream,
            InitializationOptions(
                server_name="rwa-attest",
                server_version=__version__,
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


async def run_http(host: str, port: int):
    """Streamable-HTTP transport — for hosted listings (Smithery, etc.)."""
    import contextlib
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Mount
    from starlette.responses import JSONResponse
    from starlette.requests import Request
    import uvicorn

    session_manager = StreamableHTTPSessionManager(
        app=server,
        stateless=True,        # Each request is independent — no server-side session state
        json_response=False,   # SSE streaming for tool responses
    )

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "server": "rwa-attest", "version": __version__})

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette):
        async with session_manager.run():
            yield

    app = Starlette(
        routes=[Mount("/mcp", app=session_manager.handle_request)],
        lifespan=lifespan,
    )
    app.add_route("/healthz", health, methods=["GET"])
    app.add_route("/", health, methods=["GET"])

    logger.info(f"rwa-attest HTTP transport: http://{host}:{port}/mcp")
    config = uvicorn.Config(app, host=host, port=port, log_level="info", access_log=False)
    await uvicorn.Server(config).serve()


def main():
    import argparse, os
    parser = argparse.ArgumentParser(description="rwa-attest MCP server")
    parser.add_argument("--transport", choices=["stdio", "http"],
                        default=os.environ.get("MCP_TRANSPORT", "stdio"),
                        help="MCP transport (default: stdio)")
    parser.add_argument("--host", default=os.environ.get("MCP_HOST", "127.0.0.1"),
                        help="HTTP bind host (http transport only)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_PORT", "8090")),
                        help="HTTP bind port (http transport only)")
    args = parser.parse_args()

    if args.transport == "http":
        asyncio.run(run_http(args.host, args.port))
    else:
        asyncio.run(run_stdio())


if __name__ == "__main__":
    main()
