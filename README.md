# rwa-attest

**Cryptographically verifiable RWA (Real-World Asset) trust attestation + multi-chain DeFi data + a free protocol positioning scorecard.** Exposed via [Model Context Protocol](https://modelcontextprotocol.io/) so any MCP-capable AI assistant (Claude Desktop, Cursor, Cline, etc.) can call it.

8 signed RWA attestations live: BlackRock BUIDL, Ondo OUSG, Ondo USDY, Maple Finance, Centrifuge Protocol, Hashnote USYC, Superstate, Spiko. Every signature independently verifiable from the embedded ed25519 public keys + canonical JSON.

Built by **Tashoma Vilini** — DeFi PMM, ex-Liqwid Finance ($81M TVL peak on Cardano).

---

## What it does

Ten tools, all read-only:

| Tool | Returns |
|---|---|
| `get_chain_defi_status(chain?)` | Total TVL, top 5 protocols, native token for any chain. **Default: Ethereum**. |
| `get_protocol_tvl(protocol_name, chain?)` | TVL + 1d/7d/30d changes for any DefiLlama-listed protocol. |
| `list_top_protocols(chain?, limit?)` | Ranked list of top DeFi protocols on a chain (default: Ethereum top 10). |
| `get_rwa_landscape` | RWA category overview: total TVL, segments (tokenized treasuries / private credit / other), top issuers per segment, chain distribution. |
| `list_top_rwa_protocols(limit?)` | Ranked list of top RWA protocols across all chains — BUIDL, Ondo, Maple, Centrifuge, USYC, etc. |
| `get_rwa_protocol_detail(protocol_name)` | Deep view of one RWA protocol: TVL, momentum, chain spread, segment, attestation availability. |
| `score_protocol_positioning(protocol_name)` | **FREE 5-dimension positioning scorecard** — messaging clarity, niche specificity, TVL momentum, category fit, cross-chain reach. The GTM hook. |
| `list_signed_rwa_attestations` | Every RWA protocol this server has a signed trust attestation for (BUIDL, Ondo OUSG/USDY, Maple, Centrifuge, Hashnote USYC, Superstate, Spiko, …). |
| `get_signed_rwa_attestation(protocol_slug?)` | Signed RWA trust attestation summary view for a specific protocol (default: most recent). |
| `get_signed_rwa_attestation_full(protocol_slug?)` | Full signed attestation with every proof_element + signature for independent cryptographic verification. |

Data source for chain/protocol tools: [DefiLlama public API](https://defillama.com/docs/api). No paid keys required for the data tools.

---

## Why use it

- **Built for where RWAs actually live.** Most RWA TVL ($15B+) is on Ethereum — BlackRock BUIDL, Ondo OUSG/USDY, Maple, Centrifuge, Hashnote USYC, Superstate, Spiko. This server is RWA-first and Ethereum-default.
- **Cardano-aware lens.** Author was a Cardano DeFi operator (Liqwid). Cardano's $130M DeFi ecosystem gets equal treatment — including the small but growing RWA presence (KAIO, Mehen).
- **Free positioning scorecard.** Tell it a protocol name; get a 5-dimension teardown. If the surface-level diagnosis is useful, the upsell path is a paid full teardown — DM `@tashomavilini` on X.
- **Verifiable attestations, not vibes.** The RWA attestation tool returns ed25519-signed trust evidence with reproducible canonical JSON. Most DeFi "trust scores" are opaque dashboards. Ours are cryptographically verifiable from the public keys + the policy + the inputs.

---

## Security model

Built defense-in-depth, by construction, not by convention. Every tool routes through:

| Layer | What it enforces |
|---|---|
| **Tool allowlist** | Exactly 10 tools. All read-only. No shell execution. No arbitrary file reads. No write operations. No code execution from inputs. |
| **HTTP host allowlist** | Outbound HTTP locked to: `api.llama.fi`, `stablecoins.llama.fi`, `coins.llama.fi`, `api.coingecko.com`, `gamma-api.polymarket.com`. Any other host → rejected. HTTPS only — `http://` schemes rejected. |
| **File-read allowlist** | Tools can only read 11 hard-coded files (the policy YAML + 2 chain-head attestations + 8 per-protocol attestations + manifest). Tool inputs are NEVER concatenated into paths. |
| **Chain-name allowlist** | The `chain` argument is matched against a frozen set of recognized chain names. Unknown chains rejected with a helpful error. |
| **Protocol-name validation** | Strict regex: alphanumeric + dash/dot/underscore/space, max 64 chars. Path traversal (`../`), shell metacharacters (`;`, `|`, `&`), oversize input — all rejected before any HTTP/file/LLM call. |
| **Secrets scanner on every response** | Patterns checked: PEM private keys, OpenAI / Anthropic / Replicate / Composio / HuggingFace / xAI / Slack API key formats, dotenv lines, sensitive filesystem paths (`/root/.hermes/keys/`, `/root/Obsidian Vault/`, `/root/CVs/`, memory dirs). Any hit → the response is REFUSED and a generic error returned. |
| **LLM context isolation** | The scorecard tool calls an LLM with a hermetic system prompt — no operator-personal context, no vault references, no instructions about other systems. The LLM sees only the public protocol metadata fetched from DefiLlama. |
| **Rate limiting** | Per-client request budget: 30/minute, 1000/day. In-memory defense-in-depth. |
| **Privacy-preserving audit log** | Server-side logs record THAT a tool was called with SOME args (hashed), but never the literal arg values or response content. |

### What this server CANNOT do, by design

- Cannot execute arbitrary code
- Cannot read your filesystem beyond the 11 hard-coded files above
- Cannot make HTTP requests to any host outside the 5-entry allowlist
- Cannot write any file
- Cannot start any subprocess
- Cannot exfiltrate environment variables, .env contents, or API keys
- Cannot leak filesystem paths under `/root/.hermes/keys/`, `/root/Obsidian Vault/`, `/root/CVs/`, `/root/.claude/projects/-root/memory/`, or any operator-personal location

If the server detects a non-allowlisted host, a non-allowlisted file read, or a response that would contain secret-shaped data, it refuses with a generic error and logs the violation server-side. No exception messages, file paths, or stack traces are surfaced to the caller.

---

## Install (Claude Desktop)

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (or platform equivalent):

```json
{
  "mcpServers": {
    "rwa-attest": {
      "command": "python",
      "args": ["-m", "rwa_attest.server"],
      "env": {
        "ANTHROPIC_API_KEY_FOR_MCP": "<your-anthropic-key-for-scorecard-tool>"
      }
    }
  }
}
```

The `ANTHROPIC_API_KEY_FOR_MCP` env var is optional — only needed if you want the `score_protocol_positioning` tool to actually score (it falls back to returning raw protocol metadata otherwise). The other 9 tools work without any API key.

## Install (Smithery)

```
npx @smithery/cli install rwa-attest --client claude
```

(once published — see `smithery.yaml`)

---

## Run locally

```bash
python -m rwa_attest.server
```

Speaks MCP via stdio. Compatible with any MCP client.

---

## Example queries

Once installed, ask your AI assistant things like:

- *"What's the total RWA TVL right now and which chain dominates?"*
- *"List the top 5 Ethereum RWA protocols by TVL."*
- *"Compare BlackRock BUIDL and Ondo Yield Assets — which has stronger 7d momentum?"*
- *"Score Aave V3's positioning on the 5 dimensions."*
- *"Show me the most recent signed RWA trust attestation."*
- *"Give me Cardano's DeFi status."* — Cardano is here too, just not the default.

---

## Architecture

```
rwa_attest/
├── security.py                # Allowlists, validators, secrets scanner, rate limiter
├── server.py                  # MCP entry point, tool registry, dispatch
└── tools/
    ├── chain.py               # Multi-chain DeFi data (DefiLlama) — Ethereum default
    ├── rwa.py                 # RWA landscape + top protocols + protocol detail
    ├── positioning.py         # FREE 5-dimension scorecard (sandboxed LLM)
    └── attestation.py         # Wraps the signed RWA attestation engine output
```

Every tool routes through:
- `validate_*(arg)` for inputs
- `safe_get(url)` for outbound HTTP (host allowlist)
- `safe_read(path)` for file reads (path allowlist)
- `safe_response(payload)` for outbound responses (secrets scanner)

This is enforced at the function level. There is no fall-through path that bypasses the security layer.

---

## License

MIT.

---

## Author

**Tashoma Vilini** — DeFi PMM, ex-Liqwid Finance ($81M TVL peak on Cardano).

For a full DeFi positioning teardown, GTM sprint, or custom RWA trust attestation: **DM `@tashomavilini` on X**.
