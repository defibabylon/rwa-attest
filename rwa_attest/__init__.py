"""RWA Attest server — Tashoma Vilini.

Multi-chain DeFi data + free protocol positioning scorecard + cryptographically
verifiable RWA trust attestation. Exposes read-only tools via Model Context
Protocol. Strong on the RWA side (where most action is on Ethereum); Cardano-aware
because the author was a Cardano operator at Liqwid Finance.

Security model: every tool routes through allowlist + sanitizer in security.py.
No filesystem access from tool inputs. No shell execution. No private-key
exposure. Outbound HTTP locked to ALLOWED_HOSTS.

Entry point: rwa_attest.server.main
"""
__version__ = "0.2.0"
