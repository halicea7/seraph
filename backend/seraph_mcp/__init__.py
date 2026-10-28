"""Seraph MCP connector — a local stdio MCP server that exposes Seraph's
REST API as tools for an MCP client (Claude Desktop, Claude Code, etc.).

This package is a client of the Seraph API, not part of it: it never
imports `main`, `database`, or any Seraph router module, and runs as its
own process (`python -m seraph_mcp`), authenticated like any other
`srph_...`-token caller — see client.py and README.md.
"""
