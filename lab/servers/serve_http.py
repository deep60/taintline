"""Serve any lab server over Streamable HTTP on 127.0.0.1 (never a public interface):

    python lab/servers/serve_http.py notes 8765 [--legacy]

--legacy keeps the server stateful (session ids), as 2025-era servers are.
"""
import importlib
import sys

name, port = sys.argv[1], int(sys.argv[2])
mod = importlib.import_module(f"{name}_server")
mod.mcp.run(transport="streamable-http", host="127.0.0.1", port=port,
            stateless_http="--legacy" not in sys.argv)
