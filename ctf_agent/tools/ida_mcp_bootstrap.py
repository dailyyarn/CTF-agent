"""
IDA startup helper for automatically starting the MCP plugin server.

Usage example from an external shell:

    ida64.exe -S"<REPO_ROOT>\\ctf_agent\\tools\\ida_mcp_bootstrap.py" sample.bin

This script is intended to run inside IDA's embedded Python runtime.
"""

import importlib.util
import os
from pathlib import Path


PLUGIN_CANDIDATES = [
    Path(os.getenv("APPDATA", "")) / "Hex-Rays" / "IDA Pro" / "plugins" / "mcp-plugin.py",
    Path(__file__).resolve().parents[2] / ".sidecars" / "ida-pro-mcp-py312" / "Lib" / "site-packages" / "ida_pro_mcp" / "mcp-plugin.py",
]


def _load_plugin_module():
    for candidate in PLUGIN_CANDIDATES:
        if not candidate.exists():
            continue
        spec = importlib.util.spec_from_file_location("ida_mcp_plugin", str(candidate))
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, candidate
    raise RuntimeError("unable to locate mcp-plugin.py")


def main():
    module, plugin_path = _load_plugin_module()
    plugin = module.MCP()
    plugin.init()
    plugin.run(0)
    print("[CTF] IDA MCP bootstrap started from {0}".format(plugin_path))


if __name__ == "__main__":
    main()
