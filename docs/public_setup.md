# Public Setup

This document is about getting the public GitHub edition close to the author's working capability without shipping private data.

## What the public repo already includes

- Main runtime and MCP hub
- AI solver runtime
- Embedded `ctf-skills`
- Web, binary, and specialized solvers
- Fastest mode and solved export
- Tests and editor integration helpers

## What is intentionally not shipped

- `local_config.json`
- Private remote hosts
- Private wiki / writeup corpus
- Local sidecar virtual environments
- Personal workspace artifacts and caches

## Biggest capability gaps

If you want results close to a stronger private setup, the main factors are:

1. A strong LLM
2. A good `rag.wiki_root`
3. Remote helper hosts
4. IDA / Ghidra / x64dbg MCP sidecars

## Minimum usable setup

- Python 3.8+
- `python -m pip install -e .`
- `python -m pip install -e ".[web]"`
- A configured OpenAI-compatible model
- A local toolkit directory
- A browser for browser MCP

## Recommended setup order

1. Copy `local_config.example.json` to `local_config.json`
2. Fill `workspace_root`, `toolkit_root`, and `rag.wiki_root`
3. Set environment variables from `docs/examples/ctf_agent_env_template.ps1`
4. Install optional MCP sidecars
5. Add remote helpers if you want stronger `pwn` / `re` / `reverse`
6. Run `ctf-agent doctor`

## Suggested commands

```powershell
Copy-Item .\local_config.example.json .\local_config.json
python -m pip install -e .
python -m pip install -e ".[web]"
ctf-agent doctor --config .\local_config.json --workspace-root .\ctf-agent-output
```

## Optional personal wiki

The public repo keeps the `rag.wiki_root` interface but does not ship personal writeups.

If you want stronger long-tail performance:

- Prepare a sanitized wiki / writeup directory
- Point `rag.wiki_root` at that directory

## Optional nested MCP

Recommended order:

1. `ida-pro-mcp`
2. `ghidra-mcp`
3. `x64dbg-automate`
4. `browser-use`

## Remote helpers

The example config intentionally does not ship any `remote_hosts` entries.

If you want remote capability:

- Add one or more Linux helper hosts to `local_config.json`
- Keep passwords in environment variables
- Use `ctf-agent remote-probe --host <name>` to validate them
