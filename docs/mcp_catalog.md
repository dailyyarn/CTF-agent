# MCP Catalog

This project uses two layers of MCP integration.

## Layer 1: top-level hub

The editor should talk to `ctf-agent-mcp`.

Typical high-level tools:

- `run_ctf_session`
- `continue_ctf_session`
- `auto_solve_ctf`
- `preview_ctf_task`
- `get_ctf_board_summary`
- `read_ctf_run_artifact`

## Layer 2: nested MCP managed by the hub

Configured in `local_config.json`:

- `ida-pro-mcp`
- `ghidra-mcp`
- `browser-use`
- `x64dbg-automate`

## Why keep nested MCP behind the hub

- Fewer tools exposed to the editor
- Better routing for CTF tasks
- Shared workspace and protocol outputs
- Consistent task intake

## Example nested MCP config

```json
{
  "preferred_browser_mcp": "browser-use",
  "preferred_reverse_mcp": "ida-pro-mcp",
  "mcp_servers": [
    {
      "name": "browser-use",
      "transport": "stdio",
      "command": "python",
      "args": ["-m", "ctf_agent.browser_mcp_server"],
      "enabled": true,
      "priority": 10
    }
  ]
}
```

## Debug commands

```powershell
ctf-agent mcp-list --config .\local_config.json
ctf-agent mcp-call --config .\local_config.json --server browser-use --tool tools/list --arguments "{}"
```
