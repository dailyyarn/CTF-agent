# Editor Integration

Goal:

- The editor sees one hub: `ctf-agent-mcp`
- The editor passes only task text, target, and attachments
- Nested MCP, local tools, and remote helpers stay behind the hub

## Copy the config

```powershell
Copy-Item .\local_config.example.json .\local_config.json
```

## Recommended top-level tools

Use these first:

1. `run_ctf_session`
2. `continue_ctf_session`
3. `get_ctf_board_summary`

One-shot path:

1. `auto_solve_ctf`
2. `get_ctf_task_status`
3. `get_ctf_board_summary`

If input is noisy:

1. `preview_ctf_task`
2. use `suggested_task.quick_markdown`
3. then call `run_ctf_session` or `auto_solve_ctf`

## Cursor example

```json
{
  "mcpServers": {
    "ctf-agent": {
      "command": "ctf-agent-mcp",
      "args": [
        "--stdio",
        "--config",
        "<REPO_ROOT>\\local_config.json",
        "--workspace-root",
        "<WORKSPACE_ROOT>"
      ]
    }
  }
}
```

## Codex example

```powershell
codex mcp add ctf-agent -- ctf-agent-mcp --stdio --config <REPO_ROOT>\local_config.json --workspace-root <WORKSPACE_ROOT>
```

## Windsurf example

Use the same `ctf-agent-mcp` server shape as Cursor and point it at your local repo + workspace.

## Short chat format

```text
Type: web|misc|pwn|re|reverse|crypto|forensics|osint|malware
Target:
Files:
- F:/path/to/attachment
Hint:
```

## Why one hub only

Do not expose every nested MCP directly to the editor.

Keep:

- fewer tools
- better tool selection
- one workspace model
- one task protocol

Nested services such as `ida-pro-mcp`, `ghidra-mcp`, and `browser-use` should stay behind `ctf-agent-mcp`.
