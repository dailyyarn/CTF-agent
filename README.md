# CTF Agent

一个用于CTF的agent  支持web、misc、reverse、pwn、crypto、osint方向 目前能力还需完善 可选择接入一些工具mcp

This repository keeps a practical public edition of the agent runtime, with a single MCP hub, reproducible workspaces, embedded skills, solved export, and optional remote helpers. You can choose to connect some tools MCP.

## Why CTF Agent

- `ctf-agent` 是唯一执行主体，统一 CLI、MCP、Web console、workspace 和 triage board。
- 顶层只暴露 `ctf-agent-mcp`，把嵌套 MCP、工具链和远程能力收敛在同一个入口后面。
- 公共仓库内置 `embedded_ctf_skills`，开箱就有战术 playbook，不必先额外拉一个 skills 仓库。
- 默认路径公开安全，能力接口保留完整，方便别人装上自己的 MCP / wiki / remote helper 后尽量接近作者本机效果。

## Key Capabilities

| Area | Public Edition |
| --- | --- |
| Entry points | `ctf-agent`, `ctf-agent-mcp`, `ctf-agent-browser-mcp`, `ctf-agent serve-web` |
| Solver paths | AI loop, web solver, binary solver, specialized solvers |
| Knowledge | Embedded `ctf-skills` + optional `rag.wiki_root` |
| Pwn / Reverse | hard pwn families, remote helper interface, reverse MCP hooks |
| Outputs | `triage_board.json`, `task_protocol_summary.json`, `notes.md`, `solution.py`, solved export |
| Default public paths | `./ctf-agent-output`, `./ctf-toolkit`, `./agent-wp`, `./ctf-agent-wiki` |

Solved output contract:

- First line: `flag: ...`
- Second line: `wp_package_path: ...`
- Solved runs export `flag.txt`, `wp.md`, `poc.md`, `meta.json`, and `code/` under `./agent-wp/<category>_<title>_wp`

## Quick Start

```powershell
python -m pip install -e .
python -m pip install -e ".[web]"
Copy-Item .\local_config.example.json .\local_config.json

# Set your own OpenAI-compatible endpoint credentials first
$env:CTF_AGENT_LLM_API_KEY = 'your-key'
$env:CTF_AGENT_LLM_BASE_URL = 'https://api.example.com/v1'
$env:CTF_AGENT_LLM_MODEL = 'gpt-4o'

ctf-agent doctor --config .\local_config.json --workspace-root .\ctf-agent-output
ctf-agent-mcp
ctf-agent serve-web
```

最短公开工作流：

- `auto_solve_ctf`: 一句话直接做
- `get_ctf_board_summary`: 查看进度摘要


## Architecture

```text
challenge -> intake/router/autopilot
          -> solver runtime
             |- AI loop (LLM + tools + code execution + reflection)
             |- Binary / web / specialized solvers
             |- MCP hub + local tools + optional remote helpers
             |- workspace artifacts
             `- solved export
```

统一产物：

- `notes.md`
- `state.json`
- `runs.jsonl`
- `solution.py`
- `triage_board.json`
- `task_protocol_summary.json`
- `artifacts/*`

## Knowledge Sources

- Embedded skills: [ctf_agent/knowledge/embedded_ctf_skills](ctf_agent/knowledge/embedded_ctf_skills)
- Optional personal wiki: configured through `rag.wiki_root`


## Fastest Mode

触发关键词：

- `fastest`
- `最快`
- `speedrun`

命中后会优先走最短链路：

- 尽量跳过长链知识检索
- 不强制 preview / template 往返
- 输出更紧凑

## Hard Pwn

- 运行时可以先输出 `pwn_family`，再输出当前 blocker / next step
- 已支持的 family 包括 `seccomp-orw`、`sandbox-orw`、`srop`、`ret2dlresolve`、`heap-*`、`fsop`、`shellcode-mmap`
- fastest 模式下，hard-pwn lane 保持短而有界

## Third-Party Attribution

This repository embeds the upstream `ctf-skills` knowledge pack inside `ctf_agent/knowledge/embedded_ctf_skills`.

- Source: [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills)
- Upstream license: [MIT](https://raw.githubusercontent.com/ljagiello/ctf-skills/main/LICENSE)
- Local notice: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

The upstream `LICENSE` and `README.md` are preserved inside the embedded directory.

## Safety Boundary

- Only for authorized CTF, lab, and private research targets
- Do not commit `local_config.json`, 
1. 复制 [local_config.example.json](local_config.example.json) 到本地 `local_config.json`
2. 填好 LLM、toolkit、可选 wiki 路径
3. 跑一次 `ctf-agent doctor`
4. 用编辑器接 `ctf-agent-mcp`，或者直接开 `ctf-agent serve-web`

更多配置说明：

- [Public Setup](docs/public_setup.md)
- [Editor Integration](docs/editor_integration.md)
- [Remote Helpers](docs/remote_helpers.md)
- [MCP Catalog](docs/mcp_catalog.md)
- [Solved Output](docs/solved_output.md)
- [Fastest Mode](docs/fastest_mode.md)

## Demo Workflow

```text
Authorized challenge
  -> ctf-agent-mcp / ctf-agent serve-web
  -> intake + router + solver runtime
  -> tools / MCP / optional remote helper
  -> triage_board.json + notes.md + artifacts
  -> solved export under ./agent-wp
```
