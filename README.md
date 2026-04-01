# CTF Agent

Solve authorized CTF challenges with AI-powered reasoning, tool calling, local toolkit integration, optional MCP augmentation, and dual-source knowledge retrieval.

This public edition keeps the main runtime close to the author's working build: CLI, MCP hub, AI solver, fastest mode, hard-pwn workflow, solved export, embedded skills, browser MCP entry, remote-helper support, and the existing test suite all stay in the repository. It does not ship private secrets, private wiki content, personal sidecars, or a prefilled remote-host topology.

Docs:

- [Public Setup](docs/public_setup.md)
- [Editor Integration](docs/editor_integration.md)
- [Remote Helpers](docs/remote_helpers.md)
- [MCP Catalog](docs/mcp_catalog.md)
- [Solved Output](docs/solved_output.md)
- [Fastest Mode](docs/fastest_mode.md)

## 产品定位

`ctf-agent` 是一个面向授权 CTF / 靶场 / 私有研究目标的统一执行体。

- CLI: `ctf-agent`
- MCP Hub: `ctf-agent-mcp`
- Browser MCP entry: `ctf-agent-browser-mcp`
- Local web console: `ctf-agent serve-web`

默认公开版路径:

- Workspace root: `./ctf-agent-output`
- Toolkit root: `./ctf-toolkit`
- Solved export root: `./agent-wp`
- Optional wiki root: `./ctf-agent-wiki`

## Solved Output 约定

- If a challenge is solved, output `flag: ...` on the first line.
- The next line is `wp_package_path: ...`.
- Keep the conclusion short after that.
- Solved runs auto-export `flag.txt`, `wp.md`, `poc.md`, `meta.json`, and `code/` under `./agent-wp/<category>_<title>_wp` by default.

## 适用场景

当用户在做授权的 CTF / 靶场题，并且希望:

- AI 驱动的解题循环
- 双源知识检索
- 本地工具箱集成
- 可选 IDA / Ghidra / browser / x64dbg MCP
- 可选远程 helper
- 中文输出和可复现工作区

## 架构

```text
challenge -> intake/router/autopilot
          -> solver runtime
             |- AI loop (LLM + tools + code execution + reflection)
             |- Binary / web / specialized solvers
             |- MCP hub + local tools + optional remote helpers
             |- workspace artifacts
             `- solved export
```

统一产物:

- `notes.md`
- `state.json`
- `runs.jsonl`
- `solution.py`
- `triage_board.json`
- `task_protocol_summary.json`
- `artifacts/*`

## 推荐工作流

- `run_ctf_session` 作为主会话入口
- `continue_ctf_session` 用于轮询 / 续做
- `auto_solve_ctf` 用于一句话直接执行
- `get_ctf_board_summary` 用于查看进度摘要

## Fastest 模式

触发关键词:

- `fastest`
- `最快`
- `搏一把`
- `speedrun`

命中后:

- 尽量走最短可复现链路
- 不主动绕去长链知识检索
- 不强制先跑 preview / template 往返
- 输出更紧凑
- 对 `pwn` 优先 remote-first

## 短格式输入

```text
Type: web|misc|pwn|re|reverse|crypto|forensics|osint|malware
Target:
Files:
- <path-to-attachment>
Hint:
```

## 知识源

- Embedded skills: `ctf_agent/knowledge/embedded_ctf_skills/`
- Optional personal wiki: configured through `rag.wiki_root`

公开仓库保留 embedded skills，但不附带个人 wiki / writeup。

## LLM 配置

Supports any OpenAI-compatible endpoint:

```json
"llm": {
  "enabled": true,
  "api_key": "${CTF_AGENT_LLM_API_KEY}",
  "base_url": "${CTF_AGENT_LLM_BASE_URL}",
  "model": "${CTF_AGENT_LLM_MODEL}"
}
```

## 关键原则

- 顶层编辑器优先只接 `ctf-agent-mcp`，不要把所有嵌套 MCP 直接暴露出去。
- 结果应落在工作区，而不是只停留在聊天里。
- 持续复用 `triage_board.json`、`notes.md`、`solution.py`、`task_protocol_summary.json`。
- 持续推进直到拿到 flag 或明确记录 blocker。
- 默认输出语言是中文，除非操作者另行指定。

## Hard Pwn

- 运行时可以先给出 `pwn_family`，再给当前 blocker 或 next step。
- 已支持的 family 包括 `seccomp-orw`、`sandbox-orw`、`srop`、`ret2dlresolve`、`heap-*`、`fsop`、`shellcode-mmap`。
- 在 fastest 模式下，hard-pwn lane 会保持短而有界。

## Third-Party Attribution

This repository embeds the `ctf-skills` knowledge pack inside `ctf_agent/knowledge/embedded_ctf_skills`.

- Source: [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills)
- Upstream license: [MIT](https://raw.githubusercontent.com/ljagiello/ctf-skills/main/LICENSE)
- Local notice: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

The upstream `LICENSE` and `README.md` are preserved inside the embedded directory.

## 安全边界

- Only for authorized CTF, lab, and private research targets.
- Do not commit private `local_config.json`, remote credentials, personal wiki data, or sidecar environments.
- Remote helpers and nested MCP servers are optional operator-managed integrations.
