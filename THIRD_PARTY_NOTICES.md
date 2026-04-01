# Third-Party Notices

## Embedded `ctf-skills`

This repository embeds the upstream `ctf-skills` knowledge pack under:

- `ctf_agent/knowledge/embedded_ctf_skills`

Upstream project:

- Repository: https://github.com/ljagiello/ctf-skills
- Author: Lukasz Jagiello
- License: MIT

What is preserved in this repository:

- Upstream `LICENSE`
- Upstream `README.md`
- The embedded markdown knowledge files used by the agent runtime

Local adaptation notes:

- The knowledge pack is vendored as an embedded runtime asset so the public edition can work without an extra install step.
- Repository-specific routing, runtime policy, solver selection, and MCP integration live outside the embedded upstream content.
