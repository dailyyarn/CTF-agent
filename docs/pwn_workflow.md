# Pwn Workflow

Recommended public workflow:

1. classify the target
2. probe local protections and symbols
3. select a configured remote helper when needed
4. run parity / build probes
5. choose the shortest exploit or build lane
6. write artifacts back to the workspace

When source files are present, the solver can insert a remote build lane before the normal binary path.
