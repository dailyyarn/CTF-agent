# Fastest Mode

## Keywords

- `fastest`
- `最快`
- `搏一把`
- `speedrun`

## Behavior

- Set `speed_mode=fastest`
- Skip knowledge detours by default
- Skip redundant preview hops when possible
- Prefer the shortest runnable path
- Keep the final answer compact

## Category notes

- `web`: shortest request chain first
- `misc` / `crypto` / `reverse`: prefer bounded scripts and direct probes
- `pwn`: stay remote-first when a helper is configured
- hard pwn: keep one or two bounded lanes only

## Solved format

- first line: `flag: ...`
- second line: `wp_package_path: ...`
- then a short conclusion
