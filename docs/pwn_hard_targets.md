# Pwn Hard Targets

## Goal

Wave-4 extends pwn from `ret2win / ret2libc / fmt / basic ROP` into harder exploit families while keeping the existing Ubuntu helper mainline.

## Families

- `heap-uaf`
  - Entry: `uaf`, `use after free`, `malloc/free/edit/show`, dangling chunk reuse
  - Automation: scaffold-first; when menu primitive and leak/write target clues are present, can raise to `stage1-ready`
  - Typical blocker: missing stable heap leak or menu primitive names
- `heap-double-free`
  - Entry: `double free`, `free(): double free`, repeated free on same chunk
  - Automation: scaffold-first; can prefill double-free review and write-target hints
  - Typical blocker: no usable tcache/fastbin poisoning target
- `heap-tcache-poison`
  - Entry: `tcache`, `__free_hook`, `__malloc_hook`, poisoning clues
  - Automation: scaffold-first; can prefill menu helpers, leak targets, and hook candidates
  - Typical blocker: no leak or no hook/target write primitive
- `heap-unsorted-bin`
  - Entry: `unsorted bin`, `main_arena`, bk/fd leak hints
  - Automation: scaffold-first; can prefill `main_arena`-style leak direction
  - Typical blocker: glibc version mismatch or missing leak
- `seccomp-orw`
  - Entry: `seccomp`, `prctl`, `open/read/write`, ORW-only sandbox
  - Automation: stage-1/stage-2 pwntools stub
  - Typical blocker: no syscall surface or no writable memory/gadgets
- `sandbox-orw`
  - Entry: `sandbox`, `openat`, `read`, `write`, filtered shell path
  - Automation: stage-1/stage-2 pwntools stub
  - Typical blocker: sandbox details still unclear
- `srop`
  - Entry: `sigreturn`, `rt_sigreturn`, `syscall; ret`, `setcontext`
  - Automation: stage-1/stage-2 pwntools stub
  - Typical blocker: missing `syscall; ret` or register-control chain
- `fsop`
  - Entry: `_IO_2_1_stdout_`, `_IO_FILE`, `_IO_list_all`, vtable clues
  - Automation: scaffold-first; when FILE target and trigger path are both visible, can raise to `stage1-ready`
  - Typical blocker: no FILE target, no libc context, no flush path
- `shellcode-mmap`
  - Entry: `mmap`, `mprotect`, RWX, shellcode loader surface
  - Automation: stage-1/stage-2 pwntools stub
  - Typical blocker: missing RWX pivot or bad shellcode write path
- `ret2dlresolve`
  - Entry: `ret2dlresolve`, `_dl_runtime_resolve`, `link_map`, partial RELRO
  - Automation: stage-1/stage-2 pwntools stub
  - Typical blocker: Full RELRO or no writable relocation staging area

## Stage Status

- `classified-only`: only family and evidence are stable
- `skeleton-generated`: exploit skeleton exists, but still needs manual fill-in
- `stage1-ready`: leak or first-stage plan exists
- `stage2-synthesized`: stage-2 pwntools stub exists
- `verified-transcript`: bounded lane produced a stable transcript
- `verified-flag`: solver already confirmed the flag

## Notes

- `fastest` only keeps the shortest one or two hard lanes.
- Hard lanes stay bounded. They are not blind fuzzers.
- If a lane gives a better transcript or a validated flag, later lanes stop immediately.
- `heap / fsop` 当前会额外输出菜单 primitive、泄漏/写入目标、触发路径等半自动提示，方便继续手补 exploit。
