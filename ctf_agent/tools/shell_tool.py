import subprocess


class ShellTool(object):
    def __init__(self, policy=None, workspace=None):
        self.policy = policy
        self.workspace = str(workspace) if workspace else ""

    def configure_policy(self, policy=None, workspace=None):
        if policy is not None:
            self.policy = policy
        if workspace is not None:
            self.workspace = str(workspace)
        return self

    def run(self, command, cwd=None, timeout=15, env=None, stdin_text=None):
        runtime_cwd = cwd or self.workspace or None
        runtime_timeout = timeout
        if self.policy:
            try:
                shell_gate = self.policy.evaluate_shell(command, cwd=runtime_cwd, timeout=timeout)
                if getattr(shell_gate, "decision", "") == "deny":
                    error = {"ok": False, "reason": shell_gate.reason, "details": dict(shell_gate.details or {})}
                    return {
                        "returncode": -1,
                        "stdout": "",
                        "stderr": "[POLICY] {0}".format(error.get("reason", "")),
                        "status": "blocked",
                        "error": error,
                    }
                if getattr(shell_gate, "decision", "") == "ask":
                    details = dict(getattr(shell_gate, "details", {}) or {})
                    return {
                        "returncode": -1,
                        "stdout": "",
                        "stderr": "[APPROVAL] {0}".format(getattr(shell_gate, "reason", "approval required")),
                        "status": "needs_approval",
                        "approval": shell_gate.to_dict() if hasattr(shell_gate, "to_dict") else details,
                        "request_id": getattr(shell_gate, "request_id", ""),
                        "error": {
                            "ok": False,
                            "reason": getattr(shell_gate, "reason", "approval required"),
                            "details": details,
                        },
                    }
                runtime_cwd = (getattr(shell_gate, "details", {}) or {}).get("cwd") or runtime_cwd
                runtime_timeout = int((getattr(shell_gate, "details", {}) or {}).get("timeout", timeout))
            except Exception as exc:
                error = exc.to_dict() if hasattr(exc, "to_dict") else {"ok": False, "reason": str(exc)}
                return {
                    "returncode": -1,
                    "stdout": "",
                    "stderr": "[POLICY] {0}".format(error.get("reason", str(exc))),
                    "status": "blocked",
                    "error": error,
                }
        use_shell = isinstance(command, str)
        completed = subprocess.run(
            command,
            cwd=runtime_cwd,
            timeout=runtime_timeout,
            shell=use_shell,
            capture_output=True,
            text=True,
            errors="replace",
            env=env,
            input=stdin_text,
        )
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "status": "ok" if completed.returncode == 0 else "error",
        }
