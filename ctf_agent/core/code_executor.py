"""Sandboxed Python execution for LLM-generated solve scripts.

Runs code in a subprocess with timeout, captures stdout/stderr, and
optionally scans output for flags.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_TIMEOUT = 30
_MAX_OUTPUT_CHARS = 80000


class ExecutionResult:
    """Result of a sandboxed code execution."""

    __slots__ = ("stdout", "stderr", "exit_code", "timed_out", "artifact_path", "elapsed_ms")

    def __init__(self, stdout="", stderr="", exit_code=-1, timed_out=False, artifact_path=None, elapsed_ms=0):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.artifact_path = artifact_path
        self.elapsed_ms = elapsed_ms

    @property
    def success(self):
        return self.exit_code == 0 and not self.timed_out

    @property
    def output(self):
        parts = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append("[stderr] " + self.stderr)
        if self.timed_out:
            parts.append("[TIMEOUT after {0}ms]".format(self.elapsed_ms))
        return "\n".join(parts) if parts else "(no output)"

    def to_dict(self):
        return {
            "stdout": self.stdout[:_MAX_OUTPUT_CHARS],
            "stderr": self.stderr[:_MAX_OUTPUT_CHARS // 4],
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "success": self.success,
            "elapsed_ms": self.elapsed_ms,
            "artifact_path": str(self.artifact_path) if self.artifact_path else None,
        }


class CodeExecutor:
    """
    Execute LLM-generated Python in a subprocess.

    Security model:
    - Runs in a child process with a wall-clock timeout
    - Working directory set to ``workspace/artifacts/``
    - Output size capped
    - Saves every script to ``solution_generated.py`` for reproducibility
    """

    def __init__(self, python_bin=None, default_timeout=None, policy=None):
        self.python_bin = python_bin or sys.executable
        self.default_timeout = default_timeout or _DEFAULT_TIMEOUT
        self.policy = policy

    def configure_policy(self, policy=None):
        if policy is not None:
            self.policy = policy
        return self

    def execute(self, code, workspace=None, timeout=None, description="", env_extra=None):
        """
        Execute *code* and return an ``ExecutionResult``.
        """
        timeout = timeout or self.default_timeout
        if self.policy:
            timeout = self.policy.clamp_shell_timeout(timeout)

        artifacts_dir = None
        if workspace:
            artifacts_dir = Path(workspace) / "artifacts"
            if self.policy:
                try:
                    self.policy.validate_file_write(artifacts_dir / "_solver_script.py")
                    self.policy.validate_file_write(artifacts_dir / "solution_generated.py")
                except Exception as exc:
                    return ExecutionResult(
                        stderr="Execution blocked: {0}".format(getattr(exc, "reason", str(exc))),
                        exit_code=-1,
                    )
            artifacts_dir.mkdir(parents=True, exist_ok=True)
        elif self.policy and self.policy.allow_workspace_writes_only:
            return ExecutionResult(
                stderr="Execution blocked: workspace is required by policy",
                exit_code=-1,
            )

        work_dir = str(artifacts_dir) if artifacts_dir else tempfile.mkdtemp(prefix="ctf_sandbox_")

        script_path = os.path.join(work_dir, "_solver_script.py")
        with open(script_path, "w", encoding="utf-8") as fh:
            fh.write(code)

        if artifacts_dir:
            saved = artifacts_dir / "solution_generated.py"
            with open(str(saved), "w", encoding="utf-8") as fh:
                if description:
                    fh.write("# {0}\n".format(description))
                fh.write(code)

        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        if env_extra:
            env.update(env_extra)

        start = time.time()
        timed_out = False
        try:
            proc = subprocess.Popen(
                [self.python_bin, "-u", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=work_dir,
                env=env,
            )
            stdout_b, stderr_b = proc.communicate(timeout=timeout)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_b, stderr_b = proc.communicate()
            exit_code = -1
            timed_out = True
        except Exception as exc:
            return ExecutionResult(
                stderr="Execution failed: {0}".format(exc),
                exit_code=-1,
                elapsed_ms=int((time.time() - start) * 1000),
            )

        elapsed_ms = int((time.time() - start) * 1000)
        stdout = stdout_b.decode("utf-8", errors="replace")[:_MAX_OUTPUT_CHARS]
        stderr = stderr_b.decode("utf-8", errors="replace")[:_MAX_OUTPUT_CHARS // 4]

        try:
            os.remove(script_path)
        except OSError:
            pass

        return ExecutionResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=timed_out,
            artifact_path=str(artifacts_dir) if artifacts_dir else work_dir,
            elapsed_ms=elapsed_ms,
        )

    def execute_and_scan(self, code, workspace, verifier, timeout=None, description="", source_tag="ai-solver"):
        """Execute code and scan output for flags."""
        result = self.execute(code, workspace=workspace, timeout=timeout, description=description)
        flags = []
        if verifier:
            for text in [result.stdout, result.stderr]:
                for flag in verifier.discover_from_text(text):
                    flags.append({"value": flag, "source": source_tag, "confidence": 0.88})
        return result, flags
