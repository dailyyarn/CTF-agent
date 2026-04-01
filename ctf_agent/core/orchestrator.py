from pathlib import Path

from ctf_agent.core.execution_policy import ExecutionPolicy
from ctf_agent.core.solver_session import approval_status_for_session, load_solver_session
from ctf_agent.core.solved_export import export_solved_workspace


class Orchestrator(object):
    def __init__(
        self,
        adapter,
        router,
        solvers,
        verifier,
        workspace_manager,
        export_policy=None,
        plugin_registry=None,
        approval_manager=None,
        approval_policy=None,
    ):
        self.adapter = adapter
        self.router = router
        self.solvers = solvers
        self.verifier = verifier
        self.workspace_manager = workspace_manager
        self.export_policy = dict(export_policy or {})
        self.plugin_registry = plugin_registry
        self.approval_manager = approval_manager
        self.approval_policy = dict(approval_policy or {})

    def solve_path(self, source_path, auto_submit=False):
        challenge = self.adapter.load_challenge(Path(source_path))
        return self.solve_challenge(challenge, auto_submit=auto_submit)

    def solve_challenge(self, challenge, auto_submit=False, run_id=None, cancel_event=None):
        if cancel_event is not None:
            challenge.metadata["cancel_event"] = cancel_event
        if run_id:
            challenge.metadata["run_id"] = run_id

        workspace = self.workspace_manager.prepare(challenge)
        challenge.metadata["workspace"] = str(workspace)
        if self.plugin_registry:
            self.plugin_registry.persist_workspace_status(workspace)

        staged_attachments = self.adapter.stage_attachments(
            challenge=challenge,
            attachments_dir=Path(workspace) / "attachments",
        )
        challenge.attachments = staged_attachments
        challenge.target = self.adapter.prepare_target(challenge)

        solver_name = self.router.route(challenge)
        solver = self.solvers[solver_name]
        self._configure_solver_runtime(solver, challenge, workspace)
        solver_session = load_solver_session(workspace)
        if solver_session and str(solver_session.get("solver", "") or "") == getattr(solver, "solver_name", lambda: solver_name)():
            approval_status = approval_status_for_session(workspace, solver_session)
            if approval_status in {"approved", "consumed", "missing"}:
                state = solver.continue_solve(challenge, workspace)
            else:
                state = solver.continue_solve(challenge, workspace)
        else:
            state = solver.solve(challenge, workspace)
        self.workspace_manager.save_state(workspace, state)
        self.workspace_manager.write_action_log(workspace, state)

        best_flag = self.verifier.choose_best(state, challenge)
        result = {
            "status": "solved" if best_flag else "unresolved",
            "workspace": str(workspace),
            "solver": solver_name,
            "state_path": str(Path(workspace) / "state.json"),
            "notes_path": str(Path(workspace) / "notes.md"),
            "solution_path": str(Path(workspace) / "solution.py"),
        }
        if state.phase == "needs_approval":
            result["status"] = "needs_approval"

        if best_flag:
            result["flag"] = best_flag.value
            if auto_submit:
                result["submit_result"] = self.adapter.submit_flag(challenge, best_flag.value)
            result.update(export_solved_workspace(challenge, result, policy=self.export_policy))

        return result

    def _configure_solver_runtime(self, solver, challenge, workspace):
        remote_tool = getattr(solver, "remote_tool", None)
        mcp_registry = getattr(solver, "mcp_registry", None)
        policy = ExecutionPolicy.build_default(
            workspace=workspace,
            attachments=getattr(challenge, "attachments", []),
            category=getattr(challenge, "category", ""),
            target=getattr(challenge, "target", ""),
            remote_hosts=remote_tool.list_hosts() if remote_tool else [],
            mcp_servers=[
                item.get("name")
                for item in (mcp_registry.enabled_servers() if mcp_registry else [])
                if item.get("name")
            ],
            approval_policy=self.approval_policy,
            approval_manager=self.approval_manager.configure(
                workspace=str(workspace),
                run_id=str(getattr(challenge, "metadata", {}).get("run_id", "") or ""),
            ) if self.approval_manager else None,
            run_id=str(getattr(challenge, "metadata", {}).get("run_id", "") or ""),
        )
        if self.plugin_registry:
            policy = policy.apply_overlay(self.plugin_registry.policy_overlay())
        file_tool = getattr(solver, "file_tool", None)
        shell_tool = getattr(solver, "shell_tool", None)
        if file_tool and hasattr(file_tool, "configure_policy"):
            file_tool.configure_policy(policy, workspace=str(workspace))
        if shell_tool and hasattr(shell_tool, "configure_policy"):
            shell_tool.configure_policy(policy, workspace=str(workspace))
        if remote_tool and hasattr(remote_tool, "configure_policy"):
            remote_tool.configure_policy(
                policy,
                category=getattr(challenge, "category", ""),
                target=getattr(challenge, "target", ""),
                background=False,
            )
            if hasattr(remote_tool, "configure_plugins"):
                remote_tool.configure_plugins(self.plugin_registry)
        if mcp_registry and hasattr(mcp_registry, "configure_runtime"):
            mcp_registry.configure_runtime(workspace=str(workspace), policy=policy)
