from abc import ABC, abstractmethod
from pathlib import Path

from ctf_agent.knowledge import SkillResolver
from ctf_agent.core.solver_session import (
    clear_solver_session,
    approval_status_for_session,
    load_solver_context,
    load_solver_session,
    restore_solver_state,
    save_solver_context,
    save_solver_session,
)


class BaseSolver(ABC):
    SOLVER_NAME = "base"

    def _resolver(self):
        resolver = getattr(self, "_skill_resolver_instance", None)
        if resolver is None:
            resolver = SkillResolver()
            self._skill_resolver_instance = resolver
        return resolver

    def _challenge_speed_mode(self, challenge):
        metadata = dict(getattr(challenge, "metadata", {}) or {})
        autopilot = dict(metadata.get("autopilot_plan") or {})
        return str(metadata.get("speed_mode") or autopilot.get("speed_mode") or "standard").strip().lower() or "standard"

    def _challenge_task_text(self, challenge):
        parts = [
            str(getattr(challenge, "title", "") or ""),
            str(getattr(challenge, "category", "") or ""),
            str(getattr(challenge, "description", "") or ""),
        ]
        return "\n".join([item for item in parts if item]).strip()

    def _resolve_skill_resolution(self, challenge, speed_mode=None):
        metadata = getattr(challenge, "metadata", None)
        if not isinstance(metadata, dict):
            metadata = dict(metadata or {})
            challenge.metadata = metadata

        normalized_speed = str(speed_mode or self._challenge_speed_mode(challenge)).strip().lower() or "standard"
        cached = dict(metadata.get("skill_resolution") or {})
        cached_speed = str(((cached.get("runtime") or {}).get("speed_mode") or "")).strip().lower()
        resolver = self._resolver()
        if not cached or cached_speed != normalized_speed:
            cached = resolver.resolve(
                task_text=self._challenge_task_text(challenge),
                target=str(getattr(challenge, "target", "") or ""),
                attachments=list(getattr(challenge, "attachments", []) or []),
                explicit_category=str(getattr(challenge, "category", "") or ""),
                speed_mode=normalized_speed,
            )
            metadata["skill_resolution"] = dict(cached)
        metadata["knowledge_selection"] = resolver.to_legacy_selection(cached)
        return cached

    def _resolve_solver_metadata(self, challenge, speed_mode=None):
        metadata = getattr(challenge, "metadata", None)
        if not isinstance(metadata, dict):
            metadata = dict(metadata or {})
            challenge.metadata = metadata

        normalized_speed = str(speed_mode or self._challenge_speed_mode(challenge)).strip().lower() or "standard"
        resolution = self._resolve_skill_resolution(challenge, speed_mode=normalized_speed)
        category = dict(resolution.get("category") or {})
        skillpack = dict(resolution.get("skillpack") or {})
        knowledge = dict(resolution.get("knowledge") or {})
        runtime = dict(resolution.get("runtime") or {})
        recommendations = dict(resolution.get("recommendations") or {})
        autopilot = dict(metadata.get("autopilot_plan") or {})
        autopilot_knowledge = dict(autopilot.get("knowledge") or {})

        merged_knowledge = {
            "selected_skill_category": autopilot_knowledge.get("selected_skill_category", category.get("selected_skill_category", getattr(challenge, "category", ""))),
            "pack_name": autopilot_knowledge.get("pack_name", knowledge.get("pack_name", skillpack.get("label", ""))),
            "knowledge_pack": dict(autopilot_knowledge.get("knowledge_pack", skillpack.get("knowledge_pack", {}))),
            "knowledge_topics": list(autopilot_knowledge.get("knowledge_topics", knowledge.get("knowledge_topics", []))),
            "top_tactics": list(autopilot_knowledge.get("top_tactics", knowledge.get("top_tactics", []))),
            "reference_docs": list(autopilot_knowledge.get("reference_docs", knowledge.get("reference_docs", []))),
            "tactics_consumed": list(autopilot_knowledge.get("tactics_consumed", knowledge.get("top_tactics", [])))[:3],
            "category_confidence": autopilot_knowledge.get("category_confidence", category.get("category_confidence", 0.0)),
            "category_evidence": list(autopilot_knowledge.get("category_evidence", category.get("category_evidence", []))),
            "explicit_category": autopilot_knowledge.get("explicit_category", category.get("explicit_category", "")),
            "auto_category": autopilot_knowledge.get("auto_category", category.get("auto_category", "")),
            "category_consistent": bool(autopilot_knowledge.get("category_consistent", category.get("category_consistent", False))),
            "speed_mode": normalized_speed,
            "retrieval_enabled": bool(runtime.get("retrieval_enabled", True)),
            "retrieval_reason": str(runtime.get("retrieval_reason", "")),
            "resolution_summary": str(resolution.get("summary", "")),
        }

        autopilot_knowledge = dict(autopilot_knowledge)
        for key, value in merged_knowledge.items():
            current = autopilot_knowledge.get(key)
            if current in (None, "", [], {}):
                if isinstance(value, dict):
                    autopilot_knowledge[key] = dict(value)
                elif isinstance(value, list):
                    autopilot_knowledge[key] = list(value)
                else:
                    autopilot_knowledge[key] = value

        autopilot["knowledge"] = autopilot_knowledge
        autopilot.setdefault("selected_skill_category", merged_knowledge["selected_skill_category"])
        autopilot.setdefault("category_confidence", merged_knowledge["category_confidence"])
        autopilot.setdefault("category_evidence", list(merged_knowledge["category_evidence"]))
        autopilot.setdefault("top_tactics", list(merged_knowledge["top_tactics"]))
        autopilot.setdefault("reference_docs", list(merged_knowledge["reference_docs"]))
        metadata["autopilot_plan"] = autopilot
        metadata["knowledge_selection"] = self._resolver().to_legacy_selection(resolution)

        return {
            "speed_mode": normalized_speed,
            "skill_resolution": dict(resolution),
            "category": category,
            "skillpack": skillpack,
            "knowledge": merged_knowledge,
            "runtime": runtime,
            "recommendations": {
                "recommended_tools": list(recommendations.get("recommended_tools", [])),
                "recommended_mcp": list(recommendations.get("recommended_mcp", [])),
                "preferred_remote_templates": list(recommendations.get("preferred_remote_templates", [])),
            },
            "autopilot": autopilot,
        }

    def solver_name(self):
        return str(getattr(self, "SOLVER_NAME", "") or self.__class__.__name__.replace("Solver", "").lower())

    def _pause_for_approval(
        self,
        challenge,
        workspace,
        state,
        checkpoint="",
        pending_approval=None,
        pending_action=None,
        context=None,
        blocked_reason="",
    ):
        payload = dict(pending_approval or {})
        action_payload = dict(pending_action or payload.get("result_payload") or {})
        message = str(blocked_reason or payload.get("message") or "approval required")
        state.phase = "needs_approval"
        state.blocked_reason = message
        solver_context = dict(context or {})
        solver_context.setdefault("state", state.to_dict())
        solver_context.setdefault("checkpoint", str(checkpoint or ""))
        context_path = save_solver_context(workspace, solver_context)
        save_solver_session(
            workspace,
            challenge,
            state,
            solver=self.solver_name(),
            checkpoint=checkpoint,
            solver_context_path_value=context_path,
            pending_approval=payload,
            pending_action=action_payload,
        )
        return state

    def _maybe_pause_on_approval(
        self,
        challenge,
        workspace,
        memory,
        checkpoint="",
        result=None,
        context=None,
        pending_action=None,
        blocked_reason="",
    ):
        payload = dict(result or {})
        if str(payload.get("status", "") or "") != "needs_approval":
            return False
        action_payload = dict(pending_action or {})
        if not action_payload:
            action_payload = {
                "checkpoint": str(checkpoint or ""),
                "result_payload": dict(payload),
            }
        self._pause_for_approval(
            challenge,
            workspace,
            memory.state,
            checkpoint=checkpoint,
            pending_approval=payload,
            pending_action=action_payload,
            context=context,
            blocked_reason=blocked_reason or str(payload.get("message", "") or "approval required"),
        )
        return True

    def _solver_session(self, workspace):
        session = load_solver_session(workspace)
        if not session:
            return None
        solver_name = str(session.get("solver", "") or "")
        if solver_name and solver_name != self.solver_name():
            return None
        return session

    def _restore_solver_resume_context(self, workspace):
        session = self._solver_session(workspace)
        if not session:
            return None, None, {}
        state = restore_solver_state(dict(session.get("state") or {}))
        context = load_solver_context(workspace, session.get("solver_context_path"))
        return session, state, context

    def continue_solve(self, challenge, workspace):
        workspace = Path(workspace)
        session = self._solver_session(workspace)
        if not session:
            return self.solve(challenge, workspace)
        approval_status = approval_status_for_session(workspace, session)
        state = restore_solver_state(dict(session.get("state") or {}))
        if approval_status not in {"approved", "consumed", "missing"}:
            state.phase = "needs_approval"
            state.blocked_reason = str(dict(session.get("pending_approval") or {}).get("message") or "approval required")
            return state
        return self._continue_from_checkpoint(challenge, workspace, session, state, load_solver_context(workspace, session.get("solver_context_path")))

    def _continue_from_checkpoint(self, challenge, workspace, session, state, context):
        return self.solve(challenge, workspace)

    def _clear_solver_session(self, workspace):
        clear_solver_session(workspace)

    def _bind_runtime_context(self, challenge, workspace, memory=None, context=None):
        self._runtime_challenge = challenge
        self._runtime_workspace = Path(workspace)
        self._runtime_memory = memory
        self._runtime_context = context or {}

    def _runtime_snapshot(self, **extra):
        context = getattr(self, "_runtime_context", {}) or {}
        payload = {"context": dict(context)}
        payload.update(dict(extra or {}))
        return payload

    @abstractmethod
    def solve(self, challenge, workspace):
        raise NotImplementedError
