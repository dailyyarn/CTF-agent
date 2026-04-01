"""Challenge router: decides which solver handles a given challenge.

Phase 1: Hybrid routing — heuristic scoring + optional LLM classification.
When an LLM client is available and the heuristic score is ambiguous,
the router asks the LLM for a second opinion and fuses both signals.
"""

import json
import logging
from typing import Optional

from ctf_agent.knowledge import SkillResolver

logger = logging.getLogger(__name__)

_VALID_SOLVERS = {"web", "binary", "triage", "crypto", "forensics", "osint", "malware", "misc"}
_SOLVER_ALIASES = {
    "pwn": "binary",
    "re": "binary",
    "reverse": "binary",
}

_LLM_CLASSIFY_PROMPT = """\
You are a CTF challenge classifier. Given the challenge information below,
output a JSON object: {"solver": "<solver>", "confidence": <0.0-1.0>, "reasoning": "<brief>"}

Valid solver values: web, binary, crypto, forensics, osint, malware, misc

Challenge:
- title: {title}
- category hint: {category}
- description (truncated): {description}
- target: {target}
- attachment names: {attachments}
"""


class HeuristicRouter(object):
    """
    Hybrid router: heuristic rules + optional LLM augmentation.

    If ``llm`` is None the router falls back to pure heuristic mode
    (identical to the pre-AI-solver behaviour).
    """

    def __init__(self, llm=None, llm_confidence_threshold=0.7):
        self.llm = llm
        self.llm_threshold = llm_confidence_threshold
        self.skill_resolver = SkillResolver()

    def _challenge_speed_mode(self, challenge):
        metadata = dict(getattr(challenge, "metadata", {}) or {})
        autopilot = dict(metadata.get("autopilot_plan") or {})
        return str(metadata.get("speed_mode") or autopilot.get("speed_mode") or "standard").strip().lower() or "standard"

    def _challenge_task_text(self, challenge):
        return "\n".join(
            [
                item
                for item in [
                    str(getattr(challenge, "title", "") or ""),
                    str(getattr(challenge, "category", "") or ""),
                    str(getattr(challenge, "description", "") or ""),
                ]
                if item
            ]
        ).strip()

    def _resolve_selection(self, challenge):
        metadata = getattr(challenge, "metadata", None)
        if not isinstance(metadata, dict):
            metadata = dict(metadata or {})
            challenge.metadata = metadata

        speed_mode = self._challenge_speed_mode(challenge)
        cached = dict(metadata.get("skill_resolution") or {})
        cached_speed = str(((cached.get("runtime") or {}).get("speed_mode") or "")).strip().lower()
        if not cached or cached_speed != speed_mode:
            cached = self.skill_resolver.resolve(
                task_text=self._challenge_task_text(challenge),
                target=str(getattr(challenge, "target", "") or ""),
                attachments=list(getattr(challenge, "attachments", []) or []),
                explicit_category=str(getattr(challenge, "category", "") or ""),
                speed_mode=speed_mode,
            )
            metadata["skill_resolution"] = dict(cached)

        selection = self.skill_resolver.to_legacy_selection(cached)
        metadata["knowledge_selection"] = dict(selection)
        return cached, selection

    def route(self, challenge):
        # --- Heuristic path (always runs) ---
        resolution, selection = self._resolve_selection(challenge)
        heuristic_solver = str((resolution.get("category") or {}).get("solver") or selection.get("solver") or "").strip().lower()
        heuristic_solver = _SOLVER_ALIASES.get(heuristic_solver, heuristic_solver)

        if heuristic_solver in _VALID_SOLVERS:
            heuristic_confidence = float(
                (resolution.get("category") or {}).get("category_confidence", selection.get("confidence", 0.8))
            )
        else:
            heuristic_solver = "triage"
            heuristic_confidence = 0.3

        # --- LLM path (only when available and heuristic is uncertain) ---
        if self.llm and self.llm.is_configured() and heuristic_confidence < self.llm_threshold:
            llm_solver, llm_confidence = self._llm_classify(challenge)
            if llm_solver and llm_confidence > heuristic_confidence:
                logger.info(
                    "Router: LLM override %s (%.0f%%) > heuristic %s (%.0f%%)",
                    llm_solver, llm_confidence * 100,
                    heuristic_solver, heuristic_confidence * 100,
                )
                return llm_solver

        return heuristic_solver

    def route_to_agent_loop(self, challenge):
        """Return True if this challenge should be routed to the AI agent loop instead of a rule-based solver."""
        solver = self.route(challenge)
        ai_policy = getattr(challenge, "metadata", {}).get("ai_solver_policy", "auto")

        if ai_policy == "always":
            return True
        if ai_policy == "never":
            return False

        # "auto": use agent loop for categories where rule-based solvers are weakest
        if solver in ("misc", "triage"):
            return True
        if challenge.category and challenge.category.lower() in ("misc",):
            return True
        return False

    def _llm_classify(self, challenge):
        prompt = _LLM_CLASSIFY_PROMPT.format(
            title=challenge.title or "(none)",
            category=challenge.category or "(none)",
            description=(challenge.description or "")[:600],
            target=challenge.target or "(none)",
            attachments=", ".join(str(a) for a in (challenge.attachments or [])[:6]) or "(none)",
        )
        try:
            result = self.llm.structured_output(
                [{"role": "user", "content": prompt}],
                schema_hint='{"solver": "string", "confidence": number, "reasoning": "string"}',
                temperature=0.1,
            )
            solver = str(result.get("solver", "")).strip().lower()
            solver = _SOLVER_ALIASES.get(solver, solver)
            confidence = float(result.get("confidence", 0.0))
            if solver in _VALID_SOLVERS:
                return solver, confidence
        except Exception as exc:
            logger.warning("LLM classify failed: %s", exc)
        return None, 0.0
