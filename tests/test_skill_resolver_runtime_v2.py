import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ctf_agent.core.agent_loop import AgentLoop, ToolRegistry
from ctf_agent.core.autopilot import build_autopilot_plan
from ctf_agent.core.config import AgentConfig
from ctf_agent.core.intake import IntakeService
from ctf_agent.core.models import Challenge, ChallengeState, SubAgentRecord
from ctf_agent.core.router import HeuristicRouter
from ctf_agent.core.runtime import run_payload
from ctf_agent.core.workspace import WorkspaceManager
from ctf_agent.knowledge import SkillResolver, build_knowledge_selection
from ctf_agent.knowledge.skillpacks import get_skillpack


class _DummyLLM(object):
    def __init__(self):
        self.stats = {"total_tokens": 0}

    def quick(self, prompt, system_prompt=None, temperature=None):
        return ""


class _FakeKnowledge(object):
    def __init__(self):
        self.calls = 0

    def is_loaded(self):
        return True

    def query(self, query, top_k=4, category_hint=None, source_filter=None):
        self.calls += 1
        return [{"source_type": "skills", "heading": "demo", "text": "demo"}]


class _SpyResolver(object):
    def __init__(self, resolution):
        self.resolution = dict(resolution or {})
        self.calls = 0

    def resolve(self, task_text="", target="", attachments=None, explicit_category=None, speed_mode="standard"):
        self.calls += 1
        return dict(self.resolution)

    def to_legacy_selection(self, resolution):
        return SkillResolver.to_legacy_selection(resolution)


class _FakeAdapter(object):
    def stage_attachments(self, challenge, attachments_dir):
        return list(challenge.attachments or [])

    def prepare_target(self, challenge):
        return challenge.target


class _FakeOrchestrator(object):
    def __init__(self):
        self.adapter = _FakeAdapter()
        self.challenge = None

    def solve_challenge(self, challenge, auto_submit=False, run_id=None, cancel_event=None):
        self.challenge = challenge
        return {"status": "ok", "solver": "fake"}


class SkillResolverRuntimeV2Tests(unittest.TestCase):
    def test_resolve_prefers_explicit_category_and_fastest_runtime(self):
        resolver = SkillResolver()
        resolution = resolver.resolve(
            task_text="rsa cipher with web login hints",
            target="http://example.com/login",
            attachments=["cipher_rsa.enc"],
            explicit_category="crypto",
            speed_mode="fastest",
        )
        pack = get_skillpack("crypto", speed_mode="fastest")

        self.assertEqual("crypto", resolution["category"]["selected_skill_category"])
        self.assertEqual("web", resolution["category"]["auto_category"])
        self.assertFalse(resolution["category"]["category_consistent"])
        self.assertFalse(resolution["runtime"]["retrieval_enabled"])
        self.assertEqual("fastest mode skipped knowledge retrieval", resolution["runtime"]["retrieval_reason"])
        self.assertEqual(pack["allowed_tools"], resolution["runtime"]["allowed_tools"])
        self.assertEqual(pack["denied_tools"], resolution["runtime"]["denied_tools"])
        self.assertEqual(pack["default_budget"], resolution["runtime"]["default_budget"])

    def test_resolve_attachment_heuristics_match_expected_categories(self):
        resolver = SkillResolver()

        forensics = resolver.resolve(task_text="analyze dump", attachments=["traffic_capture.pcapng"])
        crypto = resolver.resolve(task_text="unknown file", attachments=["cipher_rsa.enc"])
        web = resolver.resolve(task_text="", target="https://example.com/api")

        self.assertEqual("forensics", forensics["category"]["selected_skill_category"])
        self.assertEqual("crypto", crypto["category"]["selected_skill_category"])
        self.assertEqual("web", web["category"]["selected_skill_category"])

    def test_build_knowledge_selection_returns_legacy_view_and_confidence_alias(self):
        resolver = SkillResolver()
        resolution = resolver.resolve(
            task_text="jwt auth bypass",
            target="http://example.com",
            explicit_category="web",
            speed_mode="standard",
        )
        legacy = build_knowledge_selection(
            task_text="jwt auth bypass",
            target="http://example.com",
            explicit_category="web",
        )

        self.assertEqual(legacy["category_confidence"], legacy["confidence"])
        self.assertEqual(resolution["category"]["selected_skill_category"], legacy["selected_skill_category"])
        self.assertEqual(resolution["knowledge"]["pack_name"], legacy["pack_name"])
        self.assertEqual(resolution["runtime"]["allowed_tools"], legacy["allowed_tools"])
        self.assertEqual(resolution["runtime"]["default_budget"], legacy["default_budget"])

    def test_build_autopilot_plan_uses_provided_skill_resolution_without_reclassifying(self):
        config = AgentConfig.from_dict({})
        skill_resolution = SkillResolver().resolve(
            task_text="jwt auth bypass",
            target="http://example.com",
            explicit_category="web",
            speed_mode="standard",
        )

        with patch("ctf_agent.core.autopilot.SkillResolver.resolve", side_effect=AssertionError("unexpected resolve")):
            autopilot = build_autopilot_plan(
                config,
                category="misc",
                target="http://example.com",
                speed_mode="standard",
                skill_resolution=skill_resolution,
            )

        self.assertEqual("web", autopilot["category"])
        self.assertEqual("web", autopilot["skill_resolution"]["category"]["selected_skill_category"])

    def test_intake_normalize_brief_resolves_once_and_persists_views(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            config = AgentConfig.from_dict(
                {
                    "workspace_root": str(workspace),
                    "toolkit_root": str(workspace / "toolkit"),
                    "web_policy": {"auto_use_browser_mcp": False},
                }
            )
            resolution = SkillResolver().resolve(
                task_text="jwt auth bypass",
                target="http://example.com",
                explicit_category="web",
                speed_mode="standard",
            )
            intake = IntakeService(config, workspace)
            intake.skill_resolver = _SpyResolver(resolution)
            intake.select_remote_host = lambda category, target="", preferred=None: {
                "status": "skipped",
                "selected_host": "",
                "reason": "test",
            }
            intake.toolkit_tool.capability_plan = lambda category=None: {}

            normalized = intake.normalize_brief(
                {
                    "task": "Category: web\nTarget: http://example.com\nHint: jwt auth bypass",
                    "speed_mode": "standard",
                }
            )

        self.assertEqual(1, intake.skill_resolver.calls)
        self.assertEqual("web", normalized["category"])
        self.assertEqual("web", normalized["skill_resolution"]["category"]["selected_skill_category"])
        self.assertEqual("web", normalized["knowledge_selection"]["selected_skill_category"])
        self.assertEqual(
            normalized["knowledge_selection"]["selected_skill_category"],
            normalized["autopilot_plan"]["knowledge"]["selected_skill_category"],
        )
        self.assertEqual(
            normalized["skill_resolution"]["summary"],
            normalized["autopilot_plan"]["skill_resolution"]["summary"],
        )

    def test_agent_loop_uses_resolver_tool_pool_and_retrieval_gate(self):
        registry = ToolRegistry()
        registry.register("http_request", lambda args: "ok", "http", {"type": "object", "properties": {}})
        registry.register("run_python", lambda args: "ok", "python", {"type": "object", "properties": {}})
        registry.register("search_knowledge", lambda args: "knowledge", "knowledge", {"type": "object", "properties": {}})
        knowledge = _FakeKnowledge()
        resolution = SkillResolver().resolve(
            task_text="jwt auth bypass",
            target="http://example.com",
            explicit_category="web",
            speed_mode="fastest",
        )
        challenge = Challenge(
            contest_id="demo",
            challenge_id="resolver-agent-loop",
            title="resolver-agent-loop",
            category="web",
            description="resolver test",
            metadata={"speed_mode": "fastest", "skill_resolution": resolution},
        )
        loop = AgentLoop(llm=_DummyLLM(), tools=registry, knowledge_retriever=knowledge)

        selected = loop._select_active_tools(challenge, "fastest", {"skip_knowledge": True})
        skipped = loop._retrieve_initial_knowledge(challenge, speed_mode="fastest", speed_profile={"skip_knowledge": True})

        self.assertEqual(sorted(["http_request"]), sorted(selected.names))
        self.assertIn("fastest mode skipped knowledge retrieval", skipped)
        self.assertEqual(0, knowledge.calls)

    def test_agent_loop_subagent_budget_comes_from_skill_resolution(self):
        with tempfile.TemporaryDirectory() as workspace_dir:
            workspace = Path(workspace_dir)
            registry = ToolRegistry()
            registry.register("run_python", lambda args: "ok", "python", {"type": "object", "properties": {}})
            resolution = SkillResolver().resolve(
                task_text="jwt auth bypass",
                target="http://example.com",
                explicit_category="web",
                speed_mode="standard",
            )
            resolution["runtime"]["default_budget"] = {
                "max_steps": 11,
                "max_tool_calls": 7,
                "max_tokens": 123456,
                "timeout_sec": 44,
            }
            challenge = Challenge(
                contest_id="demo",
                challenge_id="resolver-subagent",
                title="resolver-subagent",
                category="web",
                description="resolver test",
                metadata={"run_id": "resolver-subagent", "skill_resolution": resolution},
            )
            state = ChallengeState(phase="agent-loop")
            loop = AgentLoop(
                llm=_DummyLLM(),
                tools=registry,
                workspace_manager=WorkspaceManager(workspace.parent),
            )
            loop._active_tools = registry
            captured = {}

            def _fake_run_subagent_spec(challenge_arg, workspace_arg, spec):
                captured["spec"] = spec
                record = SubAgentRecord(
                    id=spec.id,
                    status="completed",
                    started_at=0.0,
                    finished_at=0.0,
                    spec=spec,
                    summary={"what_was_tried": "", "what_was_found": "", "what_to_do_next": "", "summary_text": ""},
                    stop_reason="completed",
                    usage={"steps": 0, "tool_calls": 0, "tokens_used": 0, "elapsed_ms": 0},
                    artifact_paths=[],
                )
                return record, {
                    "tool": "subagent:{0}".format(spec.id),
                    "purpose": spec.purpose,
                    "status": record.status,
                    "stop_reason": record.stop_reason,
                    "usage": dict(record.usage),
                    "summary": dict(record.summary),
                    "artifact_paths": [],
                    "result": "ok",
                    "elapsed_ms": 0,
                }

            loop._run_subagent_spec = _fake_run_subagent_spec
            loop._spawn_subagents(
                challenge,
                state,
                workspace,
                [{"mode": "subagent", "purpose": "resolver budget branch", "prompt": "check branch"}],
            )

        self.assertEqual(11, captured["spec"].max_steps)
        self.assertEqual(7, captured["spec"].max_tool_calls)
        self.assertEqual(123456, captured["spec"].max_tokens)
        self.assertEqual(44, captured["spec"].timeout_sec)

    def test_router_still_works_through_legacy_selection_wrapper(self):
        router = HeuristicRouter(llm=None)
        challenge = Challenge(
            contest_id="demo",
            challenge_id="router-web",
            title="router-web",
            category="",
            description="jwt auth bypass on a website",
            target="http://example.com",
        )

        self.assertEqual("web", router.route(challenge))
        self.assertEqual(
            "web",
            challenge.metadata["skill_resolution"]["category"]["selected_skill_category"],
        )
        self.assertEqual(
            challenge.metadata["knowledge_selection"]["selected_skill_category"],
            challenge.metadata["skill_resolution"]["category"]["selected_skill_category"],
        )

    def test_router_reuses_cached_skill_resolution_without_re_resolving(self):
        resolution = SkillResolver().resolve(
            task_text="jwt auth bypass on a website",
            target="http://example.com",
            explicit_category="web",
            speed_mode="standard",
        )
        router = HeuristicRouter(llm=None)
        router.skill_resolver = _SpyResolver(resolution)
        challenge = Challenge(
            contest_id="demo",
            challenge_id="router-cached",
            title="router-cached",
            category="",
            description="jwt auth bypass on a website",
            target="http://example.com",
            metadata={"speed_mode": "standard", "skill_resolution": resolution},
        )

        self.assertEqual("web", router.route(challenge))
        self.assertEqual(0, router.skill_resolver.calls)
        self.assertEqual(
            "web",
            challenge.metadata["knowledge_selection"]["selected_skill_category"],
        )

    def test_run_payload_carries_skill_resolution_into_challenge_metadata(self):
        orchestrator = _FakeOrchestrator()
        service = {
            "orchestrator": orchestrator,
            "workspace_manager": WorkspaceManager(Path(tempfile.gettempdir())),
        }
        skill_resolution = SkillResolver().resolve(
            task_text="jwt auth bypass",
            target="http://example.com",
            explicit_category="web",
            speed_mode="standard",
        )
        arguments = {
            "category": "web",
            "title": "runtime-skill-resolution",
            "description": "runtime propagation test",
            "skill_resolution": skill_resolution,
            "knowledge_selection": SkillResolver.to_legacy_selection(skill_resolution),
            "speed_mode": "standard",
            "use_browser_mcp": False,
        }

        result = run_payload(service, arguments)

        self.assertEqual("ok", result["status"])
        self.assertEqual(
            "web",
            orchestrator.challenge.metadata["skill_resolution"]["category"]["selected_skill_category"],
        )
        self.assertEqual(
            orchestrator.challenge.metadata["knowledge_selection"]["selected_skill_category"],
            orchestrator.challenge.metadata["skill_resolution"]["category"]["selected_skill_category"],
        )


if __name__ == "__main__":
    unittest.main()
