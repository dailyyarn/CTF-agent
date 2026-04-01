import logging
from pathlib import Path

from ctf_agent.adapters.manual import ManualJsonAdapter
from ctf_agent.core.config import load_agent_config
from ctf_agent.core.approval import ApprovalManager
from ctf_agent.core.models import Challenge
from ctf_agent.core.orchestrator import Orchestrator
from ctf_agent.core.plugin_registry import PluginRegistry
from ctf_agent.core.profiles import get_profile
from ctf_agent.core.router import HeuristicRouter
from ctf_agent.core.run_manager import RunManager
from ctf_agent.core.solved_export import export_solved_workspace
from ctf_agent.core.verifier import FlagVerifier
from ctf_agent.core.workspace import WorkspaceManager
from ctf_agent.solvers.binary import BinarySolver
from ctf_agent.solvers.specialized import (
    CryptoSolver,
    ForensicsSolver,
    MalwareSolver,
    MiscSolver,
    OsintSolver,
)
from ctf_agent.solvers.triage import TriageSolver
from ctf_agent.solvers.web import WebSolver
from ctf_agent.tools.file_tool import FileTool
from ctf_agent.tools.http_tool import HttpTool
from ctf_agent.tools.mcp_runtime import MCPRuntimeRegistry
from ctf_agent.tools.oob_tool import OOBTool
from ctf_agent.tools.remote_tool import RemoteTool
from ctf_agent.tools.shell_tool import ShellTool
from ctf_agent.tools.toolkit_tool import ToolkitTool

logger = logging.getLogger(__name__)

RUN_MANAGER = RunManager()


def _normalize_runtime_path(value=None, default=None):
    raw = Path(value) if value is not None else Path(default) if default is not None else Path.cwd()
    raw = raw.expanduser()
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    return raw.absolute()


def _build_llm_client(config):
    """Build an LLMClient from config, or return None if unconfigured."""
    llm_cfg = config.llm
    if not llm_cfg or not llm_cfg.get("enabled", True):
        return None
    try:
        from ctf_agent.core.llm import LLMClient
        client = LLMClient(
            api_key=llm_cfg.get("api_key"),
            base_url=llm_cfg.get("base_url"),
            model=llm_cfg.get("model"),
            temperature=llm_cfg.get("temperature"),
            max_tokens=llm_cfg.get("max_tokens"),
            timeout=llm_cfg.get("timeout"),
        )
        if client.is_configured():
            logger.info("LLM client configured: model=%s endpoint=%s", client.model, client.base_url)
            return client
        logger.info("LLM client not configured (no API key)")
    except Exception as exc:
        logger.warning("Failed to build LLM client: %s", exc)
    return None


def _build_knowledge_retriever(config, plugin_registry=None):
    """Build the dual-source knowledge retriever from config."""
    rag_cfg = config.rag
    if not rag_cfg or not rag_cfg.get("enabled", True):
        return None
    try:
        from ctf_agent.core.knowledge_retriever import KnowledgeRetriever

        from ctf_agent.knowledge.skillpacks import EMBEDDED_SKILLS_ROOT
        skills_root_raw = rag_cfg.get("skills_root", "auto")
        if not skills_root_raw or skills_root_raw == "auto":
            skills_roots = [str(EMBEDDED_SKILLS_ROOT)]
        elif isinstance(skills_root_raw, (list, tuple)):
            skills_roots = [str(item) for item in list(skills_root_raw or []) if str(item or "").strip()]
        else:
            skills_roots = [str(skills_root_raw)]
        if plugin_registry:
            skills_roots = plugin_registry.merged_knowledge_roots(skills_roots)
        wiki_root = rag_cfg.get("wiki_root", "")

        retriever = KnowledgeRetriever(skills_root=skills_roots, wiki_root=wiki_root or None)
        retriever.load()
        logger.info("Knowledge retriever loaded: %s", retriever.stats)
        return retriever
    except Exception as exc:
        logger.warning("Failed to build knowledge retriever: %s", exc)
    return None


def _build_code_executor(config):
    """Build the sandboxed code executor."""
    try:
        from ctf_agent.core.code_executor import CodeExecutor
        ai_cfg = config.ai_solver
        return CodeExecutor(
            python_bin=ai_cfg.get("python_bin"),
            default_timeout=ai_cfg.get("code_timeout", 30),
        )
    except Exception as exc:
        logger.warning("Failed to build code executor: %s", exc)
    return None


def _build_agent_loop(llm, knowledge_retriever, code_executor, verifier,
                      file_tool, shell_tool, toolkit_tool, http_tool,
                      remote_tool, mcp_registry, oob_tool, config, workspace_manager,
                      plugin_registry=None, approval_manager=None):
    """Build the AI agent loop with all tools wired up."""
    if not llm:
        return None
    try:
        from ctf_agent.core.agent_loop import AgentLoop, build_default_tools

        tools = build_default_tools(
            code_executor=code_executor,
            knowledge_retriever=knowledge_retriever,
            verifier=verifier,
            file_tool=file_tool,
            shell_tool=shell_tool,
            toolkit_tool=toolkit_tool,
            http_tool=http_tool,
            remote_tool=remote_tool,
            mcp_registry=mcp_registry,
            oob_tool=oob_tool,
        )

        ai_cfg = config.ai_solver
        loop = AgentLoop(
            llm=llm,
            tools=tools,
            knowledge_retriever=knowledge_retriever,
            code_executor=code_executor,
            verifier=verifier,
            max_steps=ai_cfg.get("max_steps", 25),
            max_tokens_budget=ai_cfg.get("max_tokens", 120000),
            language=config.language,
            file_tool=file_tool,
            shell_tool=shell_tool,
            toolkit_tool=toolkit_tool,
            http_tool=http_tool,
            remote_tool=remote_tool,
            mcp_registry=mcp_registry,
            oob_tool=oob_tool,
            workspace_manager=workspace_manager,
            plugin_registry=plugin_registry,
            approval_manager=approval_manager,
        )
        logger.info("Agent loop built with %d tools", len(tools.names))
        return loop
    except Exception as exc:
        logger.warning("Failed to build agent loop: %s", exc)
    return None


def build_service(config_path=None, workspace_root=None, timeout=8.0, max_js_assets=8):
    project_root = Path(__file__).resolve().parents[2]
    resolved_config = _normalize_runtime_path(config_path, project_root / "local_config.json")
    config = load_agent_config(resolved_config)

    workspace_dir = _normalize_runtime_path(workspace_root, Path(config.workspace_root))
    RUN_MANAGER.set_storage_root(workspace_dir)
    workspace_manager = WorkspaceManager(workspace_dir)
    verifier = FlagVerifier()

    file_tool = FileTool()
    http_tool = HttpTool(timeout=timeout)
    shell_tool = ShellTool()
    toolkit_tool = ToolkitTool(config.toolkit_root, shell_tool=shell_tool)
    remote_tool = RemoteTool(config.remote_hosts, policy=config.remote_policy)
    plugin_registry = PluginRegistry(
        bundled_root=project_root / "plugins",
        plugin_roots=config.plugin_roots,
        enabled_plugins=config.enabled_plugins,
        disabled_plugins=config.disabled_plugins,
        workspace_manager=workspace_manager,
    )
    plugin_registry.discover()
    if hasattr(remote_tool, "configure_plugins"):
        remote_tool.configure_plugins(plugin_registry)
    approval_manager = ApprovalManager(
        workspace_manager=workspace_manager,
        approval_policy=config.approval_policy,
    )
    oob_tool = OOBTool(
        base_url=config.oob_base_url or None,
        poll_url_template=config.oob_poll_url_template or None,
        auth_token=config.oob_auth_token or None,
        auth_header=config.oob_auth_header,
        timeout=timeout,
    )
    mcp_registry = MCPRuntimeRegistry(
        plugin_registry.merged_mcp_servers(config.mcp_servers),
        timeout=config.mcp_timeout,
        preferred_browser=config.preferred_browser_mcp,
        preferred_reverse=config.preferred_reverse_mcp,
        workspace_manager=workspace_manager,
    )

    # --- AI Solver components (Phase 0-5) ---
    llm_client = _build_llm_client(config)
    knowledge_retriever = _build_knowledge_retriever(config, plugin_registry=plugin_registry)
    code_executor = _build_code_executor(config)

    router = HeuristicRouter(llm=llm_client)

    agent_loop = _build_agent_loop(
        llm_client, knowledge_retriever, code_executor, verifier,
        file_tool, shell_tool, toolkit_tool, http_tool,
        remote_tool, mcp_registry, oob_tool, config, workspace_manager,
        plugin_registry=plugin_registry,
        approval_manager=approval_manager,
    )

    solvers = {
        "web": WebSolver(
            http_tool=http_tool,
            file_tool=file_tool,
            shell_tool=shell_tool,
            oob_tool=oob_tool,
            verifier=verifier,
            toolkit_tool=toolkit_tool,
            remote_tool=remote_tool,
            profile=get_profile("web"),
            mcp_registry=mcp_registry,
            auto_run_sqlmap=config.auto_run_sqlmap,
            max_js_assets=max_js_assets,
            web_policy=config.web_policy,
        ),
        "binary": BinarySolver(
            file_tool=file_tool,
            shell_tool=shell_tool,
            verifier=verifier,
            toolkit_tool=toolkit_tool,
            remote_tool=remote_tool,
            mcp_registry=mcp_registry,
            policy=config.remote_policy,
        ),
        "triage": TriageSolver(
            file_tool=file_tool,
            shell_tool=shell_tool,
            verifier=verifier,
            toolkit_tool=toolkit_tool,
            remote_tool=remote_tool,
            mcp_registry=mcp_registry,
            http_tool=http_tool,
        ),
        "crypto": CryptoSolver(
            file_tool=file_tool,
            shell_tool=shell_tool,
            verifier=verifier,
            toolkit_tool=toolkit_tool,
            remote_tool=remote_tool,
            mcp_registry=mcp_registry,
            http_tool=http_tool,
        ),
        "forensics": ForensicsSolver(
            file_tool=file_tool,
            shell_tool=shell_tool,
            verifier=verifier,
            toolkit_tool=toolkit_tool,
            remote_tool=remote_tool,
            mcp_registry=mcp_registry,
            http_tool=http_tool,
        ),
        "osint": OsintSolver(
            file_tool=file_tool,
            shell_tool=shell_tool,
            verifier=verifier,
            toolkit_tool=toolkit_tool,
            remote_tool=remote_tool,
            mcp_registry=mcp_registry,
            http_tool=http_tool,
        ),
        "malware": MalwareSolver(
            file_tool=file_tool,
            shell_tool=shell_tool,
            verifier=verifier,
            toolkit_tool=toolkit_tool,
            remote_tool=remote_tool,
            mcp_registry=mcp_registry,
            http_tool=http_tool,
        ),
        "misc": MiscSolver(
            file_tool=file_tool,
            shell_tool=shell_tool,
            verifier=verifier,
            toolkit_tool=toolkit_tool,
            remote_tool=remote_tool,
            mcp_registry=mcp_registry,
            http_tool=http_tool,
        ),
    }
    orchestrator = Orchestrator(
        adapter=ManualJsonAdapter(),
        router=router,
        solvers=solvers,
        verifier=verifier,
        workspace_manager=workspace_manager,
        export_policy=config.export_policy,
        plugin_registry=plugin_registry,
        approval_manager=approval_manager,
        approval_policy=config.approval_policy,
    )
    return {
        "project_root": project_root,
        "config": config,
        "workspace_dir": workspace_dir,
        "workspace_manager": workspace_manager,
        "verifier": verifier,
        "router": router,
        "file_tool": file_tool,
        "http_tool": http_tool,
        "shell_tool": shell_tool,
        "toolkit_tool": toolkit_tool,
        "remote_tool": remote_tool,
        "oob_tool": oob_tool,
        "mcp_registry": mcp_registry,
        "plugin_registry": plugin_registry,
        "approval_manager": approval_manager,
        "orchestrator": orchestrator,
        # AI Solver components
        "llm_client": llm_client,
        "knowledge_retriever": knowledge_retriever,
        "code_executor": code_executor,
        "agent_loop": agent_loop,
    }


def close_service(service):
    if service and service.get("mcp_registry"):
        service["mcp_registry"].close()


def run_payload(service, arguments, run_id=None, cancel_event=None, source="cli"):
    orchestrator = service["orchestrator"]
    category = (arguments.get("category") or "web").strip().lower()
    attachments = [Path(item).resolve() for item in arguments.get("attachments", [])]

    ai_solver_mode = str(arguments.get("ai_solver", "auto")).strip().lower()

    challenge = Challenge(
        contest_id=arguments.get("contest_id", "manual"),
        challenge_id=arguments.get("challenge_id", "manual-{0}".format(category)),
        title=arguments.get("title", "manual-{0}".format(category)),
        category=category,
        description=arguments.get("description", "Manual {0} challenge".format(category)),
        attachments=attachments,
        target=arguments.get("url"),
        flag_format=arguments.get("flag_format", r"flag\{[^{}\n]+\}"),
        metadata={
            "source": source,
            "profile": category,
            "max_rounds": int(arguments.get("max_rounds", 6)),
            "use_browser_mcp": bool(arguments.get("use_browser_mcp", True)),
            "use_remote_host": arguments.get("use_remote_host"),
            "speed_mode": str(arguments.get("speed_mode") or "standard"),
            "speed_profile": dict(arguments.get("speed_profile") or {}),
            "remote_selection": dict(arguments.get("remote_selection") or {}),
            "autopilot_plan": dict(arguments.get("autopilot_plan") or {}),
            "skill_resolution": dict(arguments.get("skill_resolution") or {}),
            "knowledge_selection": dict(arguments.get("knowledge_selection") or {}),
            "input_summary": dict(arguments.get("input_summary") or {}),
            "task_template": dict(arguments.get("task_template") or {}),
            "ai_solver_policy": ai_solver_mode,
        },
    )

    # --- AI Solver routing ---
    agent_loop = service.get("agent_loop")
    router = service.get("router")
    if agent_loop and router and ai_solver_mode != "never":
        use_ai = (ai_solver_mode == "always") or router.route_to_agent_loop(challenge)
        if use_ai:
            logger.info("Routing to AI agent loop (mode=%s, category=%s)", ai_solver_mode, category)
            workspace = service["workspace_manager"].prepare(challenge)
            adapter = orchestrator.adapter
            staged = adapter.stage_attachments(
                challenge=challenge,
                attachments_dir=Path(workspace) / "attachments",
            )
            challenge.attachments = staged
            challenge.target = adapter.prepare_target(challenge)

            from ctf_agent.core.agent_loop import build_default_tools
            tools = build_default_tools(
                code_executor=service.get("code_executor"),
                knowledge_retriever=service.get("knowledge_retriever"),
                verifier=service.get("verifier"),
                file_tool=service.get("file_tool"),
                shell_tool=service.get("shell_tool"),
                toolkit_tool=service.get("toolkit_tool"),
                http_tool=service.get("http_tool"),
                remote_tool=service.get("remote_tool"),
                mcp_registry=service.get("mcp_registry"),
                oob_tool=service.get("oob_tool"),
                plugin_registry=service.get("plugin_registry"),
                workspace=str(workspace),
            )
            agent_loop.tools = tools
            if service.get("plugin_registry"):
                service["plugin_registry"].persist_workspace_status(workspace)
            state = agent_loop.solve(challenge, workspace)

            best_flag = service["verifier"].choose_best(state, challenge)
            result = {
                "status": "solved" if best_flag else state.phase,
                "workspace": str(workspace),
                "solver": "agent-loop",
                "state_path": str(Path(workspace) / "state.json"),
                "notes_path": str(Path(workspace) / "agent_loop_notes.md"),
                "solution_path": str(Path(workspace) / "artifacts" / "solution_generated.py"),
                "agent_loop_stats": agent_loop.llm.stats,
            }
            if state.phase == "needs_approval":
                result["status"] = "needs_approval"
            if best_flag:
                result["flag"] = best_flag.value
            service["workspace_manager"].save_state(workspace, state)
            if best_flag:
                result.update(export_solved_workspace(challenge, result, policy=service["config"].export_policy))
            return result

    return orchestrator.solve_challenge(
        challenge,
        auto_submit=bool(arguments.get("submit", False)),
        run_id=run_id,
        cancel_event=cancel_event,
    )
