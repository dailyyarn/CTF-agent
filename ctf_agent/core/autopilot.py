from pathlib import Path

from ctf_agent.knowledge import SkillResolver


def build_autopilot_plan(
    config,
    category,
    target="",
    attachments=None,
    remote_selection=None,
    use_browser_mcp=None,
    toolkit_capability_plan=None,
    speed_mode="standard",
    speed_profile=None,
    skill_resolution=None,
):
    attachments = [Path(item) for item in list(attachments or [])]
    remote_selection = dict(remote_selection or {})
    toolkit_capability_plan = dict(toolkit_capability_plan or {})
    speed_mode = str(speed_mode or "standard").strip().lower() or "standard"
    speed_profile = dict(speed_profile or {})
    if not skill_resolution or str(((skill_resolution.get("runtime") or {}).get("speed_mode") or "")).strip().lower() != speed_mode:
        skill_resolution = SkillResolver().resolve(
            task_text="",
            target=target,
            attachments=attachments,
            explicit_category=category,
            speed_mode=speed_mode,
        )

    skill_resolution = dict(skill_resolution or {})
    category_info = dict(skill_resolution.get("category") or {})
    skillpack = dict(skill_resolution.get("skillpack") or {})
    knowledge = dict(skill_resolution.get("knowledge") or {})
    recommendations = dict(skill_resolution.get("recommendations") or {})
    runtime = dict(skill_resolution.get("runtime") or {})
    category = category_info.get("selected_skill_category", (category or "misc").strip().lower() or "misc")

    local_tools = []
    recommended_mcp = []
    remote_templates = []
    solver_hints = list(knowledge.get("top_tactics", []))[:3]
    execution_profile = "triage"

    preferred_browser = str(getattr(config, "preferred_browser_mcp", "") or "").strip()
    preferred_reverse = str(getattr(config, "preferred_reverse_mcp", "") or "").strip()
    selected_remote = remote_selection.get("selected_host", "")
    selected_lanes = list(toolkit_capability_plan.get("selected_lanes", []))
    recommended_sidecars = list(toolkit_capability_plan.get("recommended_sidecars", []))

    if category == "web":
        execution_profile = "web-exploit"
        local_tools = ["http", "shell", "sqlmap", "strings"]
        if preferred_browser:
            recommended_mcp.append(preferred_browser)
        if bool(use_browser_mcp):
            solver_hints.append("浼樺厛鍚敤 browser MCP 澶勭悊鐧诲綍鎬併€丼PA 璺敱鍜屼笂浼犲鐜般€?")
        else:
            solver_hints.append("鍏堣蛋绾?HTTP 渚﹀療锛屽繀瑕佹椂鍐嶈ˉ browser MCP銆?")
        if selected_remote:
            remote_templates.append("http-replay")
            solver_hints.append("宸查€夎繙绋嬩富鏈猴紝鍙敤 http-replay 鍋氱浜岃瑙掑娴嬨€?")
    elif category in {"re", "reverse"}:
        execution_profile = "reverse-analysis"
        local_tools = ["strings", "ida64", "idat64", "imhex"]
        if preferred_reverse:
            recommended_mcp.append(preferred_reverse)
        if selected_remote:
            remote_templates.extend(["binary-analysis", "reverse-runner"])
            solver_hints.append("宸查€夎繙绋嬩富鏈猴紝鍙苟琛岃窇 binary-analysis / reverse-runner銆?")
        if recommended_sidecars:
            solver_hints.append("浼樺厛鍛戒腑 reverse MCP 涓?sidecar 宸ュ叿閾撅紝鍐嶅喅瀹氭槸鍚﹁ˉ杩滅▼鎵ц銆?")
    elif category == "pwn":
        execution_profile = "pwn-analysis"
        local_tools = ["strings", "checksec", "pwntools", "ida64", "x64dbg"]
        if preferred_reverse:
            recommended_mcp.append(preferred_reverse)
        remote_templates = ["binary-analysis", "binary-checksec"]
        if selected_remote:
            remote_templates.extend(["pwntools-probe", "input-bruteforce-lite"])
            solver_hints.append("宸查€夎繙绋嬩富鏈猴紝浼樺厛鍥哄寲 pwntools probe 鍜岃交閲忓€欓€夎緭鍏ラ獙璇併€?")
        if recommended_sidecars:
            solver_hints.append("蹇呰鏃跺垏 x64dbg / IDA sidecar 鍋氬姩鎬佽瘯鎺㈠拰闈欐€佺鍙峰畾浣嶃€?")
    else:
        execution_profile = "triage"
        local_tools = ["strings", "exiftool", "file"]
        solver_hints.append("鍏堝畬鎴愬熀纭€鍒嗚瘖锛屽啀娌挎帹鑽愯矾寰勫垏鍒板搴?specialized follow-up銆?")

    if speed_mode == "fastest":
        execution_profile = "fastest-{0}".format(execution_profile)
        solver_hints.insert(0, "Fastest mode active: favor the shortest runnable path, avoid knowledge detours, and keep the final answer compact.")
        if category == "pwn" and selected_remote:
            solver_hints.insert(1, "Fastest pwn path: stay remote-first and start from binary-checksec + pwn_probe + input-bruteforce-lite / pwntools-probe.")

    attachment_suffixes = sorted({item.suffix.lower() for item in attachments if item.suffix})
    if any(suffix in {".pcap", ".pcapng"} for suffix in attachment_suffixes):
        solver_hints.append("妫€娴嬪埌娴侀噺鍖咃紝浼樺厛鎻愬彇浼氳瘽銆佸璞″拰鍗忚鐥曡抗銆?")
    if any(suffix in {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"} for suffix in attachment_suffixes):
        solver_hints.append("妫€娴嬪埌鍘嬬缉鍖咃紝鍏堝畬鏁村睍寮€骞堕噸鎺掍富闄勪欢銆?")

    local_tools = sorted(
        set(
            local_tools
            + list(recommendations.get("recommended_tools", []))
            + list(toolkit_capability_plan.get("recommended_tools", []))
            + list(toolkit_capability_plan.get("recommended_libraries", []))
        )
    )
    recommended_mcp = sorted(set(recommended_mcp + list(recommendations.get("recommended_mcp", []))))
    remote_templates = sorted(set(remote_templates + list(recommendations.get("preferred_remote_templates", []))))

    summary_parts = [
        "category={0}".format(category),
        "local_tools={0}".format(", ".join(local_tools) if local_tools else "none"),
    ]
    if selected_lanes:
        summary_parts.append("lanes={0}".format("+".join(selected_lanes)))
    if recommended_mcp:
        summary_parts.append("mcp={0}".format(", ".join(recommended_mcp)))
    if recommended_sidecars:
        summary_parts.append("sidecars={0}".format(", ".join(recommended_sidecars)))
    if selected_remote:
        summary_parts.append("remote={0}".format(selected_remote))
    if remote_templates:
        summary_parts.append("templates={0}".format(", ".join(remote_templates)))
    if knowledge.get("pack_name"):
        summary_parts.append("playbook={0}".format(knowledge["pack_name"]))
    if speed_mode == "fastest":
        summary_parts.append("speed=fastest")

    return {
        "enabled": True,
        "category": category,
        "execution_profile": execution_profile,
        "speed_mode": speed_mode,
        "speed_profile": speed_profile,
        "summary": " | ".join(summary_parts),
        "local_tools": local_tools,
        "recommended_mcp": recommended_mcp,
        "remote_templates": remote_templates,
        "selected_remote_host": selected_remote,
        "solver_hints": solver_hints,
        "attachment_suffixes": attachment_suffixes,
        "target": str(target or ""),
        "use_browser_mcp": bool(use_browser_mcp) if use_browser_mcp is not None else None,
        "knowledge": {
            "selected_skill_category": category_info.get("selected_skill_category", category),
            "auto_category": category_info.get("auto_category", ""),
            "explicit_category": category_info.get("explicit_category", ""),
            "category_confidence": category_info.get("category_confidence", 0.0),
            "category_evidence": list(category_info.get("category_evidence", [])),
            "category_consistent": bool(category_info.get("category_consistent", False)),
            "knowledge_pack": dict(skillpack.get("knowledge_pack", {})),
            "pack_name": knowledge.get("pack_name", skillpack.get("label", "")),
            "knowledge_topics": list(knowledge.get("knowledge_topics", [])),
            "top_tactics": list(knowledge.get("top_tactics", [])),
            "reference_docs": list(knowledge.get("reference_docs", [])),
            "tactics_consumed": list(knowledge.get("top_tactics", []))[:3],
        },
        "skill_resolution": dict(skill_resolution),
        "selected_skill_category": category_info.get("selected_skill_category", category),
        "category_confidence": category_info.get("category_confidence", 0.0),
        "category_evidence": list(category_info.get("category_evidence", [])),
        "top_tactics": list(knowledge.get("top_tactics", [])),
        "reference_docs": list(knowledge.get("reference_docs", [])),
        "capability_plan": toolkit_capability_plan,
        "retrieval_enabled": bool(runtime.get("retrieval_enabled", True)),
        "retrieval_reason": str(runtime.get("retrieval_reason", "")),
    }
