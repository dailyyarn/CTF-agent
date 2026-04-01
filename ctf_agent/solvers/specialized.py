import base64
import binascii
import codecs
import gzip
import io
import json
import math
import re
import socket
import tarfile
import wave
import zipfile
import zlib
import struct
from pathlib import Path
from urllib.parse import unquote, urlparse

from ctf_agent.solvers.triage import TriageSolver


class _KnowledgeSpecializedSolver(TriageSolver):
    CATEGORY = "misc"
    SOLVER_NAME = "specialized"

    URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
    DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
    EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
    IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    PHONE_RE = re.compile(r"\b(?:\+?\d[\d\- ]{6,}\d)\b")
    COORD_RE = re.compile(r"\b-?\d{1,3}\.\d{3,},\s*-?\d{1,3}\.\d{3,}\b")
    HANDLE_RE = re.compile(r"(?<!\w)@[A-Za-z0-9_]{3,32}\b")
    HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
    BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])")
    HEX_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{24,})(?![A-Fa-f0-9])")
    BASE32_RE = re.compile(r"(?<![A-Z2-7=])(?:[A-Z2-7]{24,}={0,6})(?![A-Z2-7=])")
    SOURCE_PRIORITY = [
        "forensics:pcap-http-decode",
        "forensics:pcap-http-body",
        "forensics:pcap-recovery",
        "forensics:binwalk-extract",
        "forensics:binwalk-extract-nested",
        "forensics:gzip-carve",
        "forensics:zip-carve",
        "forensics:appended-",
        "forensics:png-text",
        "forensics:archive-7z",
        "forensics:archive-preview",
        "forensics:foremost-object",
        "forensics:carve",
        "forensics:tshark",
        "forensics:pcap-strings",
        "forensics:binary-strings",
        "forensics:metadata",
        "forensics:pcapfix",
        "forensics:capinfos",
        "forensics:binwalk",
        "forensics:foremost",
        "crypto:rsa-known-primes",
        "crypto:rsa-private-exponent",
        "crypto:rsa-phi-supplied",
        "crypto:rsa-shared-prime",
        "crypto:rsa-common-modulus",
        "crypto:rsa-small-factor",
        "crypto:rsa-low-exponent-root",
        "crypto:vigenere",
        "crypto:caesar",
        "crypto:single-byte-xor",
        "crypto:repeating-key-xor",
        "malware:config",
        "malware:stage",
        "malware:decoded",
        "osint:dns:",
        "osint:browser:",
        "osint:http:",
        "misc:jail:",
        "misc:stego:steghide-artifact",
        "misc:stego:steghide-nested",
        "misc:stego:binwalk-extract",
        "misc:stego:binwalk-nested",
        "misc:stego:png-text",
        "misc:stego:strings",
        "misc:stego:",
        "misc:dns:tshark",
        "misc:dns:strings",
        "misc:dns:pcapfix",
        "misc:dns:capinfos",
        "misc:dns:",
        "misc:rf:ffmpeg-wav-lsb",
        "misc:rf:",
        "misc:brainfuck",
        "misc:encoding:",
    ]

    def solve(self, challenge, workspace):
        challenge.metadata = dict(challenge.metadata or {})
        challenge.metadata.setdefault("category", self.CATEGORY)
        challenge.category = self.CATEGORY if not challenge.category else challenge.category
        return super().solve(challenge, workspace)

    def _specialized_analysis(self, challenge, category, workspace, state, memory, context, primary):
        blobs = self._collect_text_blobs(challenge, context)
        result = self._run_specialized(challenge, workspace, state, memory, context, primary, blobs)
        result = self._normalize_specialized_result(category or self.CATEGORY, result)
        toolkit_recommendations = self._toolkit_recommendations(category or self.CATEGORY, result.get("subtype", ""))
        if toolkit_recommendations:
            result["recommended_tools"] = self._dedupe(list(result.get("recommended_tools", [])) + toolkit_recommendations)
        capability_plan = {}
        if self.toolkit_tool and self.toolkit_tool.is_configured() and not context.get("toolkit_capabilities"):
            context["toolkit_capabilities"] = self.toolkit_tool.capability_digest()
        if self.toolkit_tool and self.toolkit_tool.is_configured():
            capability_plan = self.toolkit_tool.capability_plan(category or self.CATEGORY, result.get("subtype", ""))
            context["capability_plan"] = capability_plan
            result["recommended_tools"] = self._dedupe(
                list(result.get("recommended_tools", []))
                + list(capability_plan.get("recommended_tools", []))
                + list(capability_plan.get("recommended_libraries", []))
                + list(capability_plan.get("recommended_sidecars", []))
            )
        artifact_payload = result.pop("artifact_payload", None)
        artifact_name = result.pop("artifact_name", "{0}_analysis.json".format(self.CATEGORY))
        artifact_path = ""
        result["used_tools"] = self._dedupe(list(context.get("used_tools", [])))
        result["used_mcp"] = self._dedupe(list(context.get("used_mcp", [])))
        if artifact_payload is not None:
            if isinstance(artifact_payload, dict):
                artifact_payload.setdefault("used_tools", self._dedupe(list(context.get("used_tools", []))))
                artifact_payload.setdefault("used_mcp", self._dedupe(list(context.get("used_mcp", []))))
                artifact_payload.setdefault("capability_plan", capability_plan or dict(context.get("capability_plan") or {}))
            artifact_path = str((workspace / "artifacts" / artifact_name))
            self.file_tool.write_json(workspace / "artifacts" / artifact_name, artifact_payload)
        result["artifact_path"] = artifact_path
        result["analysis_artifact_name"] = artifact_name
        result["artifact_count"] = int(bool(artifact_path)) + int(result.get("extracted_artifact_count", 0) or 0)
        context["specialized"] = result

        if result.get("summary"):
            memory.add_finding(self.CATEGORY, "Specialized solver summary", str(result["summary"]), 0.72)
        if result.get("subtype"):
            memory.add_hypothesis("{0} subtype: {1}".format(self.CATEGORY, result["subtype"]))

        for item in list(result.get("findings", [])):
            memory.add_finding(
                item.get("source", self.CATEGORY),
                item.get("summary", "Specialized finding"),
                item.get("evidence", ""),
                float(item.get("confidence", 0.58)),
            )
        for item in list(result.get("hypotheses", [])):
            memory.add_hypothesis(item)
        for item in list(result.get("candidate_flags", [])):
            memory.add_candidate_flag(
                item.get("value", ""),
                source=item.get("source", self.CATEGORY),
                confidence=float(item.get("confidence", 0.58)),
                reproducible=bool(item.get("reproducible", False)),
            )
        for item in list(result.get("plans", [])):
            memory.add_exploit_plan(
                item.get("title", "Knowledge-driven plan"),
                item.get("method", "local-analysis"),
                item.get("url", "attachment://{0}".format(challenge.challenge_id)),
                data=item.get("data") or {},
                headers=item.get("headers") or {},
                notes=item.get("notes", ""),
                confidence=float(item.get("confidence", 0.58)),
            )

        context["recommended_tools"] = self._dedupe(list(context.get("recommended_tools", [])) + list(result.get("recommended_tools", [])))
        context["recommended_mcp"] = self._dedupe(list(context.get("recommended_mcp", [])) + list(result.get("recommended_mcp", [])))
        context["next_actions"] = self._dedupe(list(context.get("next_actions", [])) + list(result.get("next_actions", [])))
        if result.get("recommended_path"):
            context["recommended_path"] = result["recommended_path"]

    def _run_specialized(self, challenge, workspace, state, memory, context, primary, blobs):
        return {}

    def _candidate_source_priority(self, source):
        text = str(source or "").strip().lower()
        if not text:
            return len(self.SOURCE_PRIORITY) + 5
        for index, prefix in enumerate(self.SOURCE_PRIORITY):
            if text.startswith(prefix.lower()):
                return index
        return len(self.SOURCE_PRIORITY) + 1

    def _sort_candidate_flags(self, items):
        deduped = self._dedupe_flag_items(items)
        deduped.sort(
            key=lambda item: (
                self._candidate_source_priority(item.get("source", "")),
                -float(item.get("confidence", 0.0) or 0.0),
                0 if bool(item.get("reproducible", False)) else 1,
                str(item.get("value", "")),
            )
        )
        return deduped

    def _derive_best_path(self, category, result):
        category = str(category or self.CATEGORY or "specialized")
        candidate_flags = list(result.get("candidate_flags", []))
        recovered_objects = list(result.get("recovered_objects", []))
        extracted_artifacts = list(result.get("extracted_artifacts", []))
        decoded_candidates = list(result.get("decoded_candidates", []))
        preferred = str(result.get("best_path", "") or "").strip()
        if candidate_flags:
            return "flag via {0}".format(candidate_flags[0].get("source", category))
        if recovered_objects:
            first = dict(recovered_objects[0] or {})
            return "recover object -> {0}".format(first.get("kind", first.get("name", "object")))
        if extracted_artifacts:
            first = extracted_artifacts[0]
            if isinstance(first, dict):
                return "inspect artifact -> {0}".format(first.get("name", first.get("path", "artifact")))
            return "inspect artifact -> {0}".format(Path(str(first)).name)
        if decoded_candidates:
            first = decoded_candidates[0]
            if isinstance(first, dict):
                return "decode -> {0}".format(first.get("kind", "decoded"))
            return "decode -> decoded-candidate"
        if preferred:
            return preferred
        if result.get("recommended_path"):
            return str(result.get("recommended_path"))
        subtype = str(result.get("subtype", "") or "general")
        return "{0} -> {1}".format(category, subtype)

    def _normalize_specialized_result(self, category, result):
        category = str(category or self.CATEGORY or "specialized")
        normalized = dict(result or {})
        scalar_defaults = {
            "subtype": "",
            "summary": "",
            "best_path": "",
            "recommended_path": "{0}-specialized".format(category),
            "artifact_name": "{0}_analysis.json".format(category),
            "artifact_payload": None,
            "channel_preview": {},
        }
        list_defaults = {
            "candidate_flags": [],
            "findings": [],
            "next_actions": [],
            "recommended_tools": [],
            "recommended_mcp": [],
            "extracted_artifacts": [],
            "indicators": [],
            "subsolver_reports": [],
            "decoded_candidates": [],
            "attempts": [],
            "successful_decodes": [],
            "recovered_objects": [],
            "fetch_reports": [],
            "browser_reports": [],
            "seed_entities": [],
            "entities": [],
            "pivot_entities": [],
            "entity_graph": [],
            "pcap_reports": [],
            "iocs": [],
            "subpaths": [],
            "blocked_tokens": [],
            "viable_payloads": [],
            "payload_rationale": [],
            "dns_reports": [],
            "rf_reports": [],
            "png_text_chunks": [],
            "appended_payloads": [],
            "lsb_candidates": [],
            "best_payloads": [],
            "plans": [],
            "hypotheses": [],
            "attacks_attempted": [],
            "successful_attacks": [],
            "config_blobs": [],
            "stages": [],
        }
        for key, value in scalar_defaults.items():
            normalized.setdefault(key, value)
        for key, value in list_defaults.items():
            current = normalized.get(key, value)
            if current is None:
                current = []
            elif not isinstance(current, list):
                current = [current]
            normalized[key] = list(current)

        normalized["recommended_tools"] = self._dedupe([str(item) for item in normalized["recommended_tools"] if str(item or "").strip()])
        normalized["recommended_mcp"] = self._dedupe([str(item) for item in normalized["recommended_mcp"] if str(item or "").strip()])
        normalized["next_actions"] = self._dedupe([str(item) for item in normalized["next_actions"] if str(item or "").strip()])
        normalized["extracted_artifacts"] = self._dedupe([str(item) for item in normalized["extracted_artifacts"] if str(item or "").strip()])
        normalized["indicators"] = self._dedupe(self._flatten_indicator_values(normalized["indicators"]))
        normalized["seed_entities"] = [dict(item) if isinstance(item, dict) else {"type": "seed", "value": str(item)} for item in normalized["seed_entities"] if str(item or "").strip()]
        normalized["entities"] = self._dedupe([str(item) for item in normalized["entities"] if str(item or "").strip()])
        normalized["pivot_entities"] = self._dedupe([str(item) for item in normalized["pivot_entities"] if str(item or "").strip()])
        normalized["iocs"] = self._dedupe([str(item) for item in normalized["iocs"] if str(item or "").strip()])
        normalized["subpaths"] = self._dedupe([str(item) for item in normalized["subpaths"] if str(item or "").strip()])
        normalized["blocked_tokens"] = self._dedupe([str(item) for item in normalized["blocked_tokens"] if str(item or "").strip()])
        normalized["viable_payloads"] = self._dedupe([str(item) for item in normalized["viable_payloads"] if str(item or "").strip()])
        normalized["payload_rationale"] = self._dedupe([str(item) for item in normalized["payload_rationale"] if str(item or "").strip()])
        normalized["candidate_flags"] = self._sort_candidate_flags(normalized["candidate_flags"])
        normalized["decoded_candidates"] = self._dedupe_decoded_candidates(
            [self._coerce_decoded_candidate_item(item, default_kind="decoded") for item in normalized["decoded_candidates"]]
        )
        normalized["successful_decodes"] = self._dedupe_decoded_candidates(
            [self._coerce_decoded_candidate_item(item, default_kind="decoded") for item in normalized["successful_decodes"]]
        )
        normalized["recovered_objects"] = [dict(item) for item in normalized["recovered_objects"] if isinstance(item, dict)]
        normalized["dns_reports"] = [dict(item) for item in normalized["dns_reports"] if isinstance(item, dict)]
        normalized["rf_reports"] = [dict(item) for item in normalized["rf_reports"] if isinstance(item, dict)]
        normalized["channel_preview"] = dict(normalized.get("channel_preview") or {})
        normalized["subsolver_reports"] = [dict(item) if isinstance(item, dict) else {"summary": str(item)} for item in normalized["subsolver_reports"]]
        normalized["plans"] = [dict(item) for item in normalized["plans"] if isinstance(item, dict)]
        normalized["findings"] = [
            dict(item)
            if isinstance(item, dict)
            else {"source": category, "summary": "Specialized finding", "evidence": str(item), "confidence": 0.58}
            for item in normalized["findings"]
            if str(item or "").strip()
        ]
        normalized["seed_count"] = int(normalized.get("seed_count", 0) or len(normalized["seed_entities"]))
        normalized["entity_count"] = int(normalized.get("entity_count", 0) or len(normalized["entities"]))
        normalized["pivot_count"] = int(normalized.get("pivot_count", 0) or len(normalized["pivot_entities"]))
        normalized["budget_used"] = int(normalized.get("budget_used", 0) or len(normalized["fetch_reports"]))
        normalized["candidate_flag_count"] = len(normalized["candidate_flags"])
        normalized["indicator_count"] = len(normalized["indicators"])
        normalized["extracted_artifact_count"] = len(normalized["extracted_artifacts"])
        normalized["recovered_object_count"] = int(normalized.get("recovered_object_count", 0) or len(normalized["recovered_objects"]))
        normalized["attempt_count"] = int(normalized.get("attempt_count", 0) or len(normalized["attempts"]))
        normalized["successful_decode_count"] = int(normalized.get("successful_decode_count", 0) or len(normalized["successful_decodes"]))
        normalized["payload_count"] = int(normalized.get("payload_count", 0) or len(list(normalized.get("best_payloads", []))) or len(normalized["viable_payloads"]))
        normalized["attack_count"] = int(normalized.get("attack_count", 0) or len(normalized["attacks_attempted"]))
        normalized["success_count"] = int(normalized.get("success_count", 0) or len(normalized["successful_attacks"]))
        normalized["stage_count"] = int(normalized.get("stage_count", 0) or len(normalized["stages"]))
        normalized["ioc_count"] = int(normalized.get("ioc_count", 0) or len(normalized["iocs"]))
        normalized["best_path"] = self._derive_best_path(category, normalized)
        return normalized

    def _collect_text_blobs(self, challenge, context):
        blobs = []
        seen = set()
        for item in list(context.get("attachments", [])):
            path = Path(item.get("path", "")) if item.get("path") else None
            artifact = Path(item.get("artifact", "")) if item.get("artifact") else None
            if artifact and artifact.exists():
                text = self.file_tool.read_text(artifact, limit_bytes=120000)
                key = ("artifact", str(artifact))
                if key not in seen:
                    blobs.append(
                        {
                            "name": artifact.name,
                            "text": text,
                            "path": str(artifact),
                            "kind": item.get("kind", ""),
                            "source_name": str(item.get("name", "") or ""),
                            "source_path": str(path) if path else "",
                        }
                    )
                    seen.add(key)
            elif path and path.exists() and item.get("kind") == "text":
                text = self.file_tool.read_text(path, limit_bytes=120000)
                key = ("path", str(path))
                if key not in seen:
                    blobs.append(
                        {
                            "name": path.name,
                            "text": text,
                            "path": str(path),
                            "kind": item.get("kind", ""),
                            "source_name": str(item.get("name", "") or ""),
                            "source_path": str(path),
                        }
                    )
                    seen.add(key)
        if challenge.description:
            blobs.append({"name": "description.txt", "text": challenge.description, "path": "", "kind": "description"})
        if challenge.target:
            blobs.append({"name": "target.txt", "text": challenge.target, "path": "", "kind": "target"})
        return blobs

    def _toolkit_recommendations(self, category, subtype=""):
        if not self.toolkit_tool or not self.toolkit_tool.is_configured():
            return []
        return list(self.toolkit_tool.recommend_tools(category=category, subtype=subtype))

    def _record_used_tool(self, context, name):
        if context is None:
            return
        context["used_tools"] = self._dedupe(list(context.get("used_tools", [])) + [str(name or "")])

    def _record_used_mcp(self, context, name):
        if context is None:
            return
        context["used_mcp"] = self._dedupe(list(context.get("used_mcp", [])) + [str(name or "")])

    def _extract_entities(self, text):
        text = text or ""
        urls = [value for value in (self._normalize_url_candidate(item) for item in self.URL_RE.findall(text)) if value]
        domains = [value.lower() for value in self.DOMAIN_RE.findall(text) if self._looks_like_domain(value)]
        return {
            "urls": self._unique(urls),
            "domains": self._unique(domains),
            "emails": self._unique(self.EMAIL_RE.findall(text)),
            "ipv4": self._unique(self.IPV4_RE.findall(text)),
            "phones": self._unique(self.PHONE_RE.findall(text)),
            "coords": self._unique(self.COORD_RE.findall(text)),
            "handles": self._unique(self.HANDLE_RE.findall(text)),
            "hashes": self._unique(self.HASH_RE.findall(text)),
        }

    def _decoded_candidates(self, text, limit=12):
        text = text or ""
        candidates = []
        for matcher, kind in [
            (self.BASE64_RE.findall(text), "base64"),
            (self.HEX_RE.findall(text), "hex"),
            (self.BASE32_RE.findall(text.upper()), "base32"),
        ]:
            for token in matcher[:limit]:
                decoded = self._decode_token(token, kind)
                if decoded:
                    candidates.append({"kind": kind, "token": token[:60], "decoded": decoded[:240]})
        url_decoded = unquote(text)
        if url_decoded != text:
            candidates.append({"kind": "url", "token": "full-text", "decoded": url_decoded[:240]})
        return candidates[:limit]

    def _decode_charcode_sequences(self, text, limit=6):
        text = str(text or "")
        results = []
        seen = set()
        for match in re.findall(r"\[(?:\s*\d{2,3}\s*,){4,}\s*\d{2,3}\s*\]", text):
            values = []
            for item in re.findall(r"\d{2,3}", match):
                try:
                    value = int(item)
                except Exception:
                    continue
                if value < 0 or value > 255:
                    values = []
                    break
                values.append(value)
            if len(values) < 5:
                continue
            decoded = "".join(chr(value) for value in values).strip()
            if not decoded or not any(ch.isalpha() for ch in decoded):
                continue
            marker = decoded.lower()
            if marker in seen:
                continue
            seen.add(marker)
            results.append(decoded)
            if len(results) >= int(limit):
                break
        return results

    def _decode_token(self, token, kind):
        try:
            if kind == "base64":
                raw = base64.b64decode(token + "=" * ((4 - len(token) % 4) % 4), validate=False)
            elif kind == "base32":
                raw = base64.b32decode(token + "=" * ((8 - len(token) % 8) % 8), casefold=True)
            elif kind == "hex":
                raw = binascii.unhexlify(token)
            else:
                return ""
            return self._decode_bytes_to_text(raw)
        except Exception:
            return ""

    def _decode_bytes_to_text(self, raw):
        raw = bytes(raw or b"")
        variants = []
        if raw.startswith(b"\x1f\x8b"):
            try:
                variants.append(gzip.decompress(raw))
            except Exception:
                pass
        variants.append(raw)

        candidates = []
        for payload in variants:
            for encoding in ("utf-8", "utf-16le", "utf-16be", "latin-1"):
                try:
                    text = payload.decode(encoding, errors="replace")
                except Exception:
                    continue
                score = self._text_score(text)
                if score >= 0.45:
                    candidates.append((score, text))
        if not candidates:
            return ""
        candidates.sort(key=lambda item: (item[0], len(item[1])), reverse=True)
        return candidates[0][1]

    def _text_score(self, text):
        text = text or ""
        if not text:
            return 0.0
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
        ratio = printable / max(1, len(text))
        ascii_friendly = sum(
            1
            for ch in text
            if (32 <= ord(ch) <= 126 and (ch.isalnum() or ch in " \r\n\t{}[]()_:/.-'\"=;,+@"))
        )
        ascii_ratio = ascii_friendly / max(1, len(text))
        bonus = 0.0
        if self.verifier.discover_from_text(text):
            bonus += 0.3
        if self.URL_RE.search(text):
            bonus += 0.12
        if re.search(r"\b(?:flag|ctf|http|https|powershell|invoke|base64|rsa|xor)\b", text, re.I):
            bonus += 0.12
        if "{" in text and "}" in text:
            bonus += 0.08
        return (ratio * 0.35) + (ascii_ratio * 0.65) + bonus

    def _recursive_decode_candidates(self, text, limit=16, max_depth=3):
        queue = [("text", text or "", 0)]
        seen = set()
        results = []
        while queue and len(results) < limit:
            chain, current, depth = queue.pop(0)
            marker = (chain, current[:512])
            if not current or marker in seen:
                continue
            seen.add(marker)

            if depth > 0 and self._text_score(current) >= 0.55:
                results.append({"kind": chain.split("->")[-1], "token": chain, "decoded": current[:2000], "chain": chain, "depth": depth})
                if len(results) >= limit:
                    break

            if depth >= max_depth:
                continue

            transforms = []
            url_decoded = unquote(current)
            if url_decoded != current:
                transforms.append(("url", url_decoded))
            for token, kind in self._extract_encoded_tokens(current, limit=6):
                decoded = self._decode_token(token, kind)
                if decoded:
                    transforms.append((kind, decoded))
            for transform_name, decoded in transforms:
                if decoded and decoded[:512] != current[:512]:
                    queue.append(("{0}->{1}".format(chain, transform_name), decoded, depth + 1))
        return results[:limit]

    def _extract_encoded_tokens(self, text, limit=8):
        text = text or ""
        tokens = []
        for matcher, kind in [
            (self.BASE64_RE.findall(text), "base64"),
            (self.HEX_RE.findall(text), "hex"),
            (self.BASE32_RE.findall(text.upper()), "base32"),
        ]:
            for token in matcher[:limit]:
                tokens.append((token, kind))
        return tokens[:limit]

    def _parse_int_literal(self, value):
        raw = str(value or "").strip()
        if not raw:
            return None
        try:
            if raw.lower().startswith("0x"):
                return int(raw, 16)
            if re.search(r"[a-f]", raw, re.I):
                return int(raw, 16)
            return int(raw, 10)
        except Exception:
            return None

    def _int_to_text(self, value):
        try:
            integer = int(value)
        except Exception:
            return ""
        if integer < 0:
            return ""
        width = max(1, (integer.bit_length() + 7) // 8)
        raw = integer.to_bytes(width, "big")
        return self._decode_bytes_to_text(raw)

    def _integer_nth_root(self, value, degree):
        if value < 0 or degree <= 0:
            return None
        low = 0
        high = 1
        while high ** degree <= value:
            high *= 2
        while low + 1 < high:
            mid = (low + high) // 2
            power = mid ** degree
            if power == value:
                return mid
            if power < value:
                low = mid
            else:
                high = mid
        return low if low ** degree == value else None

    def _trial_factor(self, value, limit=200000):
        integer = int(value)
        if integer <= 3:
            return None
        if integer % 2 == 0:
            return (2, integer // 2)
        ceiling = min(int(math.isqrt(integer)), limit)
        candidate = 3
        while candidate <= ceiling:
            if integer % candidate == 0:
                return (candidate, integer // candidate)
            candidate += 2
        return None

    def _filter_decoded_candidates(self, candidates, min_score=0.72, limit=12):
        filtered = []
        seen = set()
        for item in list(candidates or []):
            decoded = item.get("decoded", "")
            if not decoded:
                continue
            score = self._text_score(decoded)
            if score < min_score:
                continue
            marker = decoded[:512]
            if marker in seen:
                continue
            enriched = dict(item)
            enriched["score"] = round(score, 3)
            filtered.append(enriched)
            seen.add(marker)
        filtered.sort(key=lambda item: (item.get("score", 0.0), len(item.get("decoded", ""))), reverse=True)
        return filtered[:limit]

    def _single_byte_xor_candidates(self, raw, source_kind="raw", min_score=0.9, limit=4):
        results = []
        seen = set()
        payload = bytes(raw or b"")
        for key in range(256):
            decoded = bytes(byte ^ key for byte in payload)
            text_candidate = self._decode_bytes_to_text(decoded)
            if not text_candidate:
                continue
            score = self._text_score(text_candidate)
            if score < min_score:
                continue
            marker = text_candidate[:200]
            if marker in seen:
                continue
            seen.add(marker)
            if re.search(r"flag\{", text_candidate, re.I):
                score += 0.5
            elif re.search(r"\b(?:the|http|ctf|xor|key|admin)\b", text_candidate, re.I):
                score += 0.15
            results.append(
                {
                    "attack": "single-byte-xor",
                    "key": key,
                    "kind": source_kind,
                    "score": round(score, 3),
                    "text": text_candidate[:240],
                }
            )
        results.sort(key=lambda item: (item.get("score", 0.0), len(item.get("text", ""))), reverse=True)
        return results[:limit]

    def _score_xor_key_byte(self, raw, key):
        payload = bytes(raw or b"")
        if not payload:
            return 0.0
        decoded = bytes(byte ^ key for byte in payload)
        printable = sum(1 for byte in decoded if byte in {9, 10, 13} or 32 <= byte <= 126)
        alpha = sum(1 for byte in decoded if 65 <= byte <= 90 or 97 <= byte <= 122)
        whitespace = sum(1 for byte in decoded if byte in {9, 10, 13, 32})
        ratio = printable / max(1, len(decoded))
        alpha_ratio = alpha / max(1, len(decoded))
        whitespace_ratio = whitespace / max(1, len(decoded))
        score = ratio + (alpha_ratio * 0.35) + (whitespace_ratio * 0.15)
        if b"flag{" in decoded.lower():
            score += 0.5
        return score

    def _repeating_key_xor_candidates(self, raw, min_score=0.88, limit=4):
        payload = bytes(raw or b"")
        if not payload:
            return []
        candidate_keys = [
            b"key",
            b"ctf",
            b"flag",
            b"xor",
            b"admin",
            b"secret",
            b"test",
        ]
        max_keysize = min(8, max(2, len(payload) // 4))
        for keysize in range(2, max_keysize + 1):
            guessed = bytearray()
            for offset in range(keysize):
                block = payload[offset::keysize]
                if not block:
                    continue
                best_key = max(range(256), key=lambda key: self._score_xor_key_byte(block, key))
                guessed.append(best_key)
            if len(guessed) >= 2:
                candidate_keys.append(bytes(guessed))
        results = []
        seen = set()
        for key in self._unique(candidate_keys)[:18]:
            decoded = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(payload))
            text_candidate = self._decode_bytes_to_text(decoded)
            if not text_candidate:
                continue
            score = self._text_score(text_candidate)
            if score < min_score:
                continue
            marker = text_candidate[:200]
            if marker in seen:
                continue
            seen.add(marker)
            if re.search(r"flag\{", text_candidate, re.I):
                score += 0.5
            elif re.search(r"\b(?:the|http|ctf|xor|key|admin)\b", text_candidate, re.I):
                score += 0.15
            results.append(
                {
                    "attack": "repeating-key-xor",
                    "key": key.decode("latin-1", errors="replace"),
                    "score": round(score, 3),
                    "text": text_candidate[:240],
                }
            )
        results.sort(key=lambda item: (item.get("score", 0.0), len(item.get("text", ""))), reverse=True)
        return results[:limit]

    def _caesar_candidates(self, text, min_score=0.84, limit=4):
        source = text or ""
        if not source:
            return []
        source_score = self._text_score(source)
        lowers = "abcdefghijklmnopqrstuvwxyz"
        uppers = lowers.upper()
        results = []
        seen = set()
        for shift in range(1, 26):
            trans = str.maketrans(lowers + uppers, lowers[shift:] + lowers[:shift] + uppers[shift:] + uppers[:shift])
            decoded = source.translate(trans)
            score = self._text_score(decoded)
            if score < min_score:
                continue
            marker = decoded[:200]
            if marker in seen:
                continue
            seen.add(marker)
            has_flag = bool(re.search(r"flag\{", decoded, re.I))
            if has_flag:
                score += 0.45
            elif score <= (source_score + 0.08):
                continue
            results.append({"attack": "caesar", "shift": shift, "score": round(score, 3), "text": decoded[:240]})
        results.sort(key=lambda item: (item.get("score", 0.0), len(item.get("text", ""))), reverse=True)
        return results[:limit]

    def _inflate_bytes(self, raw):
        payload = bytes(raw or b"")
        if not payload:
            return ""
        candidates = []
        if payload.startswith(b"\x1f\x8b"):
            try:
                candidates.append(gzip.decompress(payload))
            except Exception:
                pass
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                candidates.append(zlib.decompress(payload, wbits))
            except Exception:
                continue
        texts = []
        for candidate in candidates:
            decoded = self._decode_bytes_to_text(candidate)
            if decoded:
                texts.append(decoded)
        if not texts:
            return ""
        texts.sort(key=self._text_score, reverse=True)
        return texts[0]

    def _extended_gcd(self, left, right):
        if right == 0:
            return (left, 1, 0)
        gcd_value, x1, y1 = self._extended_gcd(right, left % right)
        return (gcd_value, y1, x1 - (left // right) * y1)

    def _mod_pow_signed(self, value, exponent, modulus):
        integer = int(value)
        exponent = int(exponent)
        modulus = int(modulus)
        if exponent >= 0:
            return pow(integer, exponent, modulus)
        inverse = pow(integer, -1, modulus)
        return pow(inverse, abs(exponent), modulus)

    def _vigenere_candidates(self, text, min_score=0.82, limit=4):
        corpus = str(text or "")
        if not corpus:
            return []
        alpha_only = re.sub(r"[^A-Za-z]", "", corpus)
        if len(alpha_only) < 12:
            return []
        key_candidates = ["key", "ctf", "flag", "secret", "crypto", "vigenere", "cipher"]
        hints = re.findall(r"\b[a-z]{3,8}\b", corpus.lower())
        key_candidates.extend(hints[:10])
        results = []
        seen = set()
        for key in self._unique(key_candidates)[:16]:
            decoded = []
            key_bytes = [ord(ch.lower()) - 97 for ch in key if ch.isalpha()]
            if not key_bytes:
                continue
            index = 0
            for char in corpus:
                if char.isalpha():
                    shift = key_bytes[index % len(key_bytes)]
                    base = ord("A") if char.isupper() else ord("a")
                    decoded.append(chr((ord(char) - base - shift) % 26 + base))
                    index += 1
                else:
                    decoded.append(char)
            plaintext = "".join(decoded)
            score = self._text_score(plaintext)
            if score < min_score:
                continue
            marker = plaintext[:200]
            if marker in seen:
                continue
            seen.add(marker)
            results.append({"attack": "vigenere", "key": key, "score": round(score, 3), "text": plaintext[:4000]})
        results.sort(key=lambda item: (item.get("score", 0.0), len(item.get("text", ""))), reverse=True)
        return results[:limit]

    def _extract_config_blobs(self, text, limit=8):
        content = str(text or "")
        if not content:
            return []
        blobs = []
        for match in re.finditer(r"\{[^\{\}]{12,400}\}", content, re.S):
            candidate = match.group(0).strip()
            if ":" in candidate or "=" in candidate:
                blobs.append({"kind": "inline-object", "summary": candidate[:240]})
        for match in re.finditer(r"(?im)^\s*([A-Za-z0-9_.-]{2,32})\s*[:=]\s*([^\r\n]{3,200})$", content):
            blobs.append({"kind": "assignment", "summary": "{0}={1}".format(match.group(1), match.group(2).strip())[:240]})
        deduped = []
        seen = set()
        for item in blobs:
            marker = item["summary"]
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(item)
        return deduped[:limit]

    def _recover_nested_stage_candidates(self, text, max_depth=4, limit=12):
        queue = [(str(text or ""), 0, "stage")]
        results = []
        seen = set()
        while queue and len(results) < limit:
            current, depth, chain = queue.pop(0)
            marker = current[:600]
            if not current or marker in seen:
                continue
            seen.add(marker)
            if depth > max_depth:
                continue

            candidates = []
            decoded_literal = self._decode_escaped_literal(current)
            if decoded_literal and decoded_literal != current:
                candidates.append(("unicode-escape", decoded_literal))
            url_decoded = unquote(current)
            if url_decoded != current:
                candidates.append(("url", url_decoded))
            for token, kind in self._extract_encoded_tokens(current, limit=6):
                decoded = self._decode_token(token, kind)
                if decoded:
                    candidates.append((kind, decoded))
                try:
                    raw = binascii.unhexlify(token) if kind == "hex" else base64.b64decode(token + "=" * ((4 - len(token) % 4) % 4), validate=False)
                except Exception:
                    raw = b""
                inflated = self._inflate_bytes(raw)
                if inflated:
                    candidates.append(("{0}-inflate".format(kind), inflated))
            for kind, decoded in candidates:
                if not decoded:
                    continue
                score = self._text_score(decoded)
                entry = {
                    "kind": kind,
                    "decoded": decoded[:4000],
                    "score": round(score, 3),
                    "chain": "{0}->{1}".format(chain, kind),
                    "depth": depth + 1,
                }
                if score >= 0.62 or self.verifier.discover_from_text(decoded):
                    results.append(entry)
                if depth + 1 < max_depth:
                    queue.append((decoded, depth + 1, entry["chain"]))
        return self._dedupe_decoded_candidates(results)[:limit]

    def _recover_nested_object_bytes(self, payload, workspace, prefix="", depth=0, limit=6):
        raw = bytes(payload or b"")
        if not raw or depth > 2:
            return {"artifacts": [], "objects": [], "candidate_flags": []}
        artifact_root = Path(workspace) / "artifacts"
        artifacts = []
        objects = []
        candidate_flags = []
        safe_prefix = re.sub(r"[^A-Za-z0-9._-]+", "_", str(prefix or "blob"))[:80]

        def persist_blob(name, blob, kind):
            artifact = artifact_root / "{0}_{1}".format(safe_prefix, name)
            self.file_tool.write_bytes(artifact, blob)
            artifacts.append(str(artifact))
            preview = self._decode_bytes_to_text(blob)
            if preview:
                objects.append({"name": artifact.name, "kind": kind, "artifact": str(artifact), "summary": preview[:240]})
                for flag in self.verifier.discover_from_text(preview):
                    candidate_flags.append({"value": flag, "source": "forensics:carve:{0}".format(kind), "confidence": 0.82, "reproducible": False})
            if depth < 2:
                nested = self._recover_nested_object_bytes(blob, workspace, prefix="{0}_{1}".format(safe_prefix, name), depth=depth + 1, limit=max(1, limit // 2))
                artifacts.extend(list(nested.get("artifacts", [])))
                objects.extend(list(nested.get("objects", [])))
                candidate_flags.extend(list(nested.get("candidate_flags", [])))

        try:
            if raw.startswith(b"\x1f\x8b"):
                inflated = gzip.decompress(raw)
                persist_blob("nested_{0}.bin".format(depth), inflated, "nested-gzip")
        except Exception:
            pass
        try:
            if zipfile.is_zipfile(io.BytesIO(raw)):
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    for index, info in enumerate(archive.infolist()[:4]):
                        if info.is_dir() or info.file_size > 250000:
                            continue
                        blob = archive.read(info)
                        persist_blob("nested_zip_{0}_{1}".format(depth, index), blob, "nested-zip-member")
        except Exception:
            pass
        return {
            "artifacts": artifacts[:limit],
            "objects": objects[:limit],
            "candidate_flags": self._sort_candidate_flags(candidate_flags)[:limit],
        }

    def _unique(self, values):
        ordered = []
        for value in list(values or []):
            if value and value not in ordered:
                ordered.append(value)
        return ordered

    def _normalize_url_candidate(self, value):
        text = str(value or "").strip().strip("'\"")
        if not text or not re.match(r"^[a-z][a-z0-9+.-]*://", text, re.I):
            return ""
        while text and text[-1] in "\\>)],;":
            text = text[:-1]
        parsed = urlparse(text)
        if not parsed.scheme or not parsed.netloc:
            return ""
        if parsed.path in {"", "/"} and not parsed.query and not parsed.fragment:
            return text.rstrip("/")
        return text

    def _looks_like_domain(self, value):
        text = str(value or "").strip().strip(".").lower()
        if not text or "@" in text or "/" in text:
            return False
        host = text
        if ":" in host:
            candidate, maybe_port = host.rsplit(":", 1)
            if maybe_port.isdigit():
                host = candidate
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            return True
        if "." not in host:
            return False
        file_like_suffixes = {
            "html",
            "htm",
            "js",
            "css",
            "json",
            "txt",
            "xml",
            "md",
            "png",
            "jpg",
            "jpeg",
            "gif",
            "svg",
            "php",
            "asp",
            "aspx",
            "jsp",
            "ps1",
            "bat",
            "cmd",
            "exe",
            "dll",
            "zip",
            "gz",
            "tar",
            "pcap",
            "wav",
            "sigmf",
            "bf",
        }
        parts = [item for item in host.split(".") if item]
        if len(parts) < 2 or parts[-1] in file_like_suffixes:
            return False
        pseudo_tlds = {
            "apply",
            "textcontent",
            "innerhtml",
            "outerhtml",
            "getelementbyid",
            "queryselector",
            "createelement",
            "appendchild",
            "setattribute",
            "addeventlistener",
            "fromcharcode",
            "charcodeat",
            "substring",
            "substr",
            "replace",
            "split",
            "handle",
            "email",
            "domain",
            "pathname",
            "href",
            "src",
            "onclick",
        }
        if parts[-1] in pseudo_tlds:
            return False
        return all(re.fullmatch(r"[a-z0-9-]+", item, re.I) for item in parts)

    def _coerce_decoded_candidate_item(self, item, default_kind="decoded"):
        if isinstance(item, dict):
            decoded = str(item.get("decoded", "") or item.get("preview", "") or "").strip()
            if not decoded:
                return None
            result = dict(item)
            result["kind"] = str(result.get("kind", default_kind) or default_kind)
            result["decoded"] = decoded[:4000]
            result["token"] = str(result.get("token", result["kind"]) or result["kind"])[:160]
            result["chain"] = str(result.get("chain", result["kind"]) or result["kind"])[:240]
            result["depth"] = int(result.get("depth", 0) or 0)
            if "score" in result:
                try:
                    result["score"] = round(float(result.get("score", 0.0) or 0.0), 3)
                except Exception:
                    result.pop("score", None)
            return result
        decoded = str(item or "").strip()
        if not decoded:
            return None
        return {
            "kind": default_kind,
            "token": default_kind,
            "decoded": decoded[:4000],
            "chain": default_kind,
            "depth": 0,
            "score": round(self._text_score(decoded), 3),
        }

    def _flatten_indicator_values(self, values, prefix=""):
        flattened = []
        for item in list(values or []):
            if isinstance(item, dict):
                for key, value in item.items():
                    key_prefix = "{0}{1}:".format(prefix, key)
                    if isinstance(value, dict):
                        flattened.extend(self._flatten_indicator_values([value], prefix=key_prefix))
                    elif isinstance(value, (list, tuple, set)):
                        flattened.extend(self._flatten_indicator_values(list(value), prefix=key_prefix))
                    else:
                        text = str(value or "").strip()
                        if text:
                            flattened.append("{0}{1}".format(key_prefix, text))
            elif isinstance(item, (list, tuple, set)):
                flattened.extend(self._flatten_indicator_values(list(item), prefix=prefix))
            else:
                text = str(item or "").strip()
                if text:
                    flattened.append("{0}{1}".format(prefix, text) if prefix else text)
        return flattened

    def _crypto_plaintext_confident(self, plaintext):
        text = str(plaintext or "").strip()
        if not text:
            return False
        if self.verifier.discover_from_text(text):
            return True
        return self._text_score(text) >= 0.72

    def _maybe_add_flag_candidates(self, decoded_candidates, memory, source_prefix):
        for item in decoded_candidates:
            for flag in self.verifier.discover_from_text(item.get("decoded", ""))[:4]:
                memory.add_candidate_flag(flag, source="{0}:{1}".format(source_prefix, item.get("kind", "")), confidence=0.64, reproducible=False)

    def _bounded_openssl_base64_probes(self, text, context, workspace, stem, source_prefix):
        if not self.toolkit_tool or not self.toolkit_tool.has_tool("openssl"):
            return {"artifact": "", "results": [], "candidate_flags": [], "decodes": []}
        probes = []
        candidate_flags = []
        decodes = []
        for token, kind in self._extract_encoded_tokens(text, limit=8):
            if kind != "base64":
                continue
            result = self.toolkit_tool.run_openssl_base64_decode(token, timeout=20)
            decoded_text = str(result.get("decoded_text", "") or "").strip()
            probes.append(
                {
                    "token": token[:120],
                    "status": result.get("status", ""),
                    "decoded_size": int(result.get("decoded_size", 0) or 0),
                    "decoded_text": decoded_text[:4000],
                }
            )
            if result.get("status") != "ok" or not decoded_text:
                continue
            self._record_used_tool(context, "openssl")
            score = self._text_score(decoded_text)
            if score >= 0.62 or self.verifier.discover_from_text(decoded_text):
                decodes.append(
                    {
                        "kind": "openssl-base64",
                        "token": token[:120],
                        "decoded": decoded_text[:4000],
                        "chain": "openssl-base64",
                        "depth": 1,
                        "score": round(score, 3),
                    }
                )
            for flag in self.verifier.discover_from_text(decoded_text):
                candidate_flags.append(
                    {
                        "value": flag,
                        "source": "{0}:openssl-base64".format(source_prefix),
                        "confidence": 0.8,
                        "reproducible": False,
                    }
                )
        if not probes:
            return {"artifact": "", "results": [], "candidate_flags": [], "decodes": []}
        safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", str(stem or self.CATEGORY))[:80]
        artifact = Path(workspace) / "artifacts" / "{0}_{1}_openssl_base64.json".format(safe_stem, self.CATEGORY)
        self.file_tool.write_json(artifact, probes)
        return {
            "artifact": str(artifact),
            "results": probes,
            "candidate_flags": self._sort_candidate_flags(candidate_flags),
            "decodes": self._dedupe_decoded_candidates(decodes),
        }

    def _build_osint_seed_entities(self, challenge, blobs):
        corpus = "\n".join(item.get("text", "") for item in blobs if item.get("text"))
        summary = self._extract_entities(corpus)
        if challenge.target:
            normalized_target = str(challenge.target).strip()
            if normalized_target:
                if "://" in normalized_target:
                    summary["urls"] = self._unique([normalized_target] + list(summary.get("urls", [])))
                    domain = urlparse(normalized_target).netloc
                    if domain:
                        summary["domains"] = self._unique([domain] + list(summary.get("domains", [])))
                else:
                    summary["domains"] = self._unique([normalized_target] + list(summary.get("domains", [])))
        return summary

    def _normalize_osint_entity(self, entity_type, value):
        text = str(value or "").strip()
        if not text:
            return ""
        if entity_type == "url":
            return self._normalize_url_candidate(text)
        if entity_type in {"domain", "email", "handle"}:
            normalized = text.lower()
            if entity_type == "domain" and not self._looks_like_domain(normalized):
                return ""
            return normalized
        if entity_type == "coords":
            parts = [item.strip() for item in text.split(",", 1)]
            if len(parts) == 2:
                return "{0},{1}".format(parts[0], parts[1])
        return text

    def _append_graph_node(self, nodes, index, entity_type, value, depth, source="", evidence=""):
        normalized = self._normalize_osint_entity(entity_type, value)
        if not normalized:
            return None
        key = "{0}:{1}".format(entity_type, normalized)
        node_id = index.get(key)
        if node_id is not None:
            node = nodes[node_id]
            node["depth"] = min(node.get("depth", depth), depth)
            if source and source not in node["sources"]:
                node["sources"].append(source)
            if evidence and evidence not in node["evidence"]:
                node["evidence"].append(evidence)
            return key
        node = {
            "type": entity_type,
            "value": normalized,
            "depth": int(depth),
            "sources": [source] if source else [],
            "evidence": [evidence] if evidence else [],
        }
        nodes.append(node)
        index[key] = len(nodes) - 1
        return key

    def _append_graph_edge(self, edges, seen, source_key, target_key, relation):
        if not source_key or not target_key or source_key == target_key:
            return
        marker = "{0}|{1}|{2}".format(source_key, relation, target_key)
        if marker in seen:
            return
        edges.append({"from": source_key, "to": target_key, "relation": relation})
        seen.add(marker)

    def _entity_summary_to_nodes(self, entity_summary, source, depth=0):
        mapping = [
            ("url", "urls"),
            ("domain", "domains"),
            ("email", "emails"),
            ("ipv4", "ipv4"),
            ("phone", "phones"),
            ("coords", "coords"),
            ("handle", "handles"),
        ]
        nodes = []
        for entity_type, key in mapping:
            for value in list(entity_summary.get(key, []))[:10]:
                nodes.append(
                    {
                        "type": entity_type,
                        "value": value,
                        "depth": int(depth),
                        "source": source,
                        "evidence": source,
                    }
                )
        return nodes

    def _flatten_text_candidates(self, items, field, prefix="", limit=8):
        values = []
        for item in list(items or []):
            if not isinstance(item, dict):
                continue
            text = str(item.get(field, "") or "").strip()
            if not text:
                continue
            if prefix:
                text = "{0}{1}".format(prefix, text)
            if text not in values:
                values.append(text)
            if len(values) >= limit:
                break
        return values

    def _powershell_json(self, script, timeout=30):
        if not self.shell_tool:
            return None
        result = self.shell_tool.run(
            ["powershell", "-NoProfile", "-Command", script],
            timeout=timeout,
        )
        runtime_memory = getattr(self, "_runtime_memory", None)
        runtime_challenge = getattr(self, "_runtime_challenge", None)
        runtime_workspace = getattr(self, "_runtime_workspace", None)
        if runtime_memory is not None and runtime_challenge is not None and runtime_workspace is not None:
            if self._maybe_pause_on_approval(
                runtime_challenge,
                runtime_workspace,
                runtime_memory,
                checkpoint="specialized:powershell",
                result=result,
                context=self._runtime_snapshot(script=script[:400]),
                pending_action={"kind": "shell_powershell", "script": script[:400]},
                blocked_reason=str(result.get("message", "") or "powershell approval required"),
            ):
                return None
        stdout = (result.get("stdout", "") or "").strip()
        if result.get("returncode") != 0 or not stdout:
            return None
        try:
            return json.loads(stdout)
        except Exception:
            return None

    def _resolve_dns_records(self, domain):
        domain = self._normalize_osint_entity("domain", domain)
        report = {
            "domain": domain,
            "a_records": [],
            "txt_records": [],
            "mx_records": [],
            "ns_records": [],
            "source": "live",
        }
        if not domain:
            return report
        try:
            addresses = []
            for item in socket.getaddrinfo(domain, None):
                ip_value = item[4][0]
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip_value):
                    addresses.append(ip_value)
            report["a_records"] = self._unique(addresses)[:10]
        except Exception:
            pass

        safe_domain = domain.replace("'", "''")
        query_map = {
            "TXT": ("txt_records", "Strings"),
            "MX": ("mx_records", "NameExchange"),
            "NS": ("ns_records", "NameHost"),
        }
        for record_type, (target_key, property_name) in query_map.items():
            script = (
                "$records = Resolve-DnsName -Name '{0}' -Type {1} -ErrorAction SilentlyContinue | "
                "ForEach-Object {{ $_.{2} }}; "
                "if ($records) {{ $records | ConvertTo-Json -Compress -Depth 4 }}"
            ).format(safe_domain, record_type, property_name)
            payload = self._powershell_json(script, timeout=25)
            if payload is None:
                continue
            if not isinstance(payload, list):
                payload = [payload]
            flattened = []
            for item in payload:
                if isinstance(item, list):
                    flattened.extend(str(value) for value in item if value)
                elif item:
                    flattened.append(str(item))
            report[target_key] = self._unique(flattened)[:10]
        return report

    def _attachment_is_capture(self, attachment):
        path = Path(attachment.get("path", "") or attachment.get("name", ""))
        suffix = path.suffix.lower()
        return attachment.get("kind") == "pcap" or suffix in {".pcap", ".pcapng", ".cap"}

    def _extract_tshark_dns_reports(self, text):
        reports = {}
        for line in str(text or "").splitlines():
            stripped = line.strip()
            if not stripped or "|" not in stripped:
                continue
            parts = stripped.split("|")
            http_host = self._normalize_osint_entity("domain", parts[0] if len(parts) >= 1 else "")
            dns_name = self._normalize_osint_entity("domain", parts[3] if len(parts) >= 4 else "")
            for domain, source_key in [(dns_name, "queries"), (http_host, "host_hints")]:
                if not domain or not self._looks_like_domain(domain):
                    continue
                bucket = reports.setdefault(
                    domain,
                    {
                        "domain": domain,
                        "a_records": [],
                        "txt_records": [],
                        "mx_records": [],
                        "ns_records": [],
                        "source": "pcap",
                        "queries": [],
                        "host_hints": [],
                    },
                )
                bucket[source_key].append(domain)
        normalized = []
        for domain, item in sorted(reports.items()):
            item["queries"] = self._unique(list(item.get("queries", [])))[:10]
            item["host_hints"] = self._unique(list(item.get("host_hints", [])))[:10]
            normalized.append(item)
        return normalized

    def _fetch_osint_url(self, url, depth=0):
        if not self.http_tool:
            return {}
        response = self.http_tool.request("GET", url)
        report = {
            "url": response.get("url", url),
            "requested_url": url,
            "depth": int(depth),
            "status": response.get("status"),
            "error": response.get("error", ""),
            "content_type": response.get("content_type", ""),
            "title": "",
            "links": [],
            "scripts": [],
            "forms": [],
            "entity_summary": {},
            "body_excerpt": "",
            "dynamic_hint": False,
        }
        text = response.get("text", "") or ""
        if text:
            summary = self.http_tool.summarize_html(text, response.get("url", url))
            report["title"] = summary.get("title", "")
            report["links"] = summary.get("links", [])[:10]
            report["scripts"] = summary.get("scripts", [])[:10]
            report["forms"] = summary.get("forms", [])[:4]
            report["body_excerpt"] = text[:4000]
            combined = text + "\n" + "\n".join(report["links"]) + "\n" + "\n".join(report["scripts"])
            report["entity_summary"] = self._extract_entities(combined)
            lowered = combined.lower()
            report["dynamic_hint"] = (
                len(report["scripts"]) >= 3
                or "__next" in lowered
                or "__nuxt" in lowered
                or "window.__" in lowered
                or "graphql" in lowered
                or "/api/" in lowered
                or len(report["forms"]) >= 2
            )
        return report

    def _browser_osint_recon(self, url):
        if not self.mcp_registry or not self.mcp_registry.has_servers():
            return {}
        result = self.mcp_registry.call_browser_flow_safe(
            url,
            action="recon",
            task="Open the page, extract routes, links, forms, visible entities, and dynamic hints useful for OSINT pivots.",
            timeout=45.0,
        )
        runtime_memory = getattr(self, "_runtime_memory", None)
        runtime_challenge = getattr(self, "_runtime_challenge", None)
        runtime_workspace = getattr(self, "_runtime_workspace", None)
        if runtime_memory is not None and runtime_challenge is not None and runtime_workspace is not None:
            if self._maybe_pause_on_approval(
                runtime_challenge,
                runtime_workspace,
                runtime_memory,
                checkpoint="specialized:browser_flow",
                result=result,
                context=self._runtime_snapshot(url=url),
                pending_action={"kind": "browser_flow", "url": url, "action": "recon"},
                blocked_reason=str(result.get("message", "") or "browser MCP approval required"),
            ):
                return {"error": "approval required", "status": "needs_approval"}
        if result.get("status") == "error":
            return {"error": result.get("summary", "") or result.get("message", "")}
        structured = dict(result.get("structured") or {})
        flat = self.mcp_registry.flatten_tool_result(result.get("result"))
        return {
            "server": result.get("server", ""),
            "tool": result.get("tool", ""),
            "structured": structured,
            "text": flat[:8000],
            "summary": structured.get("summary", ""),
        }

    def _brainfuck_decode(self, code, max_steps=200000, max_output=2048):
        program = "".join(ch for ch in str(code or "") if ch in "><+-.,[]")
        if not program:
            return ""
        stack = []
        brackets = {}
        for index, char in enumerate(program):
            if char == "[":
                stack.append(index)
            elif char == "]" and stack:
                left = stack.pop()
                brackets[left] = index
                brackets[index] = left
        if stack:
            return ""
        tape = [0] * 65536
        pointer = 0
        position = 0
        steps = 0
        output = []
        while 0 <= position < len(program) and steps < max_steps and len(output) < max_output:
            command = program[position]
            if command == ">":
                pointer = (pointer + 1) % len(tape)
            elif command == "<":
                pointer = (pointer - 1) % len(tape)
            elif command == "+":
                tape[pointer] = (tape[pointer] + 1) % 256
            elif command == "-":
                tape[pointer] = (tape[pointer] - 1) % 256
            elif command == ".":
                output.append(chr(tape[pointer]))
            elif command == "[" and tape[pointer] == 0:
                position = brackets.get(position, position)
            elif command == "]" and tape[pointer] != 0:
                position = brackets.get(position, position)
            position += 1
            steps += 1
        text = "".join(output)
        if self._text_score(text) < 0.45 and not self.verifier.discover_from_text(text):
            return ""
        return text

    def _describe_rf_attachment(self, attachment):
        path = Path(attachment.get("path", ""))
        suffix = path.suffix.lower()
        report = {
            "name": attachment.get("name", path.name),
            "kind": attachment.get("kind", ""),
            "suffix": suffix,
            "size": int(attachment.get("size", 0) or 0),
        }
        if suffix == ".wav" and path.exists():
            try:
                with wave.open(str(path), "rb") as handle:
                    frames = handle.getnframes()
                    framerate = handle.getframerate()
                    report.update(
                        {
                            "channels": handle.getnchannels(),
                            "sample_width": handle.getsampwidth(),
                            "frame_rate": framerate,
                            "duration_seconds": round(frames / float(framerate or 1), 3),
                        }
                    )
                    if framerate:
                        report["modulation_hint"] = "audio-baseband"
            except Exception:
                pass
        elif suffix == ".sigmf-meta" and path.exists():
            try:
                payload = json.loads(path.read_text(encoding="utf-8-sig"))
                global_block = dict((payload.get("global") or [None])[0] or {}) if isinstance(payload.get("global"), list) else dict(payload.get("global") or {})
                report.update(
                    {
                        "sample_rate": global_block.get("core:sample_rate"),
                        "datatype": global_block.get("core:datatype"),
                        "description": global_block.get("core:description", ""),
                    }
                )
                if global_block.get("core:sample_rate"):
                    report["modulation_hint"] = "inspect constellation or waterfall around sample rate"
            except Exception:
                pass
        return report

    def _extract_png_text_chunks(self, path):
        target = Path(path)
        if not target.exists():
            return []
        raw = self.file_tool.read_bytes(target, limit_bytes=4 * 1024 * 1024)
        if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
            return []
        offset = 8
        findings = []
        while offset + 8 <= len(raw):
            try:
                length = int.from_bytes(raw[offset:offset + 4], "big")
                chunk_type = raw[offset + 4:offset + 8]
                chunk_data_start = offset + 8
                chunk_data_end = chunk_data_start + length
                if chunk_data_end + 4 > len(raw):
                    break
                chunk_data = raw[chunk_data_start:chunk_data_end]
                chunk_name = chunk_type.decode("latin-1", errors="replace")
                if chunk_name == "tEXt":
                    key, _, value = chunk_data.partition(b"\x00")
                    text = self._decode_bytes_to_text(value) or value.decode("latin-1", errors="replace")
                    findings.append({"type": "tEXt", "key": key.decode("latin-1", errors="replace"), "text": text[:4000]})
                elif chunk_name == "zTXt":
                    key, _, rest = chunk_data.partition(b"\x00")
                    if rest:
                        compressed = rest[1:] if len(rest) > 1 else b""
                        try:
                            text = zlib.decompress(compressed).decode("utf-8", errors="replace")
                            findings.append({"type": "zTXt", "key": key.decode("latin-1", errors="replace"), "text": text[:4000]})
                        except Exception:
                            pass
                elif chunk_name == "iTXt":
                    parts = chunk_data.split(b"\x00", 5)
                    if len(parts) >= 6:
                        key = parts[0].decode("latin-1", errors="replace")
                        compression_flag = parts[1][:1]
                        payload = parts[5]
                        if compression_flag == b"\x01":
                            try:
                                payload = zlib.decompress(payload)
                            except Exception:
                                pass
                        text = payload.decode("utf-8", errors="replace")
                        findings.append({"type": "iTXt", "key": key, "text": text[:4000]})
                if chunk_name == "IEND":
                    break
                offset = chunk_data_end + 4
            except Exception:
                break
        return findings

    def _describe_png_channel_preview(self, path):
        target = Path(path)
        if not target.exists():
            return {}
        raw = self.file_tool.read_bytes(target, limit_bytes=512)
        if not raw.startswith(b"\x89PNG\r\n\x1a\n") or len(raw) < 33:
            return {}
        try:
            ihdr_length = int.from_bytes(raw[8:12], "big")
            chunk_name = raw[12:16]
            if chunk_name != b"IHDR" or ihdr_length < 13:
                return {}
            width = int.from_bytes(raw[16:20], "big")
            height = int.from_bytes(raw[20:24], "big")
            bit_depth = raw[24]
            color_type = raw[25]
            channel_map = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
            return {
                "width": width,
                "height": height,
                "bit_depth": bit_depth,
                "color_type": color_type,
                "channel_count": channel_map.get(color_type, 0),
            }
        except Exception:
            return {}

    def _extract_inline_dns_reports(self, text, fallback_domains=None):
        content = str(text or "")
        reports = {}
        domain_candidates = self._unique(list(fallback_domains or []) + self.DOMAIN_RE.findall(content))
        current_domain = domain_candidates[0] if domain_candidates else "inline.local"

        def ensure(domain):
            domain = str(domain or current_domain).strip().lower()
            if not domain:
                domain = current_domain
            reports.setdefault(
                domain,
                {"domain": domain, "a_records": [], "txt_records": [], "mx_records": [], "ns_records": [], "source": "inline"},
            )
            return reports[domain]

        for domain in domain_candidates[:10]:
            ensure(domain)

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            zone_match = re.search(r"(?P<domain>(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\s+(?:(?:\d+\s+)?IN\s+)?(?P<rtype>TXT|MX|NS|A)\s+(?P<value>.+)", stripped, re.I)
            if zone_match:
                domain = zone_match.group("domain").lower()
                rtype = zone_match.group("rtype").upper()
                value = zone_match.group("value").strip().strip('"')
                bucket = ensure(domain)
                if rtype == "TXT":
                    bucket["txt_records"].append(value)
                elif rtype == "MX":
                    bucket["mx_records"].append(value.split()[-1])
                elif rtype == "NS":
                    bucket["ns_records"].append(value.split()[-1])
                elif rtype == "A":
                    bucket["a_records"].append(value.split()[-1])
                continue

            txt_inline = re.search(r"\bTXT\b[^:=]*[:=]\s*[\"']?(?P<value>.+?)[\"']?$", stripped, re.I)
            if txt_inline:
                ensure(current_domain)["txt_records"].append(txt_inline.group("value").strip())
                continue
            mx_inline = re.search(r"\bMX\b[^:=]*[:=]\s*(?P<value>.+)$", stripped, re.I)
            if mx_inline:
                ensure(current_domain)["mx_records"].append(mx_inline.group("value").strip().split()[-1])
                continue
            ns_inline = re.search(r"\bNS\b[^:=]*[:=]\s*(?P<value>.+)$", stripped, re.I)
            if ns_inline:
                ensure(current_domain)["ns_records"].append(ns_inline.group("value").strip().split()[-1])
                continue

        normalized = []
        for report in reports.values():
            report["a_records"] = self._unique(report.get("a_records", []))[:10]
            report["txt_records"] = self._unique(report.get("txt_records", []))[:10]
            report["mx_records"] = self._unique(report.get("mx_records", []))[:10]
            report["ns_records"] = self._unique(report.get("ns_records", []))[:10]
            normalized.append(report)
        return normalized

    def _extract_wav_lsb_candidates(self, path, limit=6):
        target = Path(path)
        if not target.exists():
            return []
        try:
            with wave.open(str(target), "rb") as handle:
                frame_count = min(handle.getnframes(), 240000)
                frames = handle.readframes(frame_count)
                sample_width = handle.getsampwidth()
        except Exception:
            return []

        candidates = []
        bit_orders = [("byte-lsb", [byte & 1 for byte in frames])]
        if sample_width in (1, 2, 4):
            sample_bits = []
            for offset in range(0, len(frames) - sample_width + 1, sample_width):
                chunk = frames[offset:offset + sample_width]
                if sample_width == 1:
                    value = chunk[0]
                else:
                    fmt = "<h" if sample_width == 2 else "<i"
                    value = struct.unpack(fmt, chunk)[0]
                sample_bits.append(abs(int(value)) & 1)
            bit_orders.append(("sample-lsb", sample_bits))

        for label, bits in bit_orders:
            for bit_direction in ("msb-first", "lsb-first"):
                payload = bytearray()
                for offset in range(0, len(bits) - 7, 8):
                    group = bits[offset:offset + 8]
                    if bit_direction == "lsb-first":
                        value = sum((bit & 1) << index for index, bit in enumerate(group))
                    else:
                        value = 0
                        for bit in group:
                            value = (value << 1) | (bit & 1)
                    payload.append(value)
                raw_payload = bytes(payload)
                fragments = []
                decoded = self._decode_bytes_to_text(raw_payload)
                if decoded:
                    fragments.append(decoded)
                ascii_text = raw_payload.decode("latin-1", errors="ignore")
                fragments.extend(re.findall(r"[ -~]{8,}", ascii_text))
                if b"flag{" in raw_payload.lower():
                    try:
                        fragments.append(raw_payload.decode("latin-1", errors="ignore"))
                    except Exception:
                        pass
                seen_fragments = set()
                for fragment in fragments:
                    piece = str(fragment or "").strip()
                    if not piece:
                        continue
                    if piece in seen_fragments:
                        continue
                    seen_fragments.add(piece)
                    score = self._text_score(piece)
                    if re.search(r"flag\{", piece, re.I):
                        score += 0.45
                    if score < 0.62 and not re.search(r"flag\{", piece, re.I):
                        continue
                    candidates.append(
                        {
                            "kind": "wav-lsb",
                            "path": str(target),
                            "mode": "{0}:{1}".format(label, bit_direction),
                            "decoded": piece[:4000],
                            "score": round(score, 3),
                        }
                    )
        candidates.sort(key=lambda item: (item.get("score", 0.0), len(item.get("decoded", ""))), reverse=True)
        unique = []
        seen = set()
        for item in candidates:
            marker = item.get("decoded", "")[:200]
            if marker in seen:
                continue
            seen.add(marker)
            unique.append(item)
        return unique[:limit]

    def _extract_appended_payloads(self, path, limit=4):
        target = Path(path)
        if not target.exists():
            return []
        raw = self.file_tool.read_bytes(target, limit_bytes=8 * 1024 * 1024)
        markers = [
            (b"PK\x03\x04", "zip"),
            (b"\x1f\x8b", "gzip"),
            (b"Rar!\x1a\x07", "rar"),
            (b"7z\xbc\xaf\x27\x1c", "7z"),
        ]
        findings = []
        for magic, kind in markers:
            start = raw.find(magic, 32)
            if start <= 0:
                continue
            payload = raw[start:]
            preview = ""
            if kind == "gzip":
                preview = self._inflate_bytes(payload)[:4000]
            elif kind == "zip":
                try:
                    with zipfile.ZipFile(Path(target)) as _:
                        pass
                except Exception:
                    pass
                try:
                    import io
                    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                        names = archive.namelist()[:8]
                        previews = []
                        for name in names[:3]:
                            try:
                                blob = archive.read(name)
                                text = self._decode_bytes_to_text(blob)
                                if text:
                                    previews.append("{0}: {1}".format(name, text[:300]))
                            except Exception:
                                continue
                        preview = "\n".join(previews)[:4000]
                except Exception:
                    preview = ""
            findings.append({"kind": kind, "offset": start, "preview": preview, "size": len(payload)})
        return findings[:limit]

    def _extract_direct_literal_flags(self, text):
        content = str(text or "")
        findings = []
        for flag in self.verifier.discover_from_text(content)[:10]:
            findings.append({"value": flag, "source": "literal", "confidence": 0.76, "reproducible": False})
        for match in re.finditer(r"(?:flag|secret|answer|result)\s*=\s*['\"]([^'\"]{4,200})['\"]", content, re.I):
            candidate = match.group(1).strip()
            if self.verifier.discover_from_text(candidate):
                findings.append({"value": candidate, "source": "assignment", "confidence": 0.84, "reproducible": False})
        for match in re.finditer(r"bytes\s*\(\s*\[([0-9,\s]{8,})\]\s*\)", content, re.I):
            values = []
            try:
                values = [int(item.strip()) for item in match.group(1).split(",") if item.strip()]
            except Exception:
                values = []
            if values:
                decoded = self._decode_bytes_to_text(bytes(value % 256 for value in values))
                for flag in self.verifier.discover_from_text(decoded)[:4]:
                    findings.append({"value": flag, "source": "bytes-list", "confidence": 0.82, "reproducible": False})
        for match in re.finditer(r"(?:chr\(\d{1,3}\)\s*\+\s*){2,}chr\(\d{1,3}\)", content, re.I):
            values = [int(item) for item in re.findall(r"chr\((\d{1,3})\)", match.group(0))]
            if values:
                decoded = "".join(chr(value % 256) for value in values)
                for flag in self.verifier.discover_from_text(decoded)[:4]:
                    findings.append({"value": flag, "source": "chr-sequence", "confidence": 0.84, "reproducible": False})
        for match in re.finditer(r"map\s*\(\s*chr\s*,\s*\[([0-9,\s]{8,})\]\s*\)", content, re.I):
            try:
                values = [int(item.strip()) for item in match.group(1).split(",") if item.strip()]
            except Exception:
                values = []
            if values:
                decoded = "".join(chr(value % 256) for value in values)
                for flag in self.verifier.discover_from_text(decoded)[:4]:
                    findings.append({"value": flag, "source": "map-chr", "confidence": 0.84, "reproducible": False})
        for match in re.finditer(r"printf\b[^\n\"']*(['\"])((?:\\{1,2}[0-7]{3}|\\{1,2}x[0-9A-Fa-f]{2}){4,})\1", content, re.I):
            token = match.group(2)
            decoded = self._decode_escaped_literal(token)
            for flag in self.verifier.discover_from_text(decoded)[:4]:
                findings.append({"value": flag, "source": "printf-escape", "confidence": 0.83, "reproducible": False})
        for match in re.finditer(r"(['\"])((?:\\{1,2}[0-7]{3}|\\{1,2}x[0-9A-Fa-f]{2}){4,})\1", content, re.I):
            token = match.group(2)
            decoded = self._decode_escaped_literal(token)
            for flag in self.verifier.discover_from_text(decoded)[:4]:
                findings.append({"value": flag, "source": "escaped-string", "confidence": 0.8, "reproducible": False})
        for match in re.finditer(r"(?:b64decode|Buffer\.from)\s*\(\s*['\"]([A-Za-z0-9+/=]{12,})['\"](?:\s*,\s*['\"]base64['\"])?\s*\)", content, re.I):
            decoded = self._decode_token(match.group(1), "base64")
            for flag in self.verifier.discover_from_text(decoded)[:4]:
                findings.append({"value": flag, "source": "inline-base64", "confidence": 0.83, "reproducible": False})
        deduped = []
        seen = set()
        for item in findings:
            value = item.get("value", "")
            if not value or value in seen:
                continue
            seen.add(value)
            deduped.append(item)
        return deduped

    def _parse_constraint_tokens(self, entries):
        tokens = []
        ignored = {
            "blacklist",
            "whitelist",
            "only",
            "allow",
            "deny",
            "chars",
            "characters",
            "tokens",
            "letters",
            "symbols",
            "words",
        }
        for entry in list(entries or []):
            text = str(entry or "")
            for token in re.findall(r"[A-Za-z0-9_.$/:-]+|[^A-Za-z0-9_\s]", text):
                value = str(token or "").strip()
                if not value:
                    continue
                if value.lower() in ignored:
                    continue
                tokens.append(value)
        return self._unique(tokens)[:48]

    def _evaluate_jail_payload(self, payload, blacklist_tokens=None, whitelist_tokens=None):
        payload = str(payload or "")
        blacklist_tokens = list(blacklist_tokens or [])
        whitelist_tokens = list(whitelist_tokens or [])
        blocked_tokens = []
        for token in blacklist_tokens:
            if len(token) == 1:
                if token in payload:
                    blocked_tokens.append(token)
            elif token.lower() in payload.lower():
                blocked_tokens.append(token)
        whitelist_chars = set()
        compact_tokens = [item for item in whitelist_tokens if item and len(item) <= 2]
        if compact_tokens and len("".join(compact_tokens)) >= 6:
            whitelist_chars = set("".join(compact_tokens))
        elif whitelist_tokens and len("".join(whitelist_tokens)) <= 64 and len(whitelist_tokens) <= 24:
            flattened = "".join(whitelist_tokens)
            if len(set(flattened)) >= 6:
                whitelist_chars = set(flattened)
        disallowed_chars = []
        if whitelist_chars:
            disallowed_chars = sorted({char for char in payload if not char.isspace() and char not in whitelist_chars})
        viable = not blocked_tokens and not disallowed_chars
        score = 0.92
        if blocked_tokens:
            score -= min(0.6, 0.14 * len(blocked_tokens))
        if disallowed_chars:
            score -= min(0.45, 0.08 * len(disallowed_chars))
        if "__" in payload or "constructor" in payload:
            score += 0.05
        score = max(0.05, min(0.99, score))
        rationale = "locally viable"
        if blocked_tokens:
            rationale = "blocked by blacklist tokens: {0}".format(", ".join(blocked_tokens[:4]))
        elif disallowed_chars:
            rationale = "violates whitelist chars: {0}".format("".join(disallowed_chars[:8]))
        elif "__" in payload or "constructor" in payload:
            rationale = "powerful meta-object path with no immediate local filter hit"
        return {
            "payload": payload,
            "viable": bool(viable),
            "score": round(score, 3),
            "blocked_tokens": blocked_tokens[:8],
            "disallowed_chars": disallowed_chars[:12],
            "rationale": rationale,
        }

    def _dedupe_flag_items(self, items):
        best = {}
        for item in list(items or []):
            value = str(item.get("value", "") or "").strip()
            if not value:
                continue
            current = dict(item)
            existing = best.get(value)
            if existing is None:
                best[value] = current
                continue
            current_rank = (
                self._candidate_source_priority(current.get("source", "")),
                -float(current.get("confidence", 0.0) or 0.0),
                0 if bool(current.get("reproducible", False)) else 1,
            )
            existing_rank = (
                self._candidate_source_priority(existing.get("source", "")),
                -float(existing.get("confidence", 0.0) or 0.0),
                0 if bool(existing.get("reproducible", False)) else 1,
            )
            if current_rank < existing_rank:
                best[value] = current
        return list(best.values())

    def _dedupe_decoded_candidates(self, items):
        deduped = []
        seen = set()
        for item in list(items or []):
            normalized = self._coerce_decoded_candidate_item(item)
            if not normalized:
                continue
            decoded = str(normalized.get("decoded", "") or "").strip()
            marker = (str(normalized.get("kind", "") or ""), decoded[:400])
            if not decoded or marker in seen:
                continue
            seen.add(marker)
            deduped.append(normalized)
        return deduped

    def _carve_embedded_gzip_streams(self, path, workspace, prefix="", limit=4):
        target = Path(path)
        if not target.exists():
            return []
        raw = self.file_tool.read_bytes(target, limit_bytes=8 * 1024 * 1024)
        findings = []
        offset = 0
        while len(findings) < limit:
            start = raw.find(b"\x1f\x8b", offset)
            if start < 0:
                break
            payload = raw[start:]
            try:
                inflated = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(payload)
            except Exception:
                offset = start + 2
                continue
            text = self._decode_bytes_to_text(inflated)
            if not text:
                offset = start + 2
                continue
            safe_prefix = prefix or target.stem
            artifact = Path(workspace) / "artifacts" / "{0}_gzip_{1}.bin".format(safe_prefix, start)
            self.file_tool.write_bytes(artifact, inflated)
            findings.append(
                {
                    "kind": "gzip-stream",
                    "offset": start,
                    "artifact": str(artifact),
                    "preview": text[:4000],
                    "size": len(inflated),
                }
            )
            offset = start + 2
        return findings

    def _carve_embedded_zip_objects(self, path, workspace, prefix="", limit=4):
        target = Path(path)
        if not target.exists():
            return []
        raw = self.file_tool.read_bytes(target, limit_bytes=8 * 1024 * 1024)
        findings = []
        offset = 32
        while len(findings) < limit:
            start = raw.find(b"PK\x03\x04", offset)
            if start <= 0:
                break
            payload = raw[start:]
            try:
                import io

                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    members = []
                    previews = []
                    for name in archive.namelist()[:8]:
                        try:
                            blob = archive.read(name)
                        except Exception:
                            continue
                        members.append({"name": name, "size": len(blob)})
                        text = self._decode_bytes_to_text(blob)
                        if text:
                            previews.append("{0}: {1}".format(name, text[:300]))
                    if not members:
                        offset = start + 4
                        continue
            except Exception:
                offset = start + 4
                continue
            safe_prefix = prefix or target.stem
            artifact = Path(workspace) / "artifacts" / "{0}_zip_{1}.zip".format(safe_prefix, start)
            self.file_tool.write_bytes(artifact, payload)
            findings.append(
                {
                    "kind": "zip-stream",
                    "offset": start,
                    "artifact": str(artifact),
                    "preview": "\n".join(previews)[:4000],
                    "members": members,
                    "size": len(payload),
                }
            )
            offset = start + 4
        return findings

    def _extract_dns_qname_candidates(self, raw, limit=12):
        payload = bytes(raw or b"")
        findings = []
        seen = set()
        payload_length = len(payload)
        for start in range(0, max(0, payload_length - 6)):
            labels = []
            cursor = start
            while cursor < payload_length and len(labels) < 8:
                label_length = payload[cursor]
                if label_length == 0:
                    if len(labels) >= 2:
                        domain = ".".join(labels).lower()
                        if domain not in seen and re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", domain):
                            seen.add(domain)
                            findings.append(domain)
                            if len(findings) >= limit:
                                return findings
                    break
                if label_length < 1 or label_length > 32:
                    break
                label_start = cursor + 1
                label_end = label_start + label_length
                if label_end > payload_length:
                    break
                chunk = payload[label_start:label_end]
                if not all((65 <= byte <= 90) or (97 <= byte <= 122) or (48 <= byte <= 57) or byte == 45 for byte in chunk):
                    break
                labels.append(chunk.decode("ascii", errors="ignore"))
                cursor = label_end
            if len(findings) >= limit:
                break
        return findings[:limit]

    def _recover_pcap_indicators(self, path, workspace, prefix=""):
        target = Path(path)
        if not target.exists():
            return {}
        raw = self.file_tool.read_bytes(target, limit_bytes=4 * 1024 * 1024)
        text = raw.decode("latin-1", errors="ignore")
        http_requests = []
        http_responses = []
        recovered_objects = []
        extra_artifacts = []
        urls = []
        hosts = []
        credentials = []
        cookies = []
        dns_records = []

        def _headers_to_map(header_blob):
            mapped = {}
            for line in re.split(r"\r?\n", str(header_blob or "")):
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                lowered = key.strip().lower()
                mapped.setdefault(lowered, []).append(value.strip())
            return mapped

        def _decode_chunked(payload):
            body = bytes(payload or b"")
            if not body:
                return b""
            cursor = 0
            chunks = []
            total = len(body)
            while cursor < total:
                line_end = body.find(b"\r\n", cursor)
                line_sep_len = 2
                if line_end == -1:
                    line_end = body.find(b"\n", cursor)
                    line_sep_len = 1
                if line_end == -1:
                    return b""
                size_line = body[cursor:line_end].strip()
                if not size_line:
                    cursor = line_end + line_sep_len
                    continue
                try:
                    size = int(size_line.split(b";", 1)[0], 16)
                except Exception:
                    return b""
                cursor = line_end + line_sep_len
                if size == 0:
                    return b"".join(chunks)
                if cursor + size > total:
                    return b""
                chunks.append(body[cursor : cursor + size])
                cursor += size
                if body[cursor : cursor + 2] == b"\r\n":
                    cursor += 2
                elif body[cursor : cursor + 1] == b"\n":
                    cursor += 1
            return b"".join(chunks)

        def _decode_content_encoded(payload, encoding_header):
            body = bytes(payload or b"")
            encodings = []
            for item in str(encoding_header or "").split(","):
                lowered = item.strip().lower()
                if lowered:
                    encodings.append(lowered)
            decoded = body
            for encoding in encodings:
                try:
                    if encoding == "gzip":
                        decoded = gzip.decompress(decoded)
                    elif encoding == "deflate":
                        decoded = zlib.decompress(decoded)
                except Exception:
                    return b""
            return decoded

        def _parse_basic_credentials(header_map):
            findings = []
            for value in list(header_map.get("authorization", [])):
                match = re.search(r"Basic\s+([A-Za-z0-9+/=]+)", value, re.I)
                if not match:
                    continue
                token = match.group(1)
                try:
                    decoded = base64.b64decode(token + "=" * ((4 - len(token) % 4) % 4), validate=False).decode("utf-8", errors="replace")
                except Exception:
                    continue
                if decoded:
                    findings.append({"scheme": "basic", "raw": value[:240], "decoded": decoded[:240]})
            return findings

        def _collect_cookie_indicators(header_map):
            found = []
            for key in ("cookie", "set-cookie"):
                for value in list(header_map.get(key, [])):
                    for token_match in re.finditer(r"([A-Za-z0-9_.-]{2,64})=([^;\r\n]{1,200})", value):
                        cookie_name = token_match.group(1)
                        cookie_value = token_match.group(2)
                        found.append({"type": key, "name": cookie_name, "value": cookie_value[:200]})
            return found

        def _extract_dns_record_hints(payload_text):
            hints = []
            for line in str(payload_text or "").splitlines():
                match = re.search(
                    r"^\s*(?P<name>(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,})\.?\s+(?:(?P<ttl>\d+)\s+)?IN\s+(?P<rtype>TXT|MX|NS|A)\s+(?P<value>[^\r\n]+)\s*$",
                    line,
                    re.I,
                )
                if not match:
                    continue
                hints.append(
                    {
                        "name": match.group("name").strip().lower(),
                        "type": match.group("rtype").upper(),
                        "value": match.group("value").strip().strip('"'),
                    }
                )
            return hints[:20]

        def _normalize_dns_record_value(record_type, value):
            normalized = str(value or "").strip().strip('"')
            if record_type == "MX":
                parts = normalized.split()
                if len(parts) >= 2 and parts[0].isdigit():
                    normalized = parts[1]
            if record_type in {"MX", "NS"}:
                normalized = normalized.rstrip(".")
            return normalized

        def _extension_for_response(content_type, body_bytes):
            lowered = str(content_type or "").lower()
            if "json" in lowered:
                return ".json"
            if "html" in lowered:
                return ".html"
            if "xml" in lowered:
                return ".xml"
            if "plain" in lowered or "text/" in lowered:
                return ".txt"
            if body_bytes.startswith(b"\x1f\x8b"):
                return ".gz"
            if body_bytes.startswith(b"PK\x03\x04"):
                return ".zip"
            if body_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                return ".png"
            return ".bin"

        for match in re.finditer(
            r"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(?P<path>/[^\s]*)\s+HTTP/[0-9.]+(?P<headers>(?:.*?\r?\n){0,20})",
            text,
            re.I,
        ):
            method = match.group("method").upper()
            path_value = match.group("path")
            headers = match.group("headers") or ""
            header_map = _headers_to_map(headers)
            host_match = re.search(r"Host:\s*([^\r\n]+)", headers, re.I)
            host_value = str(host_match.group(1)).strip() if host_match else ""
            parsed_basic = _parse_basic_credentials(header_map)
            if parsed_basic:
                credentials.extend(parsed_basic)
            cookies.extend(_collect_cookie_indicators(header_map))
            http_requests.append(
                {
                    "method": method,
                    "path": path_value,
                    "host": host_value,
                    "headers": {
                        "authorization": list(header_map.get("authorization", []))[:2],
                        "cookie": list(header_map.get("cookie", []))[:4],
                    },
                }
            )
            if host_value:
                hosts.append(host_value)
                urls.append("http://{0}{1}".format(host_value, path_value))
        http_status = self._unique(re.findall(r"HTTP/[0-9.]+\s+([1-5][0-9]{2})", text))[:10]
        response_starts = list(re.finditer(r"HTTP/[0-9.]+\s+(?P<status>[1-5][0-9]{2})(?:[^\r\n]*)\r?\n", text, re.I))
        request_or_response_starts = [match.start() for match in re.finditer(r"(?m)(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+/|HTTP/[0-9.]+\s+[1-5][0-9]{2}", text, re.I)]
        for index, match in enumerate(response_starts):
            status_value = match.group("status")
            header_start = match.end()
            header_end = text.find("\r\n\r\n", header_start)
            separator_len = 4
            if header_end == -1:
                header_end = text.find("\n\n", header_start)
                separator_len = 2
            if header_end == -1:
                headers = text[header_start : header_start + 2000]
                body_text = ""
            else:
                headers = text[header_start:header_end]
                body_start = header_end + separator_len
                body_end = len(text)
                for candidate_start in request_or_response_starts:
                    if candidate_start > body_start:
                        body_end = candidate_start
                        break
                body_text = text[body_start:body_end]
            header_map = _headers_to_map(headers)
            content_type_match = re.search(r"Content-Type:\s*([^\r\n;]+)", headers, re.I)
            content_encoding_match = re.search(r"Content-Encoding:\s*([^\r\n]+)", headers, re.I)
            disposition_match = re.search(r"Content-Disposition:\s*([^\r\n]+)", headers, re.I)
            transfer_encoding_match = re.search(r"Transfer-Encoding:\s*([^\r\n]+)", headers, re.I)
            content_type = str(content_type_match.group(1)).strip() if content_type_match else ""
            content_encoding = str(content_encoding_match.group(1)).strip() if content_encoding_match else ""
            disposition = str(disposition_match.group(1)).strip() if disposition_match else ""
            transfer_encoding = str(transfer_encoding_match.group(1)).strip() if transfer_encoding_match else ""
            raw_body_bytes = body_text.encode("latin-1", errors="ignore")
            body_bytes = raw_body_bytes
            if "chunked" in transfer_encoding.lower():
                decoded_chunked = _decode_chunked(body_bytes)
                if decoded_chunked:
                    body_bytes = decoded_chunked
            decoded_by_header = _decode_content_encoded(body_bytes, content_encoding)
            if decoded_by_header:
                body_bytes = decoded_by_header
            body_candidates = []
            direct_text = self._decode_bytes_to_text(body_bytes)
            if direct_text:
                body_candidates.append({"kind": "body-text", "decoded": direct_text[:4000]})
            inflated = self._inflate_bytes(body_bytes)
            if inflated:
                body_candidates.append({"kind": "body-inflate", "decoded": inflated[:4000]})
            if body_bytes.startswith(b"PK\x03\x04"):
                try:
                    import io

                    with zipfile.ZipFile(io.BytesIO(body_bytes)) as archive:
                        for name in archive.namelist()[:6]:
                            try:
                                blob = archive.read(name)
                            except Exception:
                                continue
                            decoded_member = self._decode_bytes_to_text(blob)
                            if decoded_member:
                                body_candidates.append({"kind": "body-zip", "decoded": "{0}: {1}".format(name, decoded_member[:300])})
                except Exception:
                    pass
            candidate_text = self._decode_bytes_to_text(body_bytes) or body_text
            body_candidates.extend(self._recursive_decode_candidates(candidate_text, limit=6, max_depth=2))
            body_candidates.extend(self._decoded_candidates(candidate_text, limit=4))
            body_candidates = self._dedupe_decoded_candidates(self._filter_decoded_candidates(body_candidates, min_score=0.68, limit=8))
            preview = direct_text or (body_candidates[0].get("decoded", "") if body_candidates else body_text[:4000])
            artifact_path = ""
            if body_bytes:
                extension = _extension_for_response(content_type, body_bytes)
                artifact_path = Path(workspace) / "artifacts" / "{0}_http_body_{1}{2}".format(prefix or target.stem, len(http_responses), extension)
                self.file_tool.write_bytes(artifact_path, body_bytes)
                extra_artifacts.append(str(artifact_path))
                recovered_objects.append(
                    {
                        "name": "{0}:http-body-{1}".format(target.name, len(http_responses)),
                        "kind": "pcap-http-body",
                        "artifact": str(artifact_path),
                        "summary": (preview or disposition or content_type or "http body")[:240],
                    }
                )
            parsed_basic = _parse_basic_credentials(header_map)
            if parsed_basic:
                credentials.extend(parsed_basic)
            cookies.extend(_collect_cookie_indicators(header_map))
            http_responses.append(
                {
                    "status": status_value,
                    "content_type": content_type,
                    "content_encoding": content_encoding,
                    "transfer_encoding": transfer_encoding,
                    "content_disposition": disposition,
                    "artifact": str(artifact_path) if artifact_path else "",
                    "preview": preview[:4000],
                    "decoded_candidates": body_candidates,
                    "headers": {
                        "content_type": content_type,
                        "content_encoding": content_encoding,
                        "content_disposition": disposition,
                        "transfer_encoding": transfer_encoding,
                    },
                }
            )
        dns_questions = self._extract_dns_qname_candidates(raw, limit=12)
        dns_records = _extract_dns_record_hints(text)
        entity_summary = self._extract_entities(text)
        entity_summary["domains"] = self._unique(
            list(entity_summary.get("domains", []))
            + dns_questions
            + hosts
            + [item.get("name", "") for item in dns_records if item.get("name")]
            + [_normalize_dns_record_value(item.get("type", ""), item.get("value", "")) for item in dns_records if item.get("type") in {"MX", "NS"} and item.get("value")]
        )[:20]
        entity_summary["ipv4"] = self._unique(
            list(entity_summary.get("ipv4", []))
            + [item.get("value", "") for item in dns_records if item.get("type") == "A" and item.get("value")]
        )[:20]
        entity_summary["urls"] = self._unique(list(entity_summary.get("urls", [])) + urls)[:20]
        candidate_flags = []
        for flag in self.verifier.discover_from_text(text):
            candidate_flags.append({"value": flag, "source": "forensics:pcap-recovery", "confidence": 0.82, "reproducible": False})
        for item in http_responses:
            preview = str(item.get("preview", "") or "")
            for flag in self.verifier.discover_from_text(preview):
                candidate_flags.append({"value": flag, "source": "forensics:pcap-http-body", "confidence": 0.86, "reproducible": False})
            for decoded in list(item.get("decoded_candidates", [])):
                for flag in self.verifier.discover_from_text(decoded.get("decoded", "")):
                    candidate_flags.append({"value": flag, "source": "forensics:pcap-http-decode", "confidence": 0.88, "reproducible": False})
        for item in credentials:
            decoded_value = str(item.get("decoded", ""))
            if decoded_value:
                for flag in self.verifier.discover_from_text(decoded_value):
                    candidate_flags.append({"value": flag, "source": "forensics:pcap-http-decode", "confidence": 0.9, "reproducible": False})
        indicators = []
        for item in credentials:
            indicators.append("auth:{0}".format(item.get("decoded", "")))
        for item in cookies[:10]:
            indicators.append("{0}:{1}={2}".format(item.get("type", ""), item.get("name", ""), item.get("value", "")))
        for item in dns_records[:10]:
            indicators.append("dns:{0}:{1}={2}".format(item.get("type", ""), item.get("name", ""), item.get("value", "")))
        artifact = Path(workspace) / "artifacts" / "{0}_pcap_recovery.json".format(prefix or target.stem)
        report = {
            "http_requests": http_requests[:12],
            "http_responses": http_responses[:8],
            "http_status": http_status,
            "http_hosts": self._unique(hosts)[:12],
            "urls": self._unique(urls)[:12],
            "dns_questions": dns_questions,
            "dns_records": dns_records,
            "entity_summary": entity_summary,
            "credentials": credentials[:8],
            "cookies": cookies[:16],
            "indicators": indicators[:16],
            "candidate_flags": candidate_flags,
            "recovered_objects": recovered_objects,
            "extra_artifacts": extra_artifacts,
            "text_excerpt": text[:4000],
        }
        self.file_tool.write_json(artifact, report)
        report["artifact"] = str(artifact)
        return report

    def _decode_escaped_literal(self, token, rounds=3):
        current = str(token or "")
        for _ in range(max(1, int(rounds or 1))):
            try:
                decoded = codecs.decode(current, "unicode_escape")
            except Exception:
                break
            if decoded == current:
                break
            current = decoded
        return current


class CryptoSolver(_KnowledgeSpecializedSolver):
    CATEGORY = "crypto"
    SOLVER_NAME = "crypto"

    def _run_specialized(self, challenge, workspace, state, memory, context, primary, blobs):
        corpus = "\n".join(item.get("text", "") for item in blobs if item.get("text"))
        lowered = corpus.lower()
        subtype = "encoding"
        evidence = []
        if (
            "rsa" in lowered
            or re.search(r"\bn[12]?\s*=\s*[0-9a-fx]{4,}", lowered)
            or (re.search(r"\be[12]?\s*=\s*[0-9a-fx]{1,}", lowered) and re.search(r"\bc[12]?\s*=\s*[0-9a-fx]{4,}", lowered))
        ):
            subtype = "rsa"
            evidence.append("rsa-like parameters detected")
        elif any(token in lowered for token in ["mt19937", "mersenne", "seed", "rand()", "random"]):
            subtype = "prng"
            evidence.append("prng markers detected")
        elif any(token in lowered for token in ["aes", "cbc", "ctr", "gcm", "iv", "nonce", "oracle"]):
            subtype = "modern-cipher"
            evidence.append("modern cipher markers detected")
        elif any(token in lowered for token in ["caesar", "vigenere", "rail fence", "rot13", "monoalphabetic"]):
            subtype = "classic-cipher"
            evidence.append("classic cipher markers detected")
        elif any(token in lowered for token in ["xor", "repeating key", "single-byte"]):
            subtype = "xor"
            evidence.append("xor markers detected")

        decoded_candidates = []
        for blob in blobs[:6]:
            decoded_candidates.extend(self._recursive_decode_candidates(blob.get("text", ""), limit=10, max_depth=4))
        decoded_candidates = self._filter_decoded_candidates(decoded_candidates, min_score=0.7, limit=20)
        self._maybe_add_flag_candidates(decoded_candidates, memory, "crypto")
        openssl_probe = self._bounded_openssl_base64_probes(
            corpus,
            context,
            workspace,
            (primary or {}).get("name", challenge.challenge_id),
            "crypto",
        )
        if openssl_probe.get("artifact"):
            decoded_candidates.extend(list(openssl_probe.get("decodes", [])))

        labeled_params = {}
        for match in re.finditer(r"\b([a-z][a-z0-9_]{0,11})\s*=\s*([0-9A-Fa-fx]{1,})", corpus):
            key = match.group(1).lower()
            value = match.group(2)
            if key in {"n", "e", "c", "cipher", "p", "q", "d", "dp", "dq", "phi", "n1", "n2", "e1", "e2", "c1", "c2", "phi1", "phi2"}:
                labeled_params[key] = value[:160]
        rsa_ints = {key: self._parse_int_literal(value) for key, value in labeled_params.items()}
        rsa_params = {key: value for key, value in labeled_params.items() if key in {"n", "e", "c", "cipher", "p", "q", "d", "dp", "dq", "phi"}}

        attacks_attempted = []
        successful_attacks = []
        xor_candidates = []
        candidate_flags = list(openssl_probe.get("candidate_flags", []))
        yafu_probe = {}
        toolkit_runtime_probe = {}
        extracted_artifacts = []
        heavy_lane_plan = {
            "selected_runtime": "local",
            "reason": "Prefer bounded local parsing and arithmetic before escalating into toolkit runtimes.",
            "tool_candidates": [],
        }

        n = rsa_ints.get("n")
        e = rsa_ints.get("e")
        c = rsa_ints.get("c") or rsa_ints.get("cipher")
        p = rsa_ints.get("p")
        q = rsa_ints.get("q")
        d = rsa_ints.get("d")
        phi_value = rsa_ints.get("phi")
        n1 = rsa_ints.get("n1")
        n2 = rsa_ints.get("n2")
        e1 = rsa_ints.get("e1")
        e2 = rsa_ints.get("e2")
        c1 = rsa_ints.get("c1")
        c2 = rsa_ints.get("c2")

        heavy_candidates = []
        modulus_digits = len(str(abs(int(n)))) if n else 0
        if self.toolkit_tool and self.toolkit_tool.is_configured() and subtype == "rsa":
            for name in ["gmpy2", "z3", "pycryptodome", "sympy", "libnum"]:
                if self.toolkit_tool.has_library(name):
                    heavy_candidates.append(name)
            if self.toolkit_tool.has_tool("yafu") and self.toolkit_tool.is_tool_healthy("yafu"):
                heavy_candidates.append("yafu")
            if d or phi_value:
                heavy_lane_plan = {
                    "selected_runtime": "local",
                    "reason": "Private-key material is already present, so direct RSA recovery is cheaper than factorization.",
                    "tool_candidates": heavy_candidates,
                }
            elif n1 and n2 and c1 and c2:
                heavy_lane_plan = {
                    "selected_runtime": "toolkit-python311",
                    "reason": "Shared-prime and common-modulus paths benefit from bounded bigint helpers before generic factorization.",
                    "tool_candidates": heavy_candidates,
                }
            elif e and c and int(e or 0) <= 7 and heavy_candidates:
                heavy_lane_plan = {
                    "selected_runtime": "toolkit-python311",
                    "reason": "Low-exponent RSA is cheap to validate with toolkit bigint helpers.",
                    "tool_candidates": heavy_candidates,
                }
            elif n and e and c and any(name in heavy_candidates for name in ["sympy", "libnum", "gmpy2"]) and 1 <= modulus_digits <= 36:
                heavy_lane_plan = {
                    "selected_runtime": "toolkit-python311",
                    "reason": "Medium-size RSA parameters fit bounded toolkit factoring and integer-to-text helpers.",
                    "tool_candidates": heavy_candidates,
                }
            elif n and e and c and self.toolkit_tool.has_tool("yafu") and self.toolkit_tool.is_tool_healthy("yafu") and modulus_digits >= 18:
                heavy_lane_plan = {
                    "selected_runtime": "yafu",
                    "reason": "Small-factor RSA path exceeded the local trial-factor budget, so factorization sidecar is preferred.",
                    "tool_candidates": heavy_candidates,
                }

        toolkit_runtime_available = bool(
            self.toolkit_tool
            and any(self.toolkit_tool.has_library(name) for name in ["gmpy2", "z3", "pycryptodome", "sympy", "libnum"])
        )
        has_private_key_material = bool((p and q) or d or phi_value)
        has_shared_modulus_inputs = bool(
            ((n and e1 and e2 and c1 and c2) or (n1 and n2 and n1 == n2 and e1 and e2 and c1 and c2))
            and math.gcd(int(e1), int(e2)) == 1
        )
        has_shared_prime_inputs = bool(n1 and n2 and c1 and c2)
        low_e_candidate = bool(e and c and int(e) <= 5)

        if subtype == "rsa":
            if p and q and e and c:
                attacks_attempted.append("rsa-known-primes")
                try:
                    phi = (p - 1) * (q - 1)
                    d = pow(e, -1, phi)
                    plaintext = self._int_to_text(pow(c, d, p * q))
                    if self._crypto_plaintext_confident(plaintext):
                        successful_attacks.append({"name": "rsa-known-primes", "plaintext": plaintext[:240], "details": "p/q supplied", "lane": "local", "tools": []})
                except Exception:
                    pass
            if n and d and c:
                attacks_attempted.append("rsa-private-exponent")
                try:
                    plaintext = self._int_to_text(pow(c, d, n))
                    if self._crypto_plaintext_confident(plaintext):
                        successful_attacks.append({"name": "rsa-private-exponent", "plaintext": plaintext[:240], "details": "d supplied", "lane": "local", "tools": []})
                except Exception:
                    pass
            if n and e and c and phi_value:
                attacks_attempted.append("rsa-phi-supplied")
                try:
                    derived_d = pow(e, -1, phi_value)
                    plaintext = self._int_to_text(pow(c, derived_d, n))
                    if self._crypto_plaintext_confident(plaintext):
                        successful_attacks.append({"name": "rsa-phi-supplied", "plaintext": plaintext[:240], "details": "phi supplied", "lane": "local", "tools": []})
                except Exception:
                    pass
            skip_factor_paths = bool(d or phi_value or (p and q))
            if n and e and c and not skip_factor_paths:
                attacks_attempted.append("rsa-small-factor")
                factor_strategy = ["trial-factor"]
                factors = self._trial_factor(n)
                if (
                    not factors
                    and heavy_lane_plan.get("selected_runtime") == "yafu"
                    and self.toolkit_tool
                    and self.toolkit_tool.has_tool("yafu")
                    and self.toolkit_tool.is_tool_healthy("yafu")
                    and int(n) > 0
                ):
                    factor_strategy.append("yafu")
                    yafu_probe = self.toolkit_tool.run_yafu_factor(n, timeout=45)
                    yafu_payload = (str(yafu_probe.get("stdout", "") or "") + "\n" + str(yafu_probe.get("stderr", "") or "")).strip()
                    if yafu_payload:
                        artifact = workspace / "artifacts" / "crypto_yafu_probe.txt"
                        self.file_tool.write_text(artifact, yafu_payload)
                        extracted_artifacts.append(str(artifact))
                    if yafu_probe.get("status") == "ok":
                        self._record_used_tool(context, "yafu")
                        heavy_lane_plan["executed_runtime"] = "yafu"
                        yafu_factors = list(yafu_probe.get("factors", []))
                        if len(yafu_factors) >= 2:
                            factors = (int(yafu_factors[0]), int(yafu_factors[1]))
                elif not factors and heavy_lane_plan.get("selected_runtime") == "toolkit-python311":
                    factor_strategy.append("toolkit-runtime-factorint")
                heavy_lane_plan["factor_strategy"] = factor_strategy
                if yafu_probe:
                    heavy_lane_plan["probe_status"] = str(yafu_probe.get("status", "") or "")
                    heavy_lane_plan["probe_factor_count"] = len(list(yafu_probe.get("factors", [])))
                if factors:
                    fp, fq = factors
                    try:
                        phi = (fp - 1) * (fq - 1)
                        d = pow(e, -1, phi)
                        plaintext = self._int_to_text(pow(c, d, n))
                        if self._crypto_plaintext_confident(plaintext):
                            successful_attacks.append({"name": "rsa-small-factor", "plaintext": plaintext[:240], "details": "p={0},q={1}".format(fp, fq), "lane": "bounded-heavy" if yafu_probe else "local", "tools": ["yafu"] if yafu_probe else []})
                    except Exception:
                        pass
            if c and e and int(e) <= 5:
                attacks_attempted.append("rsa-low-exponent-root")
                root = self._integer_nth_root(c, int(e))
                if root is not None:
                    plaintext = self._int_to_text(root)
                    if self._crypto_plaintext_confident(plaintext):
                        successful_attacks.append({"name": "rsa-low-exponent-root", "plaintext": plaintext[:240], "details": "exact-root", "lane": "local", "tools": []})

            if ((n and e1 and e2 and c1 and c2) or (n1 and n2 and n1 == n2 and e1 and e2 and c1 and c2)) and math.gcd(int(e1), int(e2)) == 1:
                attacks_attempted.append("rsa-common-modulus")
                shared_n = int(n or n1)
                gcd_value, coeff_a, coeff_b = self._extended_gcd(int(e1), int(e2))
                if gcd_value == 1:
                    try:
                        message = (
                            self._mod_pow_signed(c1, coeff_a, shared_n) * self._mod_pow_signed(c2, coeff_b, shared_n)
                        ) % shared_n
                        plaintext = self._int_to_text(message)
                        if self._crypto_plaintext_confident(plaintext):
                            successful_attacks.append({"name": "rsa-common-modulus", "plaintext": plaintext[:240], "details": "e1={0},e2={1}".format(e1, e2), "lane": "local", "tools": []})
                    except Exception:
                        pass

            if n1 and n2 and c1 and c2:
                attacks_attempted.append("rsa-shared-prime")
                shared_prime = math.gcd(int(n1), int(n2))
                if shared_prime not in {0, 1} and shared_prime not in {n1, n2}:
                    try:
                        left_q = n1 // shared_prime
                        right_q = n2 // shared_prime
                        left_e = int(e1 or e or 65537)
                        right_e = int(e2 or e or 65537)
                        left_d = pow(left_e, -1, (shared_prime - 1) * (left_q - 1))
                        right_d = pow(right_e, -1, (shared_prime - 1) * (right_q - 1))
                        left_plain = self._int_to_text(pow(c1, left_d, n1))
                        right_plain = self._int_to_text(pow(c2, right_d, n2))
                        if self._crypto_plaintext_confident(left_plain):
                            successful_attacks.append({"name": "rsa-shared-prime", "plaintext": left_plain[:240], "details": "n1 shared prime", "lane": "local", "tools": []})
                        if self._crypto_plaintext_confident(right_plain):
                            successful_attacks.append({"name": "rsa-shared-prime", "plaintext": right_plain[:240], "details": "n2 shared prime", "lane": "local", "tools": []})
                    except Exception:
                        pass

            direct_material_solved = any(
                any(token in str(item.get("name", "") or "").lower() for token in ["known-primes", "private-exponent", "phi-supplied"])
                for item in successful_attacks
            )
            low_e_solved = any("low-exponent" in str(item.get("name", "") or "").lower() for item in successful_attacks)
            shared_structure_solved = any(
                any(token in str(item.get("name", "") or "").lower() for token in ["shared-prime", "common-modulus"])
                for item in successful_attacks
            )
            run_toolkit_runtime = False
            if toolkit_runtime_available:
                if has_private_key_material and direct_material_solved:
                    heavy_lane_plan["runtime_skipped_reason"] = "Direct RSA recovery already succeeded from supplied key material."
                elif has_shared_prime_inputs or has_shared_modulus_inputs:
                    run_toolkit_runtime = not shared_structure_solved
                    if not run_toolkit_runtime:
                        heavy_lane_plan["runtime_skipped_reason"] = "Shared-prime/common-modulus path already succeeded locally."
                elif low_e_candidate:
                    run_toolkit_runtime = not low_e_solved
                    if not run_toolkit_runtime:
                        heavy_lane_plan["runtime_skipped_reason"] = "Exact low-exponent root already succeeded locally."
                elif heavy_lane_plan.get("selected_runtime") == "toolkit-python311":
                    run_toolkit_runtime = not successful_attacks
                    if not run_toolkit_runtime:
                        heavy_lane_plan["runtime_skipped_reason"] = "A bounded local RSA attack already succeeded."
            if run_toolkit_runtime:
                attacks_attempted.append("rsa-toolkit-runtime")
                toolkit_runtime_probe = self.toolkit_tool.run_crypto_runtime_probe(
                    {
                        "n": n,
                        "e": e,
                        "c": c,
                        "d": d,
                        "phi": phi_value,
                        "n1": n1,
                        "n2": n2,
                        "e1": e1,
                        "e2": e2,
                        "c1": c1,
                        "c2": c2,
                    },
                    timeout=45,
                )
                runtime_payload = dict(toolkit_runtime_probe.get("probe") or {})
                imports = dict(runtime_payload.get("imports") or {})
                if runtime_payload:
                    artifact = workspace / "artifacts" / "crypto_toolkit_runtime_probe.json"
                    self.file_tool.write_json(artifact, runtime_payload)
                    extracted_artifacts.append(str(artifact))
                    heavy_lane_plan["executed_runtime"] = "toolkit-python311"
                if toolkit_runtime_probe.get("status") == "ok":
                    self._record_used_tool(context, "toolkit-python311")
                    if imports.get("gmpy2") == "ok":
                        self._record_used_tool(context, "gmpy2")
                    if imports.get("z3") == "ok":
                        self._record_used_tool(context, "z3")
                    if imports.get("Crypto") == "ok":
                        self._record_used_tool(context, "pycryptodome")
                    if imports.get("sympy") == "ok":
                        self._record_used_tool(context, "sympy")
                    if imports.get("libnum") == "ok":
                        self._record_used_tool(context, "libnum")
                runtime_tools = [
                    name
                    for name, import_name in [
                        ("gmpy2", "gmpy2"),
                        ("z3", "z3"),
                        ("pycryptodome", "Crypto"),
                        ("sympy", "sympy"),
                        ("libnum", "libnum"),
                    ]
                    if imports.get(import_name) == "ok"
                ]
                heavy_lane_plan["runtime_imports_ok"] = list(runtime_tools)
                for item in list(runtime_payload.get("attacks", [])):
                    if not isinstance(item, dict):
                        continue
                    plaintext = str(item.get("plaintext", "") or "")
                    if self._crypto_plaintext_confident(plaintext):
                        successful_attacks.append(
                            {
                                "name": str(item.get("name", "rsa-toolkit-runtime")),
                                "plaintext": plaintext[:240],
                                "details": str(item.get("details", "toolkit-runtime")),
                                "lane": "bounded-heavy",
                                "tools": list(runtime_tools),
                            }
                        )

        if corpus:
            attacks_attempted.append("rot13")
            rot13_text = codecs.decode(corpus, "rot_13")
            if rot13_text != corpus:
                if self._text_score(rot13_text) >= 0.7:
                    decoded_candidates.append({"kind": "rot13", "token": "corpus", "decoded": rot13_text[:2000], "chain": "text->rot13", "depth": 1})
                for flag in self.verifier.discover_from_text(rot13_text):
                    candidate_flags.append({"value": flag, "source": "crypto:rot13", "confidence": 0.7, "reproducible": False})

            attacks_attempted.append("caesar-bruteforce")
            for item in self._caesar_candidates(corpus, min_score=0.84, limit=6):
                decoded_candidates.append(
                    {
                        "kind": "caesar",
                        "token": "shift:{0}".format(item["shift"]),
                        "decoded": item["text"],
                        "chain": "text->caesar:{0}".format(item["shift"]),
                        "depth": 1,
                        "score": item["score"],
                    }
                )
                for flag in self.verifier.discover_from_text(item["text"]):
                    candidate_flags.append({"value": flag, "source": "crypto:caesar", "confidence": 0.72, "reproducible": False})

            attacks_attempted.append("vigenere-candidates")
            for item in self._vigenere_candidates(corpus, min_score=0.8, limit=5):
                decoded_candidates.append(
                    {
                        "kind": "vigenere",
                        "token": "key:{0}".format(item["key"]),
                        "decoded": item["text"],
                        "chain": "text->vigenere:{0}".format(item["key"]),
                        "depth": 1,
                        "score": item["score"],
                    }
                )
                for flag in self.verifier.discover_from_text(item["text"]):
                    candidate_flags.append({"value": flag, "source": "crypto:vigenere", "confidence": 0.76, "reproducible": False})

        if subtype in {"xor", "encoding", "classic-cipher"}:
            for token, kind in self._extract_encoded_tokens(corpus, limit=8):
                raw = b""
                try:
                    if kind == "hex":
                        raw = binascii.unhexlify(token)
                    elif kind == "base64":
                        raw = base64.b64decode(token + "=" * ((4 - len(token) % 4) % 4), validate=False)
                except Exception:
                    raw = b""
                if not raw:
                    continue
                attacks_attempted.append("single-byte-xor:{0}".format(kind))
                xor_candidates.extend(self._single_byte_xor_candidates(raw, source_kind=kind, min_score=0.86, limit=6))
                attacks_attempted.append("repeating-key-xor:{0}".format(kind))
                xor_candidates.extend(self._repeating_key_xor_candidates(raw, min_score=0.84, limit=6))
            for item in xor_candidates[:12]:
                text_value = item.get("text", "")
                self._scan_text(text_value, "crypto-xor", memory)
                decoded_candidates.append(
                    {
                        "kind": item.get("attack", "xor"),
                        "token": "key:{0}".format(item.get("key", "")),
                        "decoded": text_value[:2000],
                        "chain": item.get("attack", "xor"),
                        "depth": 1,
                        "score": item.get("score", 0.0),
                    }
                )
                for flag in self.verifier.discover_from_text(text_value):
                    candidate_flags.append({"value": flag, "source": "crypto:{0}".format(item.get("attack", "xor")), "confidence": 0.76, "reproducible": False})

        successful_attacks = self._sort_crypto_successful_attacks(successful_attacks)
        heavy_lane_plan["successful_attacks"] = [str(item.get("name", "")) for item in successful_attacks[:6]]
        decoded_candidates = self._dedupe_decoded_candidates(self._filter_decoded_candidates(decoded_candidates, min_score=0.7, limit=20))
        for item in decoded_candidates:
            if item.get("decoded"):
                self._scan_text(item["decoded"], "crypto-decoded", memory)
        for item in successful_attacks:
            plaintext = item.get("plaintext", "")
            self._scan_text(plaintext, "crypto-attack", memory)
            for flag in self.verifier.discover_from_text(plaintext):
                candidate_flags.append({"value": flag, "source": "crypto:{0}".format(item.get("name", "attack")), "confidence": 0.88, "reproducible": True})

        candidate_flags = self._sort_candidate_flags(candidate_flags)
        best_path = "crypto -> {0}".format(subtype)
        if candidate_flags:
            best_path = "flag via {0}".format(candidate_flags[0].get("source", "crypto"))
        elif successful_attacks:
            best_path = "validated attack -> {0}".format(successful_attacks[0].get("name", "attack"))
        elif decoded_candidates:
            best_path = "decode chain -> {0}".format(decoded_candidates[0].get("kind", "decoded"))
        findings = []
        if labeled_params:
            findings.append({"source": "crypto", "summary": "Crypto parameters extracted", "evidence": ", ".join(sorted(labeled_params.keys())[:10]), "confidence": 0.76})
        if decoded_candidates:
            findings.append({"source": "crypto", "summary": "Decoded candidate texts generated", "evidence": "{0} candidates".format(len(decoded_candidates)), "confidence": 0.68})
        if successful_attacks:
            findings.append({"source": "crypto", "summary": "Automatic crypto attack succeeded", "evidence": ", ".join(item.get("name", "") for item in successful_attacks), "confidence": 0.88})
        if xor_candidates:
            findings.append({"source": "crypto", "summary": "XOR candidate plaintexts recovered", "evidence": "{0} candidates".format(len(xor_candidates)), "confidence": 0.71})

        next_actions = {
            "rsa": [
                "Verify shared modulus, shared-prime, leaked p/q/phi, and low-exponent paths before escalating.",
                "Escalate to remote Python or Sage only if bounded arithmetic paths are exhausted.",
            ],
            "prng": ["Recover enough outputs to identify the generator and reconstruct its state or seed."],
            "modern-cipher": ["Confirm mode, IV or nonce reuse, and padding behavior before trying oracles or known-plaintext paths."],
            "classic-cipher": ["Run Caesar/Vigenere and low-cost classical transforms before broader brute force."],
            "xor": ["Prioritize single-byte or repeating-key XOR against printable plaintext hypotheses."],
            "encoding": ["Finish low-cost decode chains first, then escalate to mathematical attacks if required."],
        }.get(subtype, [])

        return {
            "summary": "Subtype={0}; decoded={1}; params={2}; attacks={3}; successes={4}; xor_candidates={5}".format(subtype, len(decoded_candidates), len(labeled_params), len(attacks_attempted), len(successful_attacks), len(xor_candidates)),
            "subtype": subtype,
            "entities": list(self._extract_entities(corpus).get("urls", []))[:8],
            "decoded_candidates": decoded_candidates,
            "best_path": best_path,
            "extracted_artifacts": extracted_artifacts[:8],
            "artifact_name": "crypto_analysis.json",
            "artifact_payload": {
                "subtype": subtype,
                "evidence": evidence,
                "rsa_params": rsa_params,
                "labeled_params": labeled_params,
                "rsa_ints": {key: str(value) for key, value in rsa_ints.items() if value is not None},
                "decoded_candidates": decoded_candidates,
                "attacks_attempted": attacks_attempted,
                "successful_attacks": successful_attacks,
                "attack_count": len(attacks_attempted),
                "success_count": len(successful_attacks),
                "xor_candidates": xor_candidates[:12],
                "openssl_probe": list(openssl_probe.get("results", [])),
                "yafu_probe": dict(yafu_probe or {}),
                "toolkit_runtime_probe": dict(toolkit_runtime_probe.get("probe") or {}),
                "heavy_lane_plan": dict(heavy_lane_plan),
                "candidate_flags": candidate_flags,
                "entity_summary": self._extract_entities(corpus),
                "best_path": best_path,
                "extracted_artifacts": extracted_artifacts,
            },
            "findings": findings,
            "plans": [{"title": "Crypto specialized path", "method": "local-analysis", "url": "attachment://{0}".format(challenge.challenge_id), "notes": "subtype={0}; evidence={1}".format(subtype, ", ".join(evidence) or "heuristic"), "confidence": 0.66}],
            "next_actions": next_actions,
            "recommended_tools": ["python", "run_local_tool"],
            "recommended_path": "crypto-specialized",
            "hypotheses": ["Prioritize the {0} playbook and validate the cheapest local attack path first.".format(subtype)],
            "candidate_flags": candidate_flags,
            "indicators": sorted(labeled_params.keys())[:12],
            "attacks_attempted": attacks_attempted,
            "successful_attacks": successful_attacks,
            "heavy_lane_plan": heavy_lane_plan,
        }

    def _sort_crypto_successful_attacks(self, attacks):
        best_by_plaintext = {}

        def _family_priority(name):
            lowered = str(name or "").lower()
            if "known-primes" in lowered:
                return 0
            if "private-exponent" in lowered:
                return 1
            if "phi-supplied" in lowered:
                return 2
            if "shared-prime" in lowered:
                return 3
            if "common-modulus" in lowered:
                return 4
            if "small-factor" in lowered:
                return 5
            if "low-exponent" in lowered or "exact-root" in lowered:
                return 6
            return 9

        def _sort_key(item):
            name = str(item.get("name", "") or "")
            lane = str(item.get("lane", "") or "")
            tools = list(item.get("tools", []))
            plaintext = str(item.get("plaintext", "") or "")
            return (
                _family_priority(name),
                0 if lane == "local" else 1,
                len(tools),
                -len(plaintext),
                name,
            )

        for item in list(attacks or []):
            if not isinstance(item, dict):
                continue
            plaintext = str(item.get("plaintext", "") or "")
            if not plaintext:
                continue
            existing = best_by_plaintext.get(plaintext)
            if existing is None or _sort_key(item) < _sort_key(existing):
                best_by_plaintext[plaintext] = dict(item)

        return sorted(best_by_plaintext.values(), key=_sort_key)


class ForensicsSolver(_KnowledgeSpecializedSolver):
    CATEGORY = "forensics"
    SOLVER_NAME = "forensics"

    def _run_specialized(self, challenge, workspace, state, memory, context, primary, blobs):
        subtype = "general-artifacts"
        evidence = []
        pcap_names = [item["name"] for item in context.get("attachments", []) if item.get("kind") == "pcap"]
        image_names = [item["name"] for item in context.get("attachments", []) if item.get("kind") == "image"]
        office_names = [item["name"] for item in context.get("attachments", []) if item.get("kind") == "office"]
        binary_names = [item["name"] for item in context.get("attachments", []) if item.get("kind") == "binary"]
        archive_names = [item["name"] for item in context.get("attachments", []) if item.get("kind") == "archive"]
        if pcap_names:
            subtype = "network"
            evidence.append("pcap attachment detected")
        elif image_names:
            subtype = "stego-media"
            evidence.append("image attachment detected")
        elif archive_names:
            subtype = "archive-bundle"
            evidence.append("archive attachment detected")
        elif office_names:
            subtype = "document"
            evidence.append("office/document attachment detected")
        elif binary_names:
            subtype = "memory-or-disk"
            evidence.append("binary/raw attachment detected")

        corpus = "\n".join(item.get("text", "") for item in blobs if item.get("text"))
        entity_summary = self._extract_entities(corpus)
        decoded_candidates = []
        candidate_flags = []
        for blob in blobs[:8]:
            text = blob.get("text", "")
            decoded_candidates.extend(self._recursive_decode_candidates(text, limit=8, max_depth=3))
            decoded_candidates.extend(self._decoded_candidates(text, limit=6))
        decoded_candidates = self._dedupe_decoded_candidates(self._filter_decoded_candidates(decoded_candidates, min_score=0.7, limit=12))
        for item in decoded_candidates:
            decoded_text = item.get("decoded", "")
            if not decoded_text:
                continue
            self._scan_text(decoded_text, "forensics-decoded", memory)
            for flag in self.verifier.discover_from_text(decoded_text):
                candidate_flags.append({"value": flag, "source": "forensics:{0}".format(item.get("kind", "")), "confidence": 0.78, "reproducible": False})

        extra_reports = []
        archive_members = {}
        recovered_objects = []
        pcap_reports = []
        indicators = []
        for attachment in context.get("attachments", []):
            path = Path(attachment.get("path", ""))
            if attachment.get("kind") == "pcap" and path.exists() and self.toolkit_tool and self.toolkit_tool.has_tool("pcapfix"):
                result = self.toolkit_tool.run_pcapfix_probe(path, timeout=45)
                payload = ((result.get("stdout", "") or "") + "\n" + (result.get("stderr", "") or "")).strip()
                status_text = "status={0}\nmessage={1}\ncommand={2}\ntarget={3}".format(
                    result.get("status", "unknown"),
                    result.get("message", ""),
                    result.get("command", ""),
                    result.get("target_path", str(path)),
                )
                artifact = workspace / "artifacts" / "{0}_pcapfix.txt".format(path.stem)
                self.file_tool.write_text(artifact, (payload or status_text))
                extra_reports.append(str(artifact))
                self._record_used_tool(context, "pcapfix")
                self._scan_text((payload or status_text), "{0}-pcapfix".format(path.name), memory)
                recovered_objects.append(
                    {
                        "name": "{0}:pcapfix".format(path.name),
                        "kind": "pcapfix-report",
                        "artifact": str(artifact),
                        "summary": (payload or status_text)[:240],
                    }
                )
                for flag in self.verifier.discover_from_text(payload or status_text):
                    candidate_flags.append({"value": flag, "source": "forensics:pcapfix", "confidence": 0.72, "reproducible": False})
            if attachment.get("kind") == "pcap" and path.exists() and self.toolkit_tool and self.toolkit_tool.has_tool("capinfos"):
                result = self.toolkit_tool.run_capinfos_probe(path, timeout=30)
                payload = ((result.get("stdout", "") or "") + "\n" + (result.get("stderr", "") or "")).strip()
                if payload:
                    artifact = workspace / "artifacts" / "{0}_capinfos.txt".format(path.stem)
                    self.file_tool.write_text(artifact, payload)
                    extra_reports.append(str(artifact))
                    self._record_used_tool(context, "capinfos")
                    self._scan_text(payload, "{0}-capinfos".format(path.name), memory)
                    recovered_objects.append(
                        {
                            "name": "{0}:capinfos".format(path.name),
                            "kind": "capinfos-report",
                            "artifact": str(artifact),
                            "summary": payload[:240],
                        }
                    )
                    for flag in self.verifier.discover_from_text(payload):
                        candidate_flags.append({"value": flag, "source": "forensics:capinfos", "confidence": 0.74, "reproducible": False})
            if attachment.get("kind") == "pcap" and path.exists() and self.toolkit_tool and self.toolkit_tool.has_tool("tshark"):
                result = self.toolkit_tool.run_tshark_probe(path, timeout=45)
                payload = ((result.get("stdout", "") or "") + "\n" + (result.get("stderr", "") or "")).strip()
                if payload:
                    artifact = workspace / "artifacts" / "{0}_tshark.txt".format(path.stem)
                    self.file_tool.write_text(artifact, payload)
                    extra_reports.append(str(artifact))
                    self._record_used_tool(context, "tshark")
                    self._scan_text(payload, "{0}-tshark".format(path.name), memory)
                    recovered_objects.append(
                        {
                            "name": "{0}:tshark".format(path.name),
                            "kind": "tshark-report",
                            "artifact": str(artifact),
                            "summary": payload[:240],
                        }
                    )
                    for line in payload.splitlines()[:80]:
                        fields = [part.strip() for part in line.split("|")]
                        for item in fields:
                            if not item:
                                continue
                            indicators.append(item[:200])
                            for flag in self.verifier.discover_from_text(item):
                                candidate_flags.append({"value": flag, "source": "forensics:tshark", "confidence": 0.76, "reproducible": False})
            if attachment.get("kind") == "pcap" and path.exists() and self.toolkit_tool and self.toolkit_tool.has_tool("strings"):
                result = self.toolkit_tool.run_named_tool("strings", [str(path)], timeout=120)
                artifact = workspace / "artifacts" / "{0}_pcap_strings.txt".format(path.stem)
                payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                self.file_tool.write_text(artifact, payload)
                extra_reports.append(str(artifact))
                self._scan_text(payload, path.name, memory)
                for flag in self.verifier.discover_from_text(payload):
                    candidate_flags.append({"value": flag, "source": "forensics:pcap-strings", "confidence": 0.72, "reproducible": False})
            if attachment.get("kind") == "pcap" and path.exists():
                pcap_report = self._recover_pcap_indicators(path, workspace, prefix=path.stem)
                if pcap_report:
                    pcap_reports.append(pcap_report)
                    if pcap_report.get("artifact"):
                        extra_reports.append(str(pcap_report.get("artifact")))
                    extra_reports.extend(list(pcap_report.get("extra_artifacts", [])))
                    recovered_summary = dict(pcap_report.get("entity_summary") or {})
                    for key in ["urls", "domains", "emails", "ipv4", "handles", "coords", "phones"]:
                        entity_summary[key] = self._unique(list(entity_summary.get(key, [])) + list(recovered_summary.get(key, [])))[:20]
                    excerpt = str(pcap_report.get("text_excerpt", "") or "")
                    if excerpt:
                        self._scan_text(excerpt, "{0}-pcap".format(path.name), memory)
                    for item in list(pcap_report.get("candidate_flags", [])):
                        candidate_flags.append(item)
                    indicators.extend(list(pcap_report.get("indicators", [])))
                    recovered_objects.extend(list(pcap_report.get("recovered_objects", [])))
                    recovered_objects.append(
                        {
                            "name": "{0}:pcap-recovery".format(path.name),
                            "kind": "pcap-recovery",
                            "artifact": str(pcap_report.get("artifact", "")),
                            "summary": ", ".join(list(pcap_report.get("dns_questions", []))[:3] + list(pcap_report.get("urls", []))[:2])[:240],
                        }
                    )
            if attachment.get("kind") == "binary" and path.exists() and self.toolkit_tool and self.toolkit_tool.has_tool("strings"):
                result = self.toolkit_tool.run_named_tool("strings", [str(path)], timeout=120)
                artifact = workspace / "artifacts" / "{0}_binary_strings.txt".format(path.stem)
                payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                self.file_tool.write_text(artifact, payload)
                extra_reports.append(str(artifact))
                self._scan_text(payload, path.name, memory)
                for flag in self.verifier.discover_from_text(payload):
                    candidate_flags.append({"value": flag, "source": "forensics:binary-strings", "confidence": 0.74, "reproducible": False})
            if attachment.get("kind") in {"office", "image"} and path.exists() and self.toolkit_tool and self.toolkit_tool.has_tool("exiftool"):
                result = self.toolkit_tool.run_named_tool("exiftool", [str(path)], timeout=120)
                artifact = workspace / "artifacts" / "{0}_metadata.txt".format(path.stem)
                payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                self.file_tool.write_text(artifact, payload)
                extra_reports.append(str(artifact))
                self._scan_text(payload, path.name, memory)
                for flag in self.verifier.discover_from_text(payload):
                    candidate_flags.append({"value": flag, "source": "forensics:metadata", "confidence": 0.74, "reproducible": False})
            if attachment.get("kind") == "archive" and path.exists():
                extracted = self._extract_archive_objects(path, workspace, memory, context=context)
                if extracted.get("members"):
                    archive_members[path.name] = extracted["members"]
                extra_reports.extend(extracted.get("artifacts", []))
                recovered_objects.extend(extracted.get("objects", []))
                candidate_flags.extend(list(extracted.get("candidate_flags", [])))
            if attachment.get("kind") == "office" and path.exists() and zipfile.is_zipfile(path):
                extracted = self._extract_archive_objects(path, workspace, memory, context=context, prefix="{0}_office".format(path.stem))
                if extracted.get("members"):
                    archive_members[path.name] = extracted["members"]
                extra_reports.extend(extracted.get("artifacts", []))
                recovered_objects.extend(extracted.get("objects", []))
                candidate_flags.extend(list(extracted.get("candidate_flags", [])))
            if (
                path.exists()
                and attachment.get("kind") in {"binary", "image", "archive", "office"}
                and self.toolkit_tool
                and self.toolkit_tool.has_tool("binwalk")
                and path.stat().st_size <= (32 * 1024 * 1024)
            ):
                result = self.toolkit_tool.run_binwalk_scan(path, timeout=45)
                payload = ((result.get("stdout", "") or "") + "\n" + (result.get("stderr", "") or "")).strip()
                if payload:
                    artifact = workspace / "artifacts" / "{0}_forensics_binwalk.txt".format(path.stem)
                    self.file_tool.write_text(artifact, payload)
                    extra_reports.append(str(artifact))
                    self._record_used_tool(context, "binwalk")
                    self._scan_text(payload, "{0}-binwalk".format(path.name), memory)
                    recovered_objects.append(
                        {
                            "name": "{0}:binwalk".format(path.name),
                            "kind": "binwalk-report",
                            "artifact": str(artifact),
                            "summary": payload[:240],
                        }
                    )
                    for flag in self.verifier.discover_from_text(payload):
                        candidate_flags.append({"value": flag, "source": "forensics:binwalk", "confidence": 0.74, "reproducible": False})
                extract_dir = workspace / "artifacts" / "{0}_forensics_binwalk_extract".format(path.stem)
                extract_result = self.toolkit_tool.run_binwalk_extract(path, extract_dir, timeout=60)
                extracted_listing = list(extract_result.get("extracted_files", []) or [])
                if extracted_listing:
                    self._record_used_tool(context, "binwalk")
                    for extracted_name in extracted_listing[:20]:
                        extracted_path = Path(extracted_name)
                        if not extracted_path.exists() or not extracted_path.is_file():
                            continue
                        payload_bytes = b""
                        preview = ""
                        try:
                            preview = self.file_tool.read_text(extracted_path, limit_bytes=131072)
                        except Exception:
                            preview = ""
                        try:
                            if extracted_path.stat().st_size <= 250000:
                                payload_bytes = self.file_tool.read_bytes(extracted_path, limit_bytes=250000)
                        except Exception:
                            payload_bytes = b""
                        if preview:
                            self._scan_text(preview, "{0}-binwalk-extract".format(path.name), memory)
                            for flag in self.verifier.discover_from_text(preview):
                                candidate_flags.append({"value": flag, "source": "forensics:binwalk-extract", "confidence": 0.84, "reproducible": True})
                        if payload_bytes:
                            nested = self._recover_nested_object_bytes(
                                payload_bytes,
                                workspace,
                                prefix="{0}_{1}".format(path.stem, re.sub(r"[^A-Za-z0-9._-]+", "_", extracted_path.stem)[:40]),
                            )
                            extra_reports.extend(list(nested.get("artifacts", [])))
                            recovered_objects.extend(list(nested.get("objects", [])))
                            for item in list(nested.get("candidate_flags", [])):
                                item = dict(item or {})
                                value = str(item.get("value", "") or "").strip()
                                if not value:
                                    continue
                                candidate_flags.append(
                                    {
                                        "value": value,
                                        "source": "forensics:binwalk-extract-nested",
                                        "confidence": max(0.84, float(item.get("confidence", 0.82) or 0.82)),
                                        "reproducible": True,
                                    }
                                )
                        recovered_objects.append(
                            {
                                "name": "{0}:{1}".format(path.name, extracted_path.name),
                                "kind": "binwalk-object",
                                "artifact": str(extracted_path),
                                "summary": (preview or extracted_path.name)[:240],
                            }
                        )
            if path.exists() and attachment.get("kind") in {"binary", "image", "archive", "office"}:
                appended_payloads = self._extract_appended_payloads(path)
                if appended_payloads:
                    artifact = workspace / "artifacts" / "{0}_forensics_appended.json".format(path.stem)
                    self.file_tool.write_json(artifact, appended_payloads)
                    extra_reports.append(str(artifact))
                    for item in appended_payloads:
                        preview = item.get("preview", "")
                        if preview:
                            self._scan_text(preview, "{0}-appended".format(path.name), memory)
                            for flag in self.verifier.discover_from_text(preview):
                                candidate_flags.append({"value": flag, "source": "forensics:appended-{0}".format(item.get("kind", "")), "confidence": 0.82, "reproducible": False})
                        recovered_objects.append(
                            {
                                "name": "{0}:{1}".format(path.name, item.get("kind", "payload")),
                                "kind": "appended-{0}".format(item.get("kind", "payload")),
                                "artifact": str(artifact),
                                "summary": str(item.get("preview", "") or "")[:240],
                            }
                        )
                carved_streams = self._carve_embedded_gzip_streams(path, workspace, prefix="{0}_carve".format(path.stem))
                if carved_streams:
                    artifact = workspace / "artifacts" / "{0}_forensics_gzip_carve.json".format(path.stem)
                    self.file_tool.write_json(artifact, carved_streams)
                    extra_reports.append(str(artifact))
                    for item in carved_streams:
                        preview = item.get("preview", "")
                        if preview:
                            self._scan_text(preview, "{0}-gzip-carve".format(path.name), memory)
                            for flag in self.verifier.discover_from_text(preview):
                                candidate_flags.append({"value": flag, "source": "forensics:gzip-carve", "confidence": 0.84, "reproducible": False})
                        recovered_objects.append(
                            {
                                "name": "{0}:gzip@{1}".format(path.name, item.get("offset", 0)),
                                "kind": "gzip-carve",
                                "artifact": str(item.get("artifact", "")),
                                "summary": str(preview or "")[:240],
                            }
                        )
                carved_archives = self._carve_embedded_zip_objects(path, workspace, prefix="{0}_carve".format(path.stem))
                if carved_archives:
                    artifact = workspace / "artifacts" / "{0}_forensics_zip_carve.json".format(path.stem)
                    self.file_tool.write_json(artifact, carved_archives)
                    extra_reports.append(str(artifact))
                    for item in carved_archives:
                        preview = item.get("preview", "")
                        if preview:
                            self._scan_text(preview, "{0}-zip-carve".format(path.name), memory)
                            for flag in self.verifier.discover_from_text(preview):
                                candidate_flags.append({"value": flag, "source": "forensics:zip-carve", "confidence": 0.84, "reproducible": False})
                        recovered_objects.append(
                            {
                                "name": "{0}:zip@{1}".format(path.name, item.get("offset", 0)),
                                "kind": "zip-carve",
                                "artifact": str(item.get("artifact", "")),
                                "summary": str(preview or "")[:240],
                            }
                        )
            if path.exists() and path.suffix.lower() == ".png":
                png_text_chunks = self._extract_png_text_chunks(path)
                if png_text_chunks:
                    artifact = workspace / "artifacts" / "{0}_forensics_png_text.json".format(path.stem)
                    self.file_tool.write_json(artifact, png_text_chunks)
                    extra_reports.append(str(artifact))
                    for item in png_text_chunks:
                        text_value = item.get("text", "")
                        if text_value:
                            self._scan_text(text_value, "{0}-png-text".format(path.name), memory)
                            for flag in self.verifier.discover_from_text(text_value):
                                candidate_flags.append({"value": flag, "source": "forensics:png-text", "confidence": 0.84, "reproducible": False})
                        recovered_objects.append(
                            {
                                "name": "{0}:{1}".format(path.name, item.get("type", "png-text")),
                                "kind": "png-text",
                                "artifact": str(artifact),
                                "summary": str(text_value or "")[:240],
                            }
                        )
            if (
                path.exists()
                and attachment.get("kind") in {"binary", "archive", "office", "image"}
                and self.toolkit_tool
                and self.toolkit_tool.has_tool("foremost")
                and path.stat().st_size <= (32 * 1024 * 1024)
            ):
                output_dir = workspace / "artifacts" / "{0}_foremost".format(path.stem)
                result = self.toolkit_tool.run_foremost_scan(path, output_dir, timeout=90)
                audit_path = Path(result.get("audit_path", "")) if result.get("audit_path") else None
                recovered_files = [Path(item) for item in list(result.get("recovered_files", []))[:8]]
                if audit_path and audit_path.exists():
                    audit_text = self.file_tool.read_text(audit_path, limit_bytes=200000)
                    extra_reports.append(str(audit_path))
                    self._record_used_tool(context, "foremost")
                    self._scan_text(audit_text, "{0}-foremost".format(path.name), memory)
                    recovered_objects.append(
                        {
                            "name": "{0}:foremost".format(path.name),
                            "kind": "foremost-report",
                            "artifact": str(audit_path),
                            "summary": audit_text[:240],
                        }
                    )
                    for flag in self.verifier.discover_from_text(audit_text):
                        candidate_flags.append({"value": flag, "source": "forensics:foremost", "confidence": 0.72, "reproducible": False})
                for recovered_path in recovered_files:
                    preview = ""
                    if recovered_path.exists() and recovered_path.stat().st_size <= 200000:
                        preview = self._decode_bytes_to_text(self.file_tool.read_bytes(recovered_path, limit_bytes=200000))
                    if preview:
                        self._scan_text(preview, "{0}-foremost-object".format(path.name), memory)
                        for flag in self.verifier.discover_from_text(preview):
                            candidate_flags.append({"value": flag, "source": "forensics:foremost-object", "confidence": 0.78, "reproducible": False})
                    recovered_objects.append(
                        {
                            "name": "{0}:{1}".format(path.name, recovered_path.name),
                            "kind": "foremost-object",
                            "artifact": str(recovered_path),
                            "summary": (preview or recovered_path.name)[:240],
                        }
                    )

        if decoded_candidates:
            artifact = workspace / "artifacts" / "forensics_decoded_candidates.json"
            self.file_tool.write_json(artifact, decoded_candidates)
            extra_reports.append(str(artifact))

        candidate_flags = self._sort_candidate_flags(candidate_flags)
        best_path = "forensics -> {0}".format(subtype)
        if candidate_flags:
            best_path = "flag via {0}".format(candidate_flags[0].get("source", "forensics"))
        elif recovered_objects:
            best_path = "recover objects -> inspect {0}".format(recovered_objects[0].get("kind", "artifact"))
        elif decoded_candidates:
            best_path = "decode embedded blob -> {0}".format(decoded_candidates[0].get("kind", "decoded"))

        findings = []
        for key in ["urls", "domains", "emails", "ipv4"]:
            if entity_summary.get(key):
                findings.append({"source": "forensics", "summary": "Recovered {0}".format(key), "evidence": ", ".join(entity_summary[key][:5]), "confidence": 0.63})
        if recovered_objects:
            findings.append({"source": "forensics", "summary": "Recovered embedded objects", "evidence": "{0} objects".format(len(recovered_objects)), "confidence": 0.69})
        if archive_members:
            findings.append({"source": "forensics", "summary": "Enumerated archive members", "evidence": "{0} containers".format(len(archive_members)), "confidence": 0.64})
        if decoded_candidates:
            findings.append({"source": "forensics", "summary": "Decoded embedded blobs", "evidence": "{0} decoded candidates".format(len(decoded_candidates)), "confidence": 0.71})
        if candidate_flags:
            findings.append({"source": "forensics", "summary": "Recovered candidate flags", "evidence": ", ".join(item.get("value", "") for item in candidate_flags[:3]), "confidence": 0.84})
        if indicators:
            findings.append({"source": "forensics", "summary": "Recovered network indicators", "evidence": ", ".join(self._unique(indicators)[:5]), "confidence": 0.73})

        next_actions_map = {
            "network": ["Extract conversations, hosts, and transferred objects into a minimal timeline.", "Promote suspicious HTTP, DNS, or mail traces into standalone artifacts."],
            "stego-media": ["Check EXIF, thumbnails, channel splits, and hidden payload markers first.", "Switch to dedicated stego tooling only after low-cost checks are exhausted."],
            "archive-bundle": ["Extract member hierarchy, inspect small text members first, and pivot only after recovering the obvious payloads.", "Promote suspicious embedded scripts, URLs, or documents into standalone artifacts."],
            "document": ["Inspect metadata, macros, embedded objects, and revision traces."],
            "memory-or-disk": ["Decide whether this is memory, disk, or a generic binary blob before choosing Volatility or carving."],
            "general-artifacts": ["Finish attachment classification and timeline reconstruction before deeper tooling."],
        }
        return {
            "summary": "Subtype={0}; indicators={1}; extra_reports={2}; recovered_objects={3}; decoded={4}".format(subtype, sum(len(v) for v in entity_summary.values()), len(extra_reports), len(recovered_objects), len(decoded_candidates)),
            "subtype": subtype,
            "indicators": self._unique(
                entity_summary.get("urls", [])
                + entity_summary.get("domains", [])
                + entity_summary.get("emails", [])
                + entity_summary.get("ipv4", [])
                + indicators
            )[:12],
            "decoded_candidates": ["[{0}] {1}".format(item.get("kind", ""), item.get("decoded", "")[:120]) for item in decoded_candidates[:6]],
            "extracted_artifacts": extra_reports[:12],
            "recovered_objects": recovered_objects[:12],
            "best_path": best_path,
            "pcap_reports": pcap_reports[:6],
            "recovered_object_count": len(recovered_objects),
            "http_body_artifact_count": sum(1 for item in recovered_objects if str(item.get("kind", "")).startswith("pcap-http-body")),
            "protocol_hints": self._unique(
                list({request.get("method", "") for report in pcap_reports for request in report.get("http_requests", []) if request.get("method")})
                + ["DNS" for report in pcap_reports if report.get("dns_questions")]
                + [response.get("content_type", "") for report in pcap_reports for response in report.get("http_responses", []) if response.get("content_type")]
            )[:8],
            "artifact_name": "forensics_analysis.json",
            "artifact_payload": {
                "subtype": subtype,
                "evidence": evidence,
                "pcap_attachments": pcap_names,
                "image_attachments": image_names,
                "archive_attachments": archive_names,
                "office_attachments": office_names,
                "binary_attachments": binary_names,
                "entity_summary": entity_summary,
                "pcap_reports": pcap_reports,
                "archive_members": archive_members,
                "recovered_objects": recovered_objects,
                "extra_reports": extra_reports,
                "decoded_candidates": decoded_candidates,
                "candidate_flags": candidate_flags,
                "indicators": self._unique(indicators)[:20],
                "best_path": best_path,
            },
            "findings": findings,
            "plans": [
                {
                    "title": "Forensics specialized path",
                    "method": "artifact-analysis",
                    "url": "attachment://{0}".format(challenge.challenge_id),
                    "notes": best_path,
                    "confidence": 0.68,
                }
            ],
            "next_actions": next_actions_map.get(subtype, []),
            "recommended_tools": ["exiftool", "strings", "run_local_tool"],
            "recommended_path": "forensics-specialized",
            "subpaths": extra_reports[:6],
            "candidate_flags": candidate_flags,
        }

    def _extract_archive_objects(self, path, workspace, memory, context=None, prefix=""):
        path = Path(path)
        artifact_root = workspace / "artifacts"
        safe_prefix = prefix or path.stem
        members = []
        artifacts = []
        objects = []
        candidate_flags = []

        def record_member(name, size):
            entry = {"name": name, "size": int(size)}
            members.append(entry)
            return entry

        def persist_preview(member_name, payload_bytes):
            text = self._decode_bytes_to_text(payload_bytes)
            if not text or self._text_score(text) < 0.72:
                nested = self._recover_nested_object_bytes(payload_bytes, workspace, prefix="{0}_{1}".format(safe_prefix, member_name))
                artifacts.extend(list(nested.get("artifacts", [])))
                objects.extend(list(nested.get("objects", [])))
                candidate_flags.extend(list(nested.get("candidate_flags", [])))
                return
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", member_name)[:80]
            artifact = artifact_root / "{0}_{1}_preview.txt".format(safe_prefix, safe_name)
            self.file_tool.write_text(artifact, text[:120000])
            artifacts.append(str(artifact))
            self._scan_text(text, member_name, memory)
            objects.append({"name": member_name, "kind": "text-preview", "artifact": str(artifact), "summary": text[:240]})
            for flag in self.verifier.discover_from_text(text):
                candidate_flags.append({"value": flag, "source": "forensics:archive-preview", "confidence": 0.78, "reproducible": False})
            nested = self._recover_nested_object_bytes(payload_bytes, workspace, prefix="{0}_{1}".format(safe_prefix, member_name))
            artifacts.extend(list(nested.get("artifacts", [])))
            objects.extend(list(nested.get("objects", [])))
            candidate_flags.extend(list(nested.get("candidate_flags", [])))

        if self.toolkit_tool and self.toolkit_tool.has_tool("7z"):
            result = self.toolkit_tool.list_archive_with_7z(path, timeout=45)
            listing_text = ((result.get("stdout", "") or "") + "\n" + (result.get("stderr", "") or "")).strip()
            status = str(result.get("status", "error") or "error")
            if listing_text:
                artifact = artifact_root / "{0}_7z_listing.txt".format(safe_prefix)
                self.file_tool.write_text(artifact, listing_text)
                artifacts.append(str(artifact))
                self._record_used_tool(context, "7z")
                memory.record_action("extract", "7z list {0}".format(path.name), status, "archive listing", str(artifact))
                self._scan_text(listing_text, path.name, memory)
                for flag in self.verifier.discover_from_text(listing_text):
                    candidate_flags.append({"value": flag, "source": "forensics:archive-7z", "confidence": 0.78, "reproducible": False})
                for line in list(result.get("entries_preview", [])):
                    if not str(line).startswith("Path = "):
                        continue
                    member_name = str(line).split("=", 1)[1].strip()
                    if member_name and member_name != path.name and not any(item.get("name") == member_name for item in members):
                        record_member(member_name, 0)
            elif status not in {"missing", "skipped"}:
                memory.record_action("extract", "7z list {0}".format(path.name), status, result.get("message", "archive listing"))
            if path.stat().st_size <= (32 * 1024 * 1024):
                extract_dir = artifact_root / "{0}_7z_extract".format(safe_prefix)
                extract_result = self.toolkit_tool.extract_archive_with_7z(path, extract_dir, timeout=75)
                extracted_files = [Path(item) for item in list(extract_result.get("extracted_files", []))[:20]]
                if extracted_files:
                    self._record_used_tool(context, "7z")
                    memory.record_action(
                        "extract",
                        "7z extract {0}".format(path.name),
                        extract_result.get("status", "unknown"),
                        "archive extraction",
                        str(extract_dir),
                    )
                    for recovered_path in extracted_files[:10]:
                        relative_name = str(recovered_path.relative_to(extract_dir)) if recovered_path.exists() else recovered_path.name
                        if not any(item.get("name") == relative_name for item in members):
                            try:
                                record_member(relative_name, recovered_path.stat().st_size)
                            except Exception:
                                record_member(relative_name, 0)
                        if not recovered_path.exists() or recovered_path.stat().st_size > 200000:
                            continue
                        payload = self.file_tool.read_bytes(recovered_path, limit_bytes=200000)
                        persist_preview(relative_name, payload)

        if zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist()[:24]:
                        record_member(info.filename, info.file_size)
                        if info.is_dir() or info.file_size > 200000:
                            continue
                        payload = archive.read(info)
                        persist_preview(info.filename, payload)
            except Exception:
                return {"members": members, "artifacts": artifacts, "objects": objects, "candidate_flags": candidate_flags}
            return {"members": members, "artifacts": artifacts, "objects": objects, "candidate_flags": candidate_flags}

        try:
            if tarfile.is_tarfile(path):
                with tarfile.open(path) as archive:
                    for info in archive.getmembers()[:24]:
                        record_member(info.name, info.size)
                        if not info.isfile() or info.size > 200000:
                            continue
                        extracted = archive.extractfile(info)
                        payload = extracted.read() if extracted else b""
                        if payload:
                            persist_preview(info.name, payload)
                return {"members": members, "artifacts": artifacts, "objects": objects, "candidate_flags": candidate_flags}
        except Exception:
            pass

        if path.suffix.lower() == ".gz":
            try:
                payload = gzip.decompress(path.read_bytes())
                record_member(path.stem, len(payload))
                persist_preview(path.stem, payload)
            except Exception:
                pass
        return {"members": members, "artifacts": artifacts, "objects": objects, "candidate_flags": candidate_flags}


class OsintSolver(_KnowledgeSpecializedSolver):
    CATEGORY = "osint"
    SOLVER_NAME = "osint"
    MAX_FETCHES = 20
    MAX_DEPTH = 2

    def _build_local_osint_reports(self, blobs):
        attachment_reports = []
        browser_reports = []
        html_suffixes = {".html", ".htm"}
        js_suffixes = {".js", ".mjs"}
        blob_index = {}
        for blob in list(blobs or []):
            name = str(blob.get("source_name", "") or blob.get("name", "") or "").strip()
            if name:
                blob_index[Path(name).name.lower()] = blob
        for blob in list(blobs or []):
            name = str(blob.get("source_name", "") or blob.get("name", "") or "").strip()
            text = str(blob.get("text", "") or "")
            if not name or not text:
                continue
            suffix = Path(name).suffix.lower()
            if suffix not in html_suffixes:
                continue
            summary = {"title": "", "links": [], "scripts": [], "forms": []}
            if self.http_tool:
                try:
                    summary = dict(self.http_tool.summarize_html(text, name) or {})
                except Exception:
                    summary = {"title": "", "links": [], "scripts": [], "forms": []}
            combined = "\n".join(
                [
                    summary.get("title", ""),
                    text,
                    "\n".join(summary.get("links", [])),
                    "\n".join(summary.get("scripts", [])),
                ]
            )
            lowered = combined.lower()
            dynamic_hint = (
                len(list(summary.get("scripts", []))) >= 1
                or "__next" in lowered
                or "__nuxt" in lowered
                or "window.__" in lowered
                or "string.fromcharcode" in lowered
                or "graphql" in lowered
                or "/api/" in lowered
            )
            attachment_reports.append(
                {
                    "type": "attachment-html",
                    "name": name,
                    "title": summary.get("title", ""),
                    "links": list(summary.get("links", []))[:10],
                    "scripts": list(summary.get("scripts", []))[:10],
                    "forms": list(summary.get("forms", []))[:4],
                    "entity_summary": self._extract_entities(combined),
                    "body_excerpt": text[:4000],
                    "dynamic_hint": dynamic_hint,
                }
            )
            if not dynamic_hint:
                continue
            related_names = []
            related_texts = []
            for script in list(summary.get("scripts", []))[:10]:
                script_name = Path(urlparse(str(script or "")).path or str(script or "")).name.lower()
                if script_name:
                    related_names.append(script_name)
            for candidate_name, candidate_blob in sorted(blob_index.items()):
                if Path(candidate_name).suffix.lower() not in js_suffixes:
                    continue
                if related_names and candidate_name not in related_names:
                    continue
                script_text = str(candidate_blob.get("text", "") or "")
                if not script_text:
                    continue
                related_texts.append(script_text)
            if not related_texts:
                continue
            browser_text = "\n".join([combined] + related_texts[:4])
            browser_reports.append(
                {
                    "server": "attachment",
                    "tool": "local-dynamic",
                    "attachment": name,
                    "structured": {
                        "summary": "Local attachment dynamic reconstruction",
                        "route_candidates": list(summary.get("links", []))[:10],
                        "param_candidates": [],
                    },
                    "text": browser_text[:8000],
                    "summary": "attachment dynamic bundle",
                }
            )
        return attachment_reports, browser_reports

    def _run_specialized(self, challenge, workspace, state, memory, context, primary, blobs):
        seed_summary = self._build_osint_seed_entities(challenge, blobs)
        subtype = "general-web"
        evidence = []
        if seed_summary.get("coords"):
            subtype = "geo-media"
            evidence.append("coordinate indicators detected")
        elif seed_summary.get("handles") or seed_summary.get("emails"):
            subtype = "social-media"
            evidence.append("social/account indicators detected")
        elif seed_summary.get("domains") or seed_summary.get("urls"):
            subtype = "web-and-dns"
            evidence.append("domain/url indicators detected")

        nodes = []
        node_index = {}
        edges = []
        edge_seen = set()
        seed_entities = []
        pivot_entities = []
        fetch_reports = []
        browser_reports = []
        candidate_flags = []
        queue = []
        visited_urls = set()
        visited_domains = set()

        def queue_priority(item):
            entity_type = str(item.get("type", ""))
            depth = int(item.get("depth", 0) or 0)
            source = str(item.get("source", "") or "")
            base = 100
            if entity_type == "url":
                base = 0
            elif entity_type == "domain":
                base = 8
            elif entity_type in {"email", "handle"}:
                base = 16
            elif entity_type == "coords":
                base = 24
            if source.startswith("browser:"):
                base += 6
            elif source.startswith("dns"):
                base += 4
            elif source and source != "seed":
                base += 2
            return (depth, base, str(item.get("value", "")))

        for item in self._entity_summary_to_nodes(seed_summary, source="seed", depth=0):
            key = self._append_graph_node(nodes, node_index, item["type"], item["value"], 0, source="seed", evidence=item.get("evidence", "seed"))
            if key:
                seed_entities.append({"type": item["type"], "value": self._normalize_osint_entity(item["type"], item["value"])})
                if item["type"] in {"url", "domain"}:
                    queue.append({"type": item["type"], "value": item["value"], "depth": 0, "source_key": key, "source": "seed"})

        attachment_reports, local_browser_reports = self._build_local_osint_reports(blobs)
        for report in attachment_reports:
            fetch_reports.append(report)
            self._record_used_tool(context, "attachment-html")
            attachment_name = str(report.get("name", "") or "attachment")
            text_blob = "\n".join(
                [
                    report.get("title", ""),
                    report.get("body_excerpt", ""),
                    "\n".join(report.get("links", [])),
                    "\n".join(report.get("scripts", [])),
                ]
            )
            charcode_hits = self._decode_charcode_sequences(text_blob, limit=6)
            if charcode_hits:
                text_blob = "\n".join([text_blob] + charcode_hits)
            self._scan_text(text_blob, "osint-attachment", memory)
            for flag in self.verifier.discover_from_text(text_blob):
                candidate_flags.append({"value": flag, "source": "osint:http:attachment:{0}".format(attachment_name), "confidence": 0.8, "reproducible": False})
            discovered = self._entity_summary_to_nodes(report.get("entity_summary", {}), source="attachment:{0}".format(attachment_name), depth=1)
            for item in discovered:
                entity_key = self._append_graph_node(nodes, node_index, item["type"], item["value"], 1, source="attachment:{0}".format(attachment_name), evidence="attachment scan")
                if entity_key:
                    pivot_entities.append({"type": item["type"], "value": self._normalize_osint_entity(item["type"], item["value"]), "source": "attachment:{0}".format(attachment_name), "depth": 1})
                    if item["type"] in {"url", "domain"} and len(fetch_reports) < self.MAX_FETCHES:
                        queue.append({"type": item["type"], "value": item["value"], "depth": 1, "source_key": entity_key, "source": "attachment:{0}".format(attachment_name)})

        for browser_report in local_browser_reports:
            browser_reports.append(browser_report)
            self._record_used_tool(context, "attachment-dynamic")
            attachment_name = str(browser_report.get("attachment", "") or "attachment")
            browser_text = "\n".join(
                [
                    str((browser_report.get("structured") or {}).get("summary", "") or ""),
                    str(browser_report.get("text", "") or ""),
                    "\n".join(list((browser_report.get("structured") or {}).get("route_candidates", []))),
                    "\n".join(list((browser_report.get("structured") or {}).get("param_candidates", []))),
                ]
            )
            charcode_hits = self._decode_charcode_sequences(browser_text, limit=6)
            if charcode_hits:
                browser_text = "\n".join([browser_text] + charcode_hits)
            self._scan_text(browser_text, "osint-attachment-browser", memory)
            for flag in self.verifier.discover_from_text(browser_text):
                candidate_flags.append({"value": flag, "source": "osint:browser:attachment:{0}".format(attachment_name), "confidence": 0.84, "reproducible": False})
            browser_entities = self._entity_summary_to_nodes(self._extract_entities(browser_text), source="attachment-browser:{0}".format(attachment_name), depth=1)
            for item in browser_entities:
                entity_key = self._append_graph_node(nodes, node_index, item["type"], item["value"], 1, source="attachment-browser:{0}".format(attachment_name), evidence="attachment dynamic")
                if entity_key:
                    pivot_entities.append({"type": item["type"], "value": self._normalize_osint_entity(item["type"], item["value"]), "source": "attachment-browser:{0}".format(attachment_name), "depth": 1})
                    if item["type"] in {"url", "domain"} and len(fetch_reports) < self.MAX_FETCHES:
                        queue.append({"type": item["type"], "value": item["value"], "depth": 1, "source_key": entity_key, "source": "attachment-browser:{0}".format(attachment_name)})

        while queue and len(fetch_reports) < self.MAX_FETCHES:
            queue.sort(key=queue_priority)
            current = queue.pop(0)
            depth = int(current.get("depth", 0))
            if depth > self.MAX_DEPTH:
                continue

            if current.get("type") == "url":
                normalized_url = self._normalize_osint_entity("url", current.get("value"))
                if not normalized_url or normalized_url in visited_urls:
                    continue
                visited_urls.add(normalized_url)
                report = self._fetch_osint_url(normalized_url, depth=depth)
                fetch_reports.append(report)
                self._record_used_tool(context, "http")
                memory.record_action("specialized", "osint fetch {0}".format(normalized_url), "ok" if report.get("status") else "error", "entity correlation")
                text_blob = "\n".join(
                    [
                        report.get("title", ""),
                        report.get("body_excerpt", ""),
                        "\n".join(report.get("links", [])),
                        "\n".join(report.get("scripts", [])),
                    ]
                )
                self._scan_text(text_blob, normalized_url, memory)
                for flag in self.verifier.discover_from_text(text_blob):
                    candidate_flags.append({"value": flag, "source": "osint:http:{0}".format(normalized_url), "confidence": 0.8, "reproducible": False})

                discovered = self._entity_summary_to_nodes(report.get("entity_summary", {}), source=normalized_url, depth=depth + 1)
                for item in discovered:
                    entity_key = self._append_graph_node(nodes, node_index, item["type"], item["value"], depth + 1, source=normalized_url, evidence="http fetch")
                    self._append_graph_edge(edges, edge_seen, current.get("source_key"), entity_key, "http-discovery")
                    if entity_key:
                        pivot_entities.append({"type": item["type"], "value": self._normalize_osint_entity(item["type"], item["value"]), "source": normalized_url, "depth": depth + 1})
                        if depth + 1 <= self.MAX_DEPTH and item["type"] in {"url", "domain"}:
                            queue.append({"type": item["type"], "value": item["value"], "depth": depth + 1, "source_key": entity_key, "source": normalized_url})

                if report.get("dynamic_hint") and self.mcp_registry and self.mcp_registry.has_servers():
                    browser_report = self._browser_osint_recon(normalized_url)
                    if browser_report:
                        browser_reports.append(browser_report)
                        if browser_report.get("server") and browser_report.get("tool"):
                            self._record_used_tool(context, "browser-use")
                            self._record_used_mcp(context, "{0}::{1}".format(browser_report["server"], browser_report["tool"]))
                        structured = dict(browser_report.get("structured") or {})
                        browser_text = "\n".join(
                            [
                                structured.get("summary", ""),
                                browser_report.get("text", ""),
                                "\n".join(structured.get("route_candidates", [])),
                                "\n".join(structured.get("param_candidates", [])),
                            ]
                        )
                        charcode_hits = self._decode_charcode_sequences(browser_text, limit=6)
                        if charcode_hits:
                            browser_text = "\n".join([browser_text] + charcode_hits)
                        self._scan_text(browser_text, "osint-browser", memory)
                        for flag in self.verifier.discover_from_text(browser_text):
                            candidate_flags.append({"value": flag, "source": "osint:browser:{0}".format(normalized_url), "confidence": 0.82, "reproducible": False})
                        browser_entities = self._entity_summary_to_nodes(self._extract_entities(browser_text), source="browser:{0}".format(normalized_url), depth=depth + 1)
                        for item in browser_entities:
                            entity_key = self._append_graph_node(nodes, node_index, item["type"], item["value"], depth + 1, source="browser:{0}".format(normalized_url), evidence="browser recon")
                            self._append_graph_edge(edges, edge_seen, current.get("source_key"), entity_key, "browser-discovery")
                            if entity_key:
                                pivot_entities.append({"type": item["type"], "value": self._normalize_osint_entity(item["type"], item["value"]), "source": normalized_url, "depth": depth + 1})
                                if depth + 1 <= self.MAX_DEPTH and item["type"] in {"url", "domain"}:
                                    queue.append({"type": item["type"], "value": item["value"], "depth": depth + 1, "source_key": entity_key, "source": "browser:{0}".format(normalized_url)})

            elif current.get("type") == "domain":
                normalized_domain = self._normalize_osint_entity("domain", current.get("value"))
                if not normalized_domain or normalized_domain in visited_domains:
                    continue
                visited_domains.add(normalized_domain)
                dns_report = self._resolve_dns_records(normalized_domain)
                fetch_reports.append(
                    {
                        "type": "dns",
                        "depth": depth,
                        "domain": normalized_domain,
                        "a_records": dns_report.get("a_records", []),
                        "txt_records": dns_report.get("txt_records", []),
                        "mx_records": dns_report.get("mx_records", []),
                        "ns_records": dns_report.get("ns_records", []),
                    }
                )
                for target_type, values in [("ipv4", dns_report.get("a_records", [])), ("domain", dns_report.get("mx_records", [])), ("domain", dns_report.get("ns_records", []))]:
                    for value in values[:10]:
                        entity_key = self._append_graph_node(nodes, node_index, target_type, value, depth + 1, source=normalized_domain, evidence="dns")
                        self._append_graph_edge(edges, edge_seen, current.get("source_key"), entity_key, "dns")
                        if entity_key:
                            pivot_entities.append({"type": target_type, "value": self._normalize_osint_entity(target_type, value), "source": normalized_domain, "depth": depth + 1})
                for txt_value in dns_report.get("txt_records", [])[:10]:
                    self._scan_text(txt_value, "osint-dns", memory)
                    for flag in self.verifier.discover_from_text(txt_value):
                        candidate_flags.append({"value": flag, "source": "osint:dns:{0}".format(normalized_domain), "confidence": 0.84, "reproducible": False})
                if depth < self.MAX_DEPTH and len(fetch_reports) < self.MAX_FETCHES:
                    candidate_url = "https://{0}".format(normalized_domain)
                    if candidate_url not in visited_urls:
                        queue.append({"type": "url", "value": candidate_url, "depth": depth + 1, "source_key": current.get("source_key"), "source": "dns:{0}".format(normalized_domain)})

        candidate_flags = self._sort_candidate_flags(candidate_flags)
        pivot_values = self._unique(["{0}:{1}".format(item.get("type", ""), item.get("value", "")) for item in pivot_entities if item.get("value")])[:20]
        suspicious_entities = self._unique([node.get("value", "") for node in nodes if node.get("type") in {"handle", "email", "coords", "domain"}])[:5]
        best_path = "seed -> entity correlation"
        if candidate_flags:
            best_path = "flag via {0}".format(candidate_flags[0].get("source", "osint"))
        elif browser_reports:
            best_path = "seed -> browser recon -> dynamic entities"
        elif any(item.get("type") == "dns" for item in fetch_reports):
            best_path = "seed -> DNS pivot -> web root"
        elif fetch_reports:
            best_path = "seed -> fetch -> linked entities"

        findings = []
        for key in ["handles", "emails", "domains", "urls", "coords"]:
            values = seed_summary.get(key, [])
            if values:
                findings.append({"source": "osint", "summary": "Recovered {0}".format(key), "evidence": ", ".join(values[:5]), "confidence": 0.64})
        findings.append({"source": "osint", "summary": "OSINT entity graph expanded", "evidence": "seed={0}, pivots={1}, fetches={2}".format(len(seed_entities), len(pivot_values), len(fetch_reports)), "confidence": 0.72})
        if browser_reports:
            findings.append({"source": "osint", "summary": "Browser-assisted OSINT used", "evidence": "{0} browser reports".format(len(browser_reports)), "confidence": 0.68})

        return {
            "summary": "Subtype={0}; seeds={1}; pivots={2}; budget={3}/{4}".format(subtype, len(seed_entities), len(pivot_values), len(fetch_reports), self.MAX_FETCHES),
            "subtype": subtype,
            "seed_entities": seed_entities[:20],
            "entities": self._unique([item["value"] for item in seed_entities[:8]] + suspicious_entities)[:12],
            "pivot_entities": pivot_values[:12],
            "entity_graph": {"nodes": nodes[:200], "edges": edges[:300]},
            "fetch_reports": fetch_reports[:12],
            "browser_reports": browser_reports[:6],
            "entity_count": len(nodes),
            "pivot_count": len(pivot_values),
            "budget_used": len(fetch_reports),
            "best_path": best_path,
            "artifact_name": "osint_analysis.json",
            "artifact_payload": {
                "subtype": subtype,
                "evidence": evidence,
                "seed_entities": seed_entities,
                "pivot_entities": pivot_values,
                "seed_count": len(seed_entities),
                "entity_count": len(nodes),
                "pivot_count": len(pivot_values),
                "budget_used": len(fetch_reports),
                "entity_graph": {"nodes": nodes[:200], "edges": edges[:300]},
                "fetch_reports": fetch_reports,
                "browser_reports": browser_reports,
                "browser_report_count": len(browser_reports),
                "candidate_flags": candidate_flags,
                "best_path": best_path,
                "budget": {"fetch_limit": self.MAX_FETCHES, "fetch_used": len(fetch_reports), "pivot_limit": self.MAX_DEPTH, "entity_cap_per_type": 10},
                "suspicious_entities": suspicious_entities,
            },
            "findings": findings,
            "plans": [
                {
                    "title": "OSINT specialized path",
                    "method": "entity-correlation",
                    "url": challenge.target or "attachment://{0}".format(challenge.challenge_id),
                    "notes": best_path,
                    "confidence": 0.7,
                }
            ],
            "next_actions": [
                "Prioritize the highest-signal entity chain and validate each pivot with source evidence.",
                "Stop broad crawling once the best path stabilizes or the fetch budget is exhausted.",
            ],
            "recommended_tools": ["browser", "run_local_tool"],
            "recommended_mcp": ["browser-use"] if any(str(item.get("server", "") or "").lower() not in {"", "attachment"} for item in browser_reports) or challenge.target else [],
            "recommended_path": "osint-specialized",
            "candidate_flags": candidate_flags,
            "indicators": suspicious_entities,
        }


class MalwareSolver(_KnowledgeSpecializedSolver):
    CATEGORY = "malware"
    SOLVER_NAME = "malware"

    def _run_specialized(self, challenge, workspace, state, memory, context, primary, blobs):
        subtype = "binary-sample"
        evidence = []
        iocs = []
        decoded_candidates = []
        suspicious_apis = []
        persistence_indicators = []
        stages = []
        config_blobs = []
        candidate_flags = []
        findings = []

        stage_api_markers = [
            "virtualalloc",
            "writeprocessmemory",
            "createprocess",
            "winexec",
            "urldownloadtofile",
            "httpopenrequest",
            "internetopenurl",
            "downloadstring",
            "invoke-webrequest",
            "start-bitstransfer",
            "regsvr32",
            "schtasks",
            "rundll32",
            "mshta",
            "webclient",
            "curl.exe",
        ]
        persistence_markers = ["\\currentversion\\run", "runonce", "startup", "schtasks", "bitsadmin", "wmi", "service", "regsvr32", "rundll32", "mshta"]

        def collect_text(text, source_tag):
            if not text:
                return
            lowered_text = text.lower()
            entities = self._extract_entities(text)
            iocs.extend(entities.get("urls", []) + entities.get("domains", []) + entities.get("ipv4", []))
            config_blobs.extend(self._extract_config_blobs(text))
            for api_name in stage_api_markers:
                if api_name in lowered_text:
                    suspicious_apis.append(api_name)
            for marker in persistence_markers:
                if marker in lowered_text:
                    persistence_indicators.append(marker)
            self._scan_text(text, source_tag, memory)
            for flag in self.verifier.discover_from_text(text):
                candidate_flags.append({"value": flag, "source": "malware:{0}".format(source_tag), "confidence": 0.82, "reproducible": False})

        for attachment in context.get("attachments", []):
            name = attachment.get("name", "").lower()
            kind = attachment.get("kind")
            path = Path(attachment.get("path", ""))
            text = ""
            if attachment.get("artifact") and Path(attachment["artifact"]).exists():
                text = self.file_tool.read_text(Path(attachment["artifact"]), limit_bytes=120000)
            elif path.exists() and kind == "text":
                text = self.file_tool.read_text(path, limit_bytes=120000)

            if name.endswith((".ps1", ".vbs", ".js", ".bat", ".hta", ".cmd")) or kind == "text":
                subtype = "script-or-obfuscated"
                evidence.append("script-like attachment detected")
            if text:
                lowered_text = text.lower()
                if any(token in lowered_text for token in ["frombase64string", "powershell -enc", "iex(", "invoke-expression", "charcode", "xor", "compressedstream", "deflate"]):
                    evidence.append("obfuscation markers detected")
                decoded_candidates.extend(self._recursive_decode_candidates(text, limit=10, max_depth=4))
                stages.extend(self._extract_powershell_stages(text))
                stages.extend(self._recover_nested_stage_candidates(text, max_depth=4, limit=10))
                collect_text(text, attachment.get("name", "malware"))

        expanded_stages = []
        for stage in list(stages)[:16]:
            stage_text = stage.get("decoded", "")
            if not stage_text:
                continue
            expanded_stages.append(dict(stage))
            collect_text(stage_text, "stage")
            decoded_candidates.extend(self._recursive_decode_candidates(stage_text, limit=8, max_depth=3))
            decoded_candidates.extend(self._recover_nested_stage_candidates(stage_text, max_depth=3, limit=8))
        stages = expanded_stages

        decoded_candidates = self._dedupe_decoded_candidates(self._filter_decoded_candidates(decoded_candidates, min_score=0.68, limit=16))
        self._maybe_add_flag_candidates(decoded_candidates, memory, "malware")
        for item in decoded_candidates:
            decoded_text = item.get("decoded", "")
            collect_text(decoded_text, "decoded")
            for flag in self.verifier.discover_from_text(decoded_text):
                candidate_flags.append({"value": flag, "source": "malware:decoded", "confidence": 0.72, "reproducible": False})

        iocs = self._unique(iocs)
        suspicious_apis = self._unique(suspicious_apis)
        persistence_indicators = self._unique(persistence_indicators)
        config_blobs = [dict(item) for item in config_blobs if isinstance(item, dict)]
        deduped_configs = []
        seen_configs = set()
        for item in config_blobs:
            marker = item.get("summary", "")
            if not marker or marker in seen_configs:
                continue
            seen_configs.add(marker)
            deduped_configs.append(item)
        config_blobs = sorted(
            deduped_configs,
            key=lambda item: (
                1 if self.verifier.discover_from_text(item.get("summary", "")) else 0,
                sum(1 for token in ["http", "c2", "mutex", "registry", "user_agent", "run", "startup"] if token in item.get("summary", "").lower()),
                len(item.get("summary", "")),
            ),
            reverse=True,
        )[:12]

        if suspicious_apis:
            evidence.append("suspicious APIs detected")
        if persistence_indicators:
            evidence.append("persistence markers detected")
        if config_blobs:
            evidence.append("config-like blobs recovered")

        if iocs:
            findings.append({"source": "malware", "summary": "Recovered IOC candidates", "evidence": ", ".join(iocs[:6]), "confidence": 0.73})
        if suspicious_apis:
            findings.append({"source": "malware", "summary": "Suspicious API usage", "evidence": ", ".join(suspicious_apis[:6]), "confidence": 0.68})
        if stages:
            findings.append({"source": "malware", "summary": "Recovered embedded stages", "evidence": "{0} stages".format(len(stages)), "confidence": 0.75})
        if persistence_indicators:
            findings.append({"source": "malware", "summary": "Persistence indicators recovered", "evidence": ", ".join(persistence_indicators[:6]), "confidence": 0.7})
        if config_blobs:
            findings.append({"source": "malware", "summary": "Recovered config-like blobs", "evidence": "{0} blobs".format(len(config_blobs)), "confidence": 0.72})

        candidate_flags = self._sort_candidate_flags(candidate_flags)
        next_actions = [
            "Extract the most stable config, C2, and persistence indicators into artifacts first.",
            "Only escalate to deeper reversing after stage recovery and IOC extraction plateau.",
        ]
        if subtype == "script-or-obfuscated":
            next_actions.insert(0, "Strip the script wrapper first, then classify the final payload behavior.")

        return {
            "summary": "Subtype={0}; iocs={1}; decoded={2}; apis={3}; stages={4}; persistence={5}; configs={6}".format(subtype, len(iocs), len(decoded_candidates), len(suspicious_apis), len(stages), len(persistence_indicators), len(config_blobs)),
            "subtype": subtype,
            "iocs": iocs[:12],
            "decoded_candidates": decoded_candidates,
            "artifact_name": "malware_analysis.json",
            "artifact_payload": {
                "subtype": subtype,
                "evidence": evidence,
                "iocs": iocs,
                "decoded_candidates": decoded_candidates,
                "suspicious_apis": suspicious_apis,
                "stages": stages,
                "config_blobs": config_blobs,
                "persistence_indicators": persistence_indicators,
                "candidate_flags": candidate_flags,
            },
            "findings": findings,
            "plans": [{"title": "Malware specialized path", "method": "ioc-and-config-recovery", "url": "attachment://{0}".format(challenge.challenge_id), "notes": "subtype={0}".format(subtype), "confidence": 0.69}],
            "next_actions": next_actions,
            "recommended_tools": ["strings", "run_local_tool", "ida64"],
            "recommended_mcp": ["ida-pro-mcp", "ghidra-mcp"],
            "recommended_path": "malware-specialized",
            "candidate_flags": candidate_flags,
            "indicators": self._unique(iocs + suspicious_apis + persistence_indicators)[:20],
            "config_blobs": config_blobs,
            "stages": stages,
        }

    def _extract_powershell_stages(self, text):
        stages = []
        text = text or ""
        for match in re.findall(r"(?i)(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{16,})", text):
            try:
                raw = base64.b64decode(match + "=" * ((4 - len(match) % 4) % 4), validate=False)
                decoded = raw.decode("utf-16le", errors="replace")
            except Exception:
                decoded = ""
            if decoded:
                stages.append({"kind": "powershell-enc", "token": match[:80], "decoded": decoded[:4000]})
        for match in re.findall(r"(?i)frombase64string\s*\(\s*['\"]([A-Za-z0-9+/=]{16,})['\"]\s*\)", text):
            decoded = self._decode_token(match, "base64")
            if decoded:
                stages.append({"kind": "frombase64string", "token": match[:80], "decoded": decoded[:4000]})
            try:
                raw = base64.b64decode(match + "=" * ((4 - len(match) % 4) % 4), validate=False)
            except Exception:
                raw = b""
            inflated = self._inflate_bytes(raw)
            if inflated:
                stages.append({"kind": "frombase64string-compressed", "token": match[:80], "decoded": inflated[:4000]})
        return stages[:10]


class MiscSolver(_KnowledgeSpecializedSolver):
    CATEGORY = "misc"
    SOLVER_NAME = "misc"

    def _run_specialized(self, challenge, workspace, state, memory, context, primary, blobs):
        corpus = "\n".join(item.get("text", "") for item in blobs if item.get("text"))
        lowered = corpus.lower()
        entity_summary = self._extract_entities(corpus)
        attachments = list(context.get("attachments", []))
        attachment_names = [str(item.get("name", "")) for item in attachments if item.get("name")]
        attachment_suffixes = {
            str(Path(item.get("path", item.get("name", ""))).suffix).lower()
            for item in attachments
            if item.get("path") or item.get("name")
        }
        image_suffixes = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}
        rf_suffixes = {".wav", ".flac", ".aiff", ".aif", ".au", ".iq", ".cu8", ".cfile", ".sigmf-meta", ".sigmf-data"}
        network_suffixes = {".pcap", ".pcapng", ".cap"}
        vm_suffixes = {".bf"}
        has_image_attachment = any(item.get("kind") == "image" for item in attachments) or bool(attachment_suffixes & image_suffixes)
        has_rf_attachment = bool(attachment_suffixes & rf_suffixes)
        has_network_attachment = any(item.get("kind") == "pcap" for item in attachments) or bool(attachment_suffixes & network_suffixes)
        has_vm_attachment = bool(attachment_suffixes & vm_suffixes) or any("brainfuck" in name.lower() for name in attachment_names)
        has_encoded_tokens = bool(self._extract_encoded_tokens(corpus, limit=8))
        jail_markers = re.search(r"\b(?:sandbox|jail|pyjail|nodejail|bashjail|blacklist|whitelist)\b|__import__|eval\(", lowered, re.I)
        dns_markers = re.search(r"\b(?:dns|txt(?:\s+record)?|mx|ns|subdomain)\b", lowered, re.I)
        vm_markers = re.search(r"\b(?:brainfuck|bytecode|opcode|register|stack\s+ptr|virtual\s+machine|esolang)\b", lowered, re.I)
        rf_markers = re.search(r"\b(?:sdr|iq|rf|signal|sigmf|sample\s+rate|modulation|carrier|fm|am)\b", lowered, re.I)
        subtype_scores = {
            "encoding": 0.2,
            "jail": 0.1,
            "vm-or-esolang": 0.1,
            "stego": 0.1,
            "dns": 0.1,
            "rf": 0.1,
        }
        if has_encoded_tokens:
            subtype_scores["encoding"] += 0.35
        if jail_markers:
            subtype_scores["jail"] += 0.75
        if has_image_attachment:
            subtype_scores["stego"] += 1.1
            subtype_scores["encoding"] -= 0.05
        if dns_markers:
            subtype_scores["dns"] += 0.65
        if has_network_attachment:
            subtype_scores["dns"] += 0.92
            subtype_scores["encoding"] -= 0.08
        if vm_markers or has_vm_attachment:
            subtype_scores["vm-or-esolang"] += 0.72
            subtype_scores["encoding"] -= 0.1
        if rf_markers or has_rf_attachment:
            subtype_scores["rf"] += 0.72
            subtype_scores["encoding"] -= 0.1
        subtype_scores["encoding"] = max(0.0, subtype_scores["encoding"])

        subtype = max(subtype_scores.items(), key=lambda item: item[1])[0]
        execution_order = ["encoding", "jail", "vm-or-esolang", "stego", "dns", "rf"]
        planned = [subtype] if subtype_scores[subtype] >= 0.7 else [name for name in execution_order if subtype_scores.get(name, 0.0) >= 0.45]
        should_frontload_encoding = (
            subtype == "encoding"
            or has_encoded_tokens
            or (
                not has_image_attachment
                and not has_rf_attachment
                and not has_vm_attachment
                and not jail_markers
                and not dns_markers
            )
        )
        if should_frontload_encoding and "encoding" not in planned:
            planned.insert(0, "encoding")
        planned = self._unique(planned)[:4]

        subsolver_reports = []
        attempts = []
        successful_decodes = []
        candidate_flags = []
        extracted_artifacts = []
        findings = []
        next_actions = []
        decoded_preview = []

        def extend_flags(items):
            for item in self._dedupe_flag_items(items):
                value = str(item.get("value", "") or "").strip()
                if not value:
                    continue
                if any(existing.get("value", "") == value for existing in candidate_flags):
                    continue
                candidate_flags.append(item)
                memory.add_candidate_flag(
                    value,
                    source=item.get("source", "misc"),
                    confidence=float(item.get("confidence", 0.68)),
                    reproducible=bool(item.get("reproducible", False)),
                )

        for name in planned:
            report = {"subtype": name, "summary": "", "attempts": [], "candidate_flags": [], "artifacts": []}
            if name == "encoding":
                decoded_candidates = []
                xor_candidates = []
                for blob in blobs[:6]:
                    text = blob.get("text", "")
                    decoded_candidates.extend(self._recursive_decode_candidates(text, limit=8, max_depth=3))
                    decoded_candidates.extend(self._decoded_candidates(text, limit=6))
                decoded_candidates = self._dedupe_decoded_candidates(self._filter_decoded_candidates(decoded_candidates, min_score=0.7, limit=14))
                openssl_probe = self._bounded_openssl_base64_probes(
                    corpus,
                    context,
                    workspace,
                    (primary or {}).get("name", challenge.challenge_id),
                    "misc:encoding",
                )
                if openssl_probe.get("artifact"):
                    report["artifacts"].append(openssl_probe["artifact"])
                    decoded_candidates.extend(list(openssl_probe.get("decodes", [])))
                for token, kind in self._extract_encoded_tokens(corpus, limit=8):
                    raw = b""
                    try:
                        if kind == "hex":
                            raw = binascii.unhexlify(token)
                        elif kind == "base64":
                            raw = base64.b64decode(token + "=" * ((4 - len(token) % 4) % 4), validate=False)
                    except Exception:
                        raw = b""
                    if raw:
                        xor_candidates.extend(self._single_byte_xor_candidates(raw, source_kind=kind, min_score=0.86, limit=4))
                        xor_candidates.extend(self._repeating_key_xor_candidates(raw, min_score=0.86, limit=4))
                for item in self._caesar_candidates(corpus, min_score=0.84, limit=4):
                    decoded_candidates.append(
                        {
                            "kind": "caesar",
                            "token": "shift:{0}".format(item["shift"]),
                            "decoded": item["text"],
                            "chain": "text->caesar:{0}".format(item["shift"]),
                            "depth": 1,
                            "score": item["score"],
                        }
                    )
                decoded_candidates = self._filter_decoded_candidates(decoded_candidates, min_score=0.7, limit=16)
                successful_decodes.extend(decoded_candidates[:8])
                decoded_preview = ["[{0}] {1}".format(item.get("kind", ""), item.get("decoded", "")[:120]) for item in decoded_candidates[:6]]
                report["candidate_flags"].extend(list(openssl_probe.get("candidate_flags", [])))
                for item in decoded_candidates:
                    self._scan_text(item.get("decoded", ""), "misc-encoding", memory)
                    for flag in self.verifier.discover_from_text(item.get("decoded", "")):
                        report["candidate_flags"].append({"value": flag, "source": "misc:encoding:{0}".format(item.get("kind", "")), "confidence": 0.78, "reproducible": False})
                for item in xor_candidates[:8]:
                    self._scan_text(item.get("text", ""), "misc-xor", memory)
                    for flag in self.verifier.discover_from_text(item.get("text", "")):
                        report["candidate_flags"].append({"value": flag, "source": "misc:{0}".format(item.get("attack", "xor")), "confidence": 0.8, "reproducible": False})
                report["attempts"] = [{"name": "recursive-decode", "count": len(decoded_candidates)}, {"name": "xor-and-caesar", "count": len(xor_candidates)}]
                report["summary"] = "decoded={0}, xor_candidates={1}".format(len(decoded_candidates), len(xor_candidates))
                report["best_path_hint"] = "decode chain -> highest scoring candidate"
                report["tool_signal"] = 0.62 + (0.1 if openssl_probe.get("artifact") else 0.0)
            elif name == "jail":
                flavor = "generic-jail"
                if "pyjail" in lowered or "__import__" in lowered or "python" in lowered:
                    flavor = "pyjail"
                elif "nodejail" in lowered or "javascript" in lowered or "process" in lowered:
                    flavor = "nodejail"
                elif "bash" in lowered or "/bin/sh" in lowered or "$(" in lowered:
                    flavor = "bashjail"
                blacklist = re.findall(r"blacklist[^\n:=]*[:=]\s*([^\n]+)", corpus, re.I)
                whitelist = re.findall(r"whitelist[^\n:=]*[:=]\s*([^\n]+)", corpus, re.I)
                payloads = {
                    "pyjail": [
                        "print(locals().get('flag'))",
                        "print(globals().get('flag'))",
                        "print(vars().get('flag'))",
                        "().__class__.__mro__[1].__subclasses__()",
                        "globals()['__builtins__']",
                    ],
                    "nodejail": [
                        "globalThis['pro'+'cess']",
                        "Buffer.from('ZmxhZw==','base64').toString()",
                        "globalThis.constructor.constructor('return globalThis')()",
                        "[][\"filter\"][\"constructor\"]('return globalThis')()",
                        "this.constructor.constructor('return process')()",
                        "global.process.mainModule.require('child_process')",
                    ],
                    "bashjail": [
                        "printf %s \"$flag\"",
                        "printf '\\146\\154\\141\\147'",
                        "echo ${flag}",
                        "cat${IFS}/f*",
                        "${PATH:0:1}bin${PATH:0:1}sh",
                        "$(printf sh)",
                    ],
                    "generic-jail": ["model filters before payload execution"],
                }
                payload_templates = payloads.get(flavor, payloads["generic-jail"])[:8]
                if flavor == "pyjail":
                    blacklist_text = " ".join(blacklist).lower()
                    if "__" in blacklist_text:
                        payload_templates = ["vars().__class__.__mro__", "globals().get('flag')"] + payload_templates
                    if "globals" not in blacklist_text:
                        payload_templates.insert(0, "print(globals().get('flag'))")
                    if "locals" not in blacklist_text:
                        payload_templates.insert(0, "print(locals().get('flag'))")
                blacklist_tokens = self._parse_constraint_tokens(blacklist)
                whitelist_tokens = self._parse_constraint_tokens(whitelist)
                viability_reports = [
                    self._evaluate_jail_payload(item, blacklist_tokens=blacklist_tokens, whitelist_tokens=whitelist_tokens)
                    for item in self._unique(payload_templates)[:8]
                ]
                viability_reports.sort(key=lambda item: (item.get("viable", False), item.get("score", 0.0)), reverse=True)
                decoded_candidates = self._dedupe_decoded_candidates(self._filter_decoded_candidates(
                    self._recursive_decode_candidates(corpus, limit=8, max_depth=3) + self._decoded_candidates(corpus, limit=6),
                    min_score=0.7,
                    limit=8,
                ))
                successful_decodes.extend(decoded_candidates[:4])
                for item in decoded_candidates:
                    decoded_text = item.get("decoded", "")
                    self._scan_text(decoded_text, "misc-jail-decoded", memory)
                    for flag in self.verifier.discover_from_text(decoded_text):
                        report["candidate_flags"].append({"value": flag, "source": "misc:jail:{0}".format(item.get("kind", "")), "confidence": 0.78, "reproducible": False})
                report["attempts"] = [
                    {
                        "name": "payload-template",
                        "payload": item.get("payload", ""),
                        "viable": item.get("viable", False),
                        "score": item.get("score", 0.0),
                        "rationale": item.get("rationale", ""),
                        "blocked_tokens": item.get("blocked_tokens", []),
                    }
                    for item in viability_reports[:6]
                ]
                report["best_payloads"] = [item.get("payload", "") for item in viability_reports if item.get("viable")][:3]
                report["payload_rationale"] = [item.get("rationale", "") for item in viability_reports[:4]]
                report["blocked_tokens"] = self._unique(sum([list(item.get("blocked_tokens", [])) for item in viability_reports], []))[:12]
                report["viable_payloads"] = [item.get("payload", "") for item in viability_reports if item.get("viable")][:6]
                report["summary"] = "flavor={0}, blacklist={1}, whitelist={2}, viable_payloads={3}, decoded={4}".format(
                    flavor,
                    len(blacklist_tokens),
                    len(whitelist_tokens),
                    len([item for item in viability_reports if item.get("viable")]),
                    len(decoded_candidates),
                )
                report["best_path_hint"] = "payload viability -> {0}".format(flavor)
                report["tool_signal"] = 0.66 if report["viable_payloads"] else 0.52
                report["indicators"] = {
                    "flavor": flavor,
                    "blacklist": blacklist_tokens[:6],
                    "whitelist": whitelist_tokens[:6],
                    "payload_viability": viability_reports[:6],
                }
                report["decoded_candidates"] = ["[{0}] {1}".format(item.get("kind", ""), item.get("decoded", "")[:120]) for item in decoded_candidates[:4]]
                report["candidate_flags"].extend(self._extract_direct_literal_flags(corpus))
            elif name == "vm-or-esolang":
                bf_output = ""
                for blob in blobs[:6]:
                    candidate = blob.get("text", "")
                    compact = "".join(ch for ch in candidate if not ch.isspace())
                    if compact and set(compact) <= set("><+-.,[]") and len(compact) >= 8:
                        bf_output = self._brainfuck_decode(compact)
                        if bf_output:
                            break
                opcodes = re.findall(r"\b(?:push|pop|jmp|call|mov|add|sub|xor|cmp|jnz|opcode|reg|register)\b", lowered)
                report["attempts"] = [{"name": "brainfuck-run", "success": bool(bf_output)}, {"name": "opcode-extraction", "count": len(opcodes)}]
                report["summary"] = "brainfuck_output={0}, opcodes={1}".format(bool(bf_output), len(opcodes))
                if bf_output:
                    successful_decodes.append({"kind": "brainfuck", "token": "program", "decoded": bf_output[:2000], "chain": "brainfuck", "depth": 1, "score": round(self._text_score(bf_output), 3)})
                    self._scan_text(bf_output, "misc-vm", memory)
                    for flag in self.verifier.discover_from_text(bf_output):
                        report["candidate_flags"].append({"value": flag, "source": "misc:brainfuck", "confidence": 0.82, "reproducible": False})
                if opcodes:
                    report["skeleton"] = "Recover instruction semantics, then build a minimal interpreter around: {0}".format(", ".join(self._unique(opcodes)[:8]))
                report["best_path_hint"] = "brainfuck" if bf_output else "opcode/state machine skeleton"
                report["tool_signal"] = 0.72 if bf_output else (0.58 if opcodes else 0.44)
            elif name == "stego":
                for attachment in context.get("attachments", []):
                    if attachment.get("kind") != "image":
                        continue
                    path = Path(attachment.get("path", ""))
                    png_text_chunks = []
                    appended_payloads = []
                    channel_preview = {}
                    if self.toolkit_tool and self.toolkit_tool.has_tool("exiftool") and path.exists():
                        result = self.toolkit_tool.run_named_tool("exiftool", [str(path)], timeout=90)
                        artifact = workspace / "artifacts" / "{0}_misc_exif.txt".format(path.stem)
                        payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                        self.file_tool.write_text(artifact, payload)
                        report["artifacts"].append(str(artifact))
                        self._record_used_tool(context, "exiftool")
                        self._scan_text(payload, "misc-stego", memory)
                    if self.toolkit_tool and self.toolkit_tool.has_tool("strings") and path.exists():
                        result = self.toolkit_tool.run_named_tool("strings", [str(path)], timeout=90)
                        artifact = workspace / "artifacts" / "{0}_misc_strings.txt".format(path.stem)
                        payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                        self.file_tool.write_text(artifact, payload)
                        report["artifacts"].append(str(artifact))
                        self._record_used_tool(context, "strings")
                        self._scan_text(payload, "misc-stego", memory)
                        for flag in self.verifier.discover_from_text(payload):
                            report["candidate_flags"].append({"value": flag, "source": "misc:stego:strings", "confidence": 0.7, "reproducible": False})
                    if self.toolkit_tool and self.toolkit_tool.has_tool("steghide") and path.exists() and path.suffix.lower() in {".jpg", ".jpeg", ".bmp"}:
                        result = self.toolkit_tool.run_steghide_info(path, timeout=45)
                        payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                        if payload:
                            artifact = workspace / "artifacts" / "{0}_misc_steghide.txt".format(path.stem)
                            self.file_tool.write_text(artifact, payload)
                            report["artifacts"].append(str(artifact))
                            self._record_used_tool(context, "steghide")
                            self._scan_text(payload, "misc-stego-steghide", memory)
                            for flag in self.verifier.discover_from_text(payload):
                                report["candidate_flags"].append({"value": flag, "source": "misc:stego:steghide", "confidence": 0.76, "reproducible": False})
                        extracted_path = workspace / "artifacts" / "{0}_misc_steghide_extract.bin".format(path.stem)
                        extract_result = self.toolkit_tool.run_steghide_extract(path, extracted_path, timeout=60)
                        extract_payload = (extract_result.get("stdout", "") + "\n" + extract_result.get("stderr", "")).strip()
                        if extract_payload:
                            artifact = workspace / "artifacts" / "{0}_misc_steghide_extract.txt".format(path.stem)
                            self.file_tool.write_text(artifact, extract_payload)
                            report["artifacts"].append(str(artifact))
                            self._record_used_tool(context, "steghide")
                            self._scan_text(extract_payload, "misc-stego-steghide", memory)
                            for flag in self.verifier.discover_from_text(extract_payload):
                                report["candidate_flags"].append({"value": flag, "source": "misc:stego:steghide-extract", "confidence": 0.8, "reproducible": False})
                        if bool(extract_result.get("output_exists")) and extracted_path.exists():
                            report["artifacts"].append(str(extracted_path))
                            try:
                                extracted_text = self.file_tool.read_text(extracted_path, limit_bytes=131072)
                            except Exception:
                                extracted_text = ""
                            try:
                                extracted_bytes = self.file_tool.read_bytes(extracted_path, limit_bytes=250000)
                            except Exception:
                                extracted_bytes = b""
                            if extracted_text:
                                self._scan_text(extracted_text, "misc-stego-steghide", memory)
                                for flag in self.verifier.discover_from_text(extracted_text):
                                    report["candidate_flags"].append({"value": flag, "source": "misc:stego:steghide-artifact", "confidence": 0.86, "reproducible": True})
                            if extracted_bytes:
                                nested = self._recover_nested_object_bytes(
                                    extracted_bytes,
                                    workspace,
                                    prefix="{0}_steghide".format(path.stem),
                                )
                                report["artifacts"].extend(
                                    item for item in list(nested.get("artifacts", [])) if item not in report["artifacts"]
                                )
                                for item in list(nested.get("candidate_flags", [])):
                                    item = dict(item or {})
                                    value = str(item.get("value", "") or "").strip()
                                    if not value:
                                        continue
                                    report["candidate_flags"].append(
                                        {
                                            "value": value,
                                            "source": "misc:stego:steghide-nested",
                                            "confidence": max(0.86, float(item.get("confidence", 0.82) or 0.82)),
                                            "reproducible": True,
                                        }
                                    )
                    if path.suffix.lower() == ".png" and path.exists():
                        channel_preview = self._describe_png_channel_preview(path)
                        png_text_chunks = self._extract_png_text_chunks(path)
                        if png_text_chunks:
                            artifact = workspace / "artifacts" / "{0}_misc_png_text.json".format(path.stem)
                            self.file_tool.write_json(artifact, png_text_chunks)
                            report["artifacts"].append(str(artifact))
                            for item in png_text_chunks:
                                text_value = item.get("text", "")
                                self._scan_text(text_value, "misc-stego-png", memory)
                                for flag in self.verifier.discover_from_text(text_value):
                                    report["candidate_flags"].append({"value": flag, "source": "misc:stego:png-text", "confidence": 0.84, "reproducible": False})
                        if self.toolkit_tool and self.toolkit_tool.has_tool("pngcheck"):
                            result = self.toolkit_tool.run_pngcheck_probe(path, timeout=30)
                            payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                            if payload:
                                artifact = workspace / "artifacts" / "{0}_misc_pngcheck.txt".format(path.stem)
                                self.file_tool.write_text(artifact, payload)
                                report["artifacts"].append(str(artifact))
                                self._record_used_tool(context, "pngcheck")
                                self._scan_text(payload, "misc-stego-pngcheck", memory)
                                for flag in self.verifier.discover_from_text(payload):
                                    report["candidate_flags"].append({"value": flag, "source": "misc:stego:pngcheck", "confidence": 0.74, "reproducible": False})
                    if path.exists():
                        appended_payloads = self._extract_appended_payloads(path)
                        if appended_payloads:
                            artifact = workspace / "artifacts" / "{0}_misc_appended_payloads.json".format(path.stem)
                            self.file_tool.write_json(artifact, appended_payloads)
                            report["artifacts"].append(str(artifact))
                            for item in appended_payloads:
                                preview = item.get("preview", "")
                                if preview:
                                    self._scan_text(preview, "misc-stego-appended", memory)
                                    for flag in self.verifier.discover_from_text(preview):
                                        report["candidate_flags"].append({"value": flag, "source": "misc:stego:appended-{0}".format(item.get("kind", "")), "confidence": 0.82, "reproducible": False})
                    if self.toolkit_tool and self.toolkit_tool.has_tool("binwalk") and path.exists():
                        result = self.toolkit_tool.run_binwalk_scan(path, timeout=45)
                        payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                        if payload:
                            artifact = workspace / "artifacts" / "{0}_misc_binwalk.txt".format(path.stem)
                            self.file_tool.write_text(artifact, payload)
                            report["artifacts"].append(str(artifact))
                            self._record_used_tool(context, "binwalk")
                            self._scan_text(payload, "misc-stego-binwalk", memory)
                            for flag in self.verifier.discover_from_text(payload):
                                report["candidate_flags"].append({"value": flag, "source": "misc:stego:binwalk", "confidence": 0.76, "reproducible": False})
                        extract_dir = workspace / "artifacts" / "{0}_misc_binwalk_extract".format(path.stem)
                        extract_result = self.toolkit_tool.run_binwalk_extract(path, extract_dir, timeout=60)
                        extracted_listing = list(extract_result.get("extracted_files", []) or [])
                        if extracted_listing:
                            self._record_used_tool(context, "binwalk")
                            report["artifacts"].extend(item for item in extracted_listing if item not in report["artifacts"])
                            for extracted_name in extracted_listing[:20]:
                                extracted_path = Path(extracted_name)
                                if not extracted_path.exists() or not extracted_path.is_file():
                                    continue
                                try:
                                    extracted_text = self.file_tool.read_text(extracted_path, limit_bytes=131072)
                                except Exception:
                                    extracted_text = ""
                                try:
                                    extracted_bytes = self.file_tool.read_bytes(extracted_path, limit_bytes=250000)
                                except Exception:
                                    extracted_bytes = b""
                                if extracted_text:
                                    self._scan_text(extracted_text, "misc-stego-binwalk-extract", memory)
                                    for flag in self.verifier.discover_from_text(extracted_text):
                                        report["candidate_flags"].append({"value": flag, "source": "misc:stego:binwalk-extract", "confidence": 0.84, "reproducible": True})
                                if extracted_bytes:
                                    nested = self._recover_nested_object_bytes(
                                        extracted_bytes,
                                        workspace,
                                        prefix="{0}_{1}".format(path.stem, re.sub(r"[^A-Za-z0-9._-]+", "_", extracted_path.stem)[:40]),
                                    )
                                    report["artifacts"].extend(
                                        item for item in list(nested.get("artifacts", [])) if item not in report["artifacts"]
                                    )
                                    for item in list(nested.get("candidate_flags", [])):
                                        item = dict(item or {})
                                        value = str(item.get("value", "") or "").strip()
                                        if not value:
                                            continue
                                        report["candidate_flags"].append(
                                            {
                                                "value": value,
                                                "source": "misc:stego:binwalk-nested",
                                                "confidence": max(0.84, float(item.get("confidence", 0.82) or 0.82)),
                                                "reproducible": True,
                                            }
                                        )
                    if channel_preview:
                        report["channel_preview"] = channel_preview
                    report.setdefault("png_text_chunks", []).extend(png_text_chunks[:8])
                    report.setdefault("appended_payloads", []).extend(appended_payloads[:8])
                report["attempts"] = [{"name": "metadata-and-strings", "artifact_count": len(report["artifacts"])}]
                report["summary"] = "artifacts={0}".format(len(report["artifacts"]))
                if report.get("candidate_flags"):
                    report["best_path_hint"] = "stego tool output -> recover embedded text"
                elif report.get("png_text_chunks"):
                    report["best_path_hint"] = "png text chunks -> inspect recovered chunk text"
                elif report.get("appended_payloads"):
                    report["best_path_hint"] = "appended payload -> inflate or preview carved object"
                else:
                    report["best_path_hint"] = "metadata/structure -> decide if deeper stego tooling is justified"
                report["tool_signal"] = 0.55 + min(0.28, 0.04 * len(report.get("artifacts", [])))
            elif name == "dns":
                domains = self._unique(entity_summary.get("domains", []) + [urlparse(url).netloc for url in entity_summary.get("urls", []) if urlparse(url).netloc])[:5]
                dns_reports = []
                dns_attempts = []
                for blob in blobs[:8]:
                    dns_reports.extend(self._extract_inline_dns_reports(blob.get("text", ""), fallback_domains=domains))
                for attachment in context.get("attachments", [])[:6]:
                    if not self._attachment_is_capture(attachment):
                        continue
                    path = Path(attachment.get("path", ""))
                    if not path.exists():
                        continue
                    if self.toolkit_tool and self.toolkit_tool.has_tool("pcapfix"):
                        result = self.toolkit_tool.run_pcapfix_probe(path, timeout=30)
                        payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                        dns_attempts.append({"name": "pcapfix", "target": path.name, "status": result.get("status", "missing")})
                        if payload:
                            artifact = workspace / "artifacts" / "{0}_misc_pcapfix.txt".format(path.stem)
                            self.file_tool.write_text(artifact, payload)
                            report["artifacts"].append(str(artifact))
                            self._record_used_tool(context, "pcapfix")
                            self._scan_text(payload, "misc-dns-pcapfix", memory)
                            for flag in self.verifier.discover_from_text(payload):
                                report["candidate_flags"].append({"value": flag, "source": "misc:dns:pcapfix", "confidence": 0.66, "reproducible": False})
                    if self.toolkit_tool and self.toolkit_tool.has_tool("capinfos"):
                        result = self.toolkit_tool.run_capinfos_probe(path, timeout=30)
                        payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                        dns_attempts.append({"name": "capinfos", "target": path.name, "status": result.get("status", "missing")})
                        if payload:
                            artifact = workspace / "artifacts" / "{0}_misc_capinfos.txt".format(path.stem)
                            self.file_tool.write_text(artifact, payload)
                            report["artifacts"].append(str(artifact))
                            self._record_used_tool(context, "capinfos")
                            self._scan_text(payload, "misc-dns-capinfos", memory)
                            for flag in self.verifier.discover_from_text(payload):
                                report["candidate_flags"].append({"value": flag, "source": "misc:dns:capinfos", "confidence": 0.66, "reproducible": False})
                    if self.toolkit_tool and self.toolkit_tool.has_tool("tshark"):
                        result = self.toolkit_tool.run_tshark_probe(path, timeout=45)
                        payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                        dns_attempts.append({"name": "tshark", "target": path.name, "status": result.get("status", "missing")})
                        if payload:
                            artifact = workspace / "artifacts" / "{0}_misc_tshark.txt".format(path.stem)
                            self.file_tool.write_text(artifact, payload)
                            report["artifacts"].append(str(artifact))
                            self._record_used_tool(context, "tshark")
                            self._scan_text(payload, "misc-dns-tshark", memory)
                            for flag in self.verifier.discover_from_text(payload):
                                report["candidate_flags"].append({"value": flag, "source": "misc:dns:tshark", "confidence": 0.7, "reproducible": False})
                            tshark_reports = self._extract_tshark_dns_reports(payload)
                            dns_reports.extend(tshark_reports)
                            domains = self._unique(domains + [item.get("domain", "") for item in tshark_reports if item.get("domain")])[:8]
                    if self.toolkit_tool and self.toolkit_tool.has_tool("strings"):
                        result = self.toolkit_tool.run_named_tool("strings", [str(path)], timeout=60)
                        payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                        dns_attempts.append({"name": "strings", "target": path.name, "status": result.get("status", "missing")})
                        if payload:
                            artifact = workspace / "artifacts" / "{0}_misc_dns_strings.txt".format(path.stem)
                            self.file_tool.write_text(artifact, payload)
                            report["artifacts"].append(str(artifact))
                            self._record_used_tool(context, "strings")
                            self._scan_text(payload, "misc-dns-strings", memory)
                            for flag in self.verifier.discover_from_text(payload):
                                report["candidate_flags"].append({"value": flag, "source": "misc:dns:strings", "confidence": 0.68, "reproducible": False})
                            dns_reports.extend(self._extract_inline_dns_reports(payload, fallback_domains=domains))
                for domain in domains:
                    dns_report = self._resolve_dns_records(domain)
                    dns_reports.append(dns_report)
                normalized_reports = []
                seen_dns = set()
                for dns_report in dns_reports:
                    domain = str(dns_report.get("domain", "")).strip().lower()
                    key = (
                        domain,
                        tuple(dns_report.get("a_records", [])),
                        tuple(dns_report.get("txt_records", [])),
                        tuple(dns_report.get("mx_records", [])),
                        tuple(dns_report.get("ns_records", [])),
                    )
                    if key in seen_dns:
                        continue
                    seen_dns.add(key)
                    normalized_reports.append(dns_report)
                dns_reports = normalized_reports[:10]
                source_counts = {}
                for dns_report in dns_reports:
                    source_name = str(dns_report.get("source", "unknown") or "unknown").strip().lower()
                    source_counts[source_name] = int(source_counts.get(source_name, 0) or 0) + 1
                for dns_report in dns_reports:
                    for txt_value in dns_report.get("txt_records", []):
                        self._scan_text(txt_value, "misc-dns", memory)
                        for flag in self.verifier.discover_from_text(txt_value):
                            report["candidate_flags"].append({"value": flag, "source": "misc:dns:{0}".format(dns_report.get("domain", "")), "confidence": 0.82, "reproducible": False})
                report["attempts"] = dns_attempts + [{"name": "dns-probe", "domain": item.get("domain", ""), "a_records": len(item.get("a_records", [])), "txt_records": len(item.get("txt_records", []))} for item in dns_reports]
                report["summary"] = "domains={0}, capture_attempts={1}, live={2}, inline={3}, pcap={4}".format(
                    len(dns_reports),
                    len(dns_attempts),
                    int(source_counts.get("live", 0) or 0),
                    int(source_counts.get("inline", 0) or 0),
                    int(source_counts.get("pcap", 0) or 0),
                )
                report["dns_reports"] = dns_reports
                report["source_counts"] = source_counts
                report["indicators"] = ["{0}:{1}".format(item.get("source", "unknown"), item.get("domain", "")) for item in dns_reports[:8]]
                txt_count = sum(len(item.get("txt_records", [])) for item in dns_reports)
                if txt_count:
                    report["best_path_hint"] = "dns txt records -> inspect recovered text and mail or authority pivots"
                elif int(source_counts.get("pcap", 0) or 0) and dns_attempts:
                    report["best_path_hint"] = "capture probes -> tshark/capinfos/strings -> dns correlation"
                elif int(source_counts.get("live", 0) or 0):
                    report["best_path_hint"] = "live dns -> correlate A/TXT/MX/NS answers before wider enumeration"
                else:
                    report["best_path_hint"] = "inline dns -> pivot on authoritative records and embedded zone text"
                report["tool_signal"] = 0.6 + min(0.25, 0.04 * len(dns_attempts) + 0.03 * txt_count)
            elif name == "rf":
                rf_reports = []
                lsb_candidates = []
                decoded_audio_candidates = []
                for attachment in context.get("attachments", []):
                    suffix = str(attachment.get("name", "")).lower()
                    path = Path(attachment.get("path", ""))
                    attachment_suffix = str(path.suffix).lower()
                    if suffix.endswith(tuple(rf_suffixes)) or attachment_suffix in rf_suffixes:
                        described = self._describe_rf_attachment(attachment)
                        rf_reports.append(described)
                        if self.toolkit_tool and self.toolkit_tool.has_tool("sox") and path.exists():
                            result = self.toolkit_tool.run_sox_probe(path, timeout=30)
                            payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                            if payload:
                                artifact = workspace / "artifacts" / "{0}_misc_sox.txt".format(path.stem)
                                self.file_tool.write_text(artifact, payload)
                                report["artifacts"].append(str(artifact))
                                self._record_used_tool(context, "sox")
                                self._scan_text(payload, "misc-rf-sox", memory)
                                described["sox_artifact"] = str(artifact)
                                described["sox_summary"] = payload[:240]
                                for flag in self.verifier.discover_from_text(payload):
                                    report["candidate_flags"].append({"value": flag, "source": "misc:rf:sox", "confidence": 0.72, "reproducible": False})
                        if self.toolkit_tool and self.toolkit_tool.has_tool("ffmpeg") and path.exists():
                            result = self.toolkit_tool.run_ffmpeg_probe(path, timeout=30)
                            payload = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                            if payload:
                                artifact = workspace / "artifacts" / "{0}_misc_ffmpeg.txt".format(path.stem)
                                self.file_tool.write_text(artifact, payload)
                                report["artifacts"].append(str(artifact))
                                self._record_used_tool(context, "ffmpeg")
                                self._scan_text(payload, "misc-rf-ffmpeg", memory)
                                described["ffmpeg_artifact"] = str(artifact)
                                described["ffmpeg_summary"] = payload[:240]
                                for flag in self.verifier.discover_from_text(payload):
                                    report["candidate_flags"].append({"value": flag, "source": "misc:rf:ffmpeg", "confidence": 0.7, "reproducible": False})
                        if (
                            self.toolkit_tool
                            and self.toolkit_tool.has_tool("ffmpeg")
                            and path.exists()
                            and path.suffix.lower() in {".flac", ".aiff", ".aif", ".au"}
                        ):
                            decoded_wav = workspace / "artifacts" / "{0}_misc_ffmpeg_decode.wav".format(path.stem)
                            result = self.toolkit_tool.run_ffmpeg_decode_audio(path, decoded_wav, timeout=60)
                            decode_log = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
                            if decode_log:
                                artifact = workspace / "artifacts" / "{0}_misc_ffmpeg_decode.txt".format(path.stem)
                                self.file_tool.write_text(artifact, decode_log)
                                report["artifacts"].append(str(artifact))
                                self._record_used_tool(context, "ffmpeg")
                                self._scan_text(decode_log, "misc-rf-ffmpeg-decode", memory)
                            if bool(result.get("output_exists")) and decoded_wav.exists():
                                report["artifacts"].append(str(decoded_wav))
                                described["ffmpeg_decoded_wav"] = str(decoded_wav)
                                decoded_audio_candidates.extend(self._extract_wav_lsb_candidates(decoded_wav, limit=4))
                        if path.suffix.lower() == ".wav" and path.exists():
                            lsb_candidates.extend(self._extract_wav_lsb_candidates(path, limit=4))
                for item in lsb_candidates:
                    self._scan_text(item.get("decoded", ""), "misc-rf-lsb", memory)
                    for flag in self.verifier.discover_from_text(item.get("decoded", "")):
                        report["candidate_flags"].append({"value": flag, "source": "misc:rf:{0}".format(item.get("mode", "lsb")), "confidence": 0.86, "reproducible": False})
                for item in decoded_audio_candidates:
                    self._scan_text(item.get("decoded", ""), "misc-rf-ffmpeg-lsb", memory)
                    for flag in self.verifier.discover_from_text(item.get("decoded", "")):
                        report["candidate_flags"].append({"value": flag, "source": "misc:rf:ffmpeg-wav-lsb", "confidence": 0.88, "reproducible": True})
                report["attempts"] = [
                    {"name": "rf-classification", "count": len(rf_reports)},
                    {"name": "wav-lsb", "count": len(lsb_candidates)},
                    {"name": "ffmpeg-decode-lsb", "count": len(decoded_audio_candidates)},
                ]
                report["summary"] = "rf_artifacts={0}, wav_lsb={1}, decoded_audio_lsb={2}".format(len(rf_reports), len(lsb_candidates), len(decoded_audio_candidates))
                report["rf_reports"] = rf_reports
                report["lsb_candidates"] = lsb_candidates[:6]
                report["decoded_audio_candidates"] = decoded_audio_candidates[:6]
                report["indicators"] = [
                    "{0}:{1}:{2}".format(item.get("name", ""), item.get("frame_rate", item.get("sample_rate", "?")), item.get("datatype", item.get("kind", "")))
                    for item in rf_reports[:6]
                ]
                if decoded_audio_candidates:
                    report["best_path_hint"] = "ffmpeg decode -> wav lsb -> recover hidden text from lossless audio artifacts"
                elif lsb_candidates:
                    report["best_path_hint"] = "wav lsb -> recover hidden text from decoded candidates"
                elif rf_reports:
                    report["best_path_hint"] = "audio probe -> inspect sample rate and modulation hints"
                else:
                    report["best_path_hint"] = "rf container classification -> choose next decoding tool"
                report["tool_signal"] = 0.58 + min(0.22, 0.04 * len(rf_reports) + 0.05 * len(lsb_candidates) + 0.06 * len(decoded_audio_candidates))

            subsolver_reports.append(report)
            attempts.extend(report.get("attempts", []))
            extracted_artifacts.extend(report.get("artifacts", []))
            report["candidate_flags"] = self._dedupe_flag_items(report.get("candidate_flags", []))
            extend_flags(report.get("candidate_flags", []))
            if report.get("summary"):
                findings.append({"source": "misc", "summary": "Misc subsolver {0}".format(name), "evidence": report.get("summary", ""), "confidence": 0.62})
            if name == "encoding":
                next_actions.append("Promote the highest-scoring decode chain to a concrete flag or keyword hypothesis.")
            elif name == "jail":
                next_actions.append("Validate blacklist and reachable objects before attempting any real jail escape payload.")
            elif name == "vm-or-esolang":
                next_actions.append("Recover instruction semantics and script a minimal interpreter if auto-decoding stalls.")
            elif name == "stego":
                next_actions.append("Escalate to deeper image stego tooling only if metadata and strings plateau.")
            elif name == "dns":
                next_actions.append("Pivot on TXT/MX/NS evidence before enumerating broader infrastructure.")
            elif name == "rf":
                next_actions.append("Confirm container, sample rate, and modulation before switching to SDR tooling.")

        successful_decodes = self._dedupe_decoded_candidates(successful_decodes)
        candidate_flags = self._dedupe_flag_items(candidate_flags)
        blocked_tokens = self._unique(
            sum([list(item.get("blocked_tokens", [])) for item in subsolver_reports if isinstance(item, dict)], [])
        )[:12]
        viable_payloads = self._unique(
            sum([list(item.get("viable_payloads", [])) for item in subsolver_reports if isinstance(item, dict)], [])
        )[:8]
        payload_rationale = self._unique(
            sum([list(item.get("payload_rationale", [])) for item in subsolver_reports if isinstance(item, dict)], [])
        )[:8]
        dns_reports = []
        rf_reports = []
        channel_preview = {}
        for item in subsolver_reports:
            if not isinstance(item, dict):
                continue
            dns_reports.extend(list(item.get("dns_reports", [])))
            rf_reports.extend(list(item.get("rf_reports", [])))
            if not channel_preview and isinstance(item.get("channel_preview"), dict):
                channel_preview = dict(item.get("channel_preview", {}))
        ranked_misc_hints = []
        for item in subsolver_reports:
            if not isinstance(item, dict):
                continue
            hint = str(item.get("best_path_hint", "") or "").strip()
            if not hint:
                continue
            ranked_misc_hints.append(
                (
                    float(item.get("tool_signal", 0.0) or 0.0),
                    len(list(item.get("candidate_flags", []))),
                    len(list(item.get("artifacts", []))),
                    hint,
                )
            )
        best_path = "misc -> {0}".format(subtype)
        if candidate_flags:
            best_path = "flag via {0}".format(candidate_flags[0].get("source", "misc"))
        elif ranked_misc_hints:
            ranked_misc_hints.sort(reverse=True)
            best_path = ranked_misc_hints[0][3]
        elif successful_decodes:
            best_path = "decode chain -> {0}".format(successful_decodes[0].get("kind", "text"))

        return {
            "summary": "Subtype={0}; attempts={1}; decodes={2}".format(subtype, len(attempts), len(successful_decodes)),
            "subtype": subtype,
            "decoded_candidates": successful_decodes[:6] or decoded_preview[:6],
            "attempts": attempts[:20],
            "successful_decodes": successful_decodes[:8],
            "subsolver_reports": subsolver_reports,
            "extracted_artifacts": extracted_artifacts[:12],
            "best_path": best_path,
            "blocked_tokens": blocked_tokens,
            "viable_payloads": viable_payloads,
            "payload_rationale": payload_rationale,
            "dns_reports": dns_reports[:10],
            "rf_reports": rf_reports[:10],
            "channel_preview": channel_preview,
            "artifact_name": "misc_analysis.json",
            "artifact_payload": {
                "subtype": subtype,
                "scores": subtype_scores,
                "attempts": attempts,
                "attempt_count": len(attempts),
                "successful_decodes": successful_decodes,
                "successful_decode_count": len(successful_decodes),
                "candidate_flags": candidate_flags,
                "extracted_artifacts": extracted_artifacts,
                "best_path": best_path,
                "subsolver_reports": subsolver_reports,
                 "entity_summary": entity_summary,
                 "blocked_tokens": blocked_tokens,
                 "viable_payloads": viable_payloads,
                "payload_count": max(
                    len(viable_payloads),
                    sum(
                        len(list(item.get("best_payloads", [])))
                        for item in subsolver_reports
                        if isinstance(item, dict)
                    ),
                ),
                 "payload_rationale": payload_rationale,
                 "dns_reports": dns_reports,
                 "rf_reports": rf_reports,
                 "channel_preview": channel_preview,
            },
            "findings": findings or [{"source": "misc", "summary": "Misc subtype selected", "evidence": subtype, "confidence": 0.65}],
            "plans": [
                {
                    "title": "Misc specialized path",
                    "method": "knowledge-driven-trace",
                    "url": "attachment://{0}".format(challenge.challenge_id),
                    "notes": best_path,
                    "confidence": 0.68,
                }
            ],
            "next_actions": self._dedupe(next_actions),
            "recommended_tools": ["strings", "exiftool", "run_local_tool"],
            "recommended_path": "misc-specialized",
            "candidate_flags": candidate_flags,
            "indicators": self._unique(self._flatten_indicator_values([item.get("indicators", []) for item in subsolver_reports if isinstance(item, dict)]))[:24],
            "payload_count": max(len(viable_payloads), sum(len(list(item.get("best_payloads", []))) for item in subsolver_reports if isinstance(item, dict))),
        }








