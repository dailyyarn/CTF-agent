import re

from ctf_agent.knowledge import supported_categories


TASK_TEMPLATE_NAME = "ctf-task-template"
TASK_TEMPLATE_VERSION = "2026-03-23"
CATEGORY_ENUM = "|".join(supported_categories())

FIELD_ALIASES = {
    "category": ["category", "type", "题型", "类型", "分类"],
    "target": ["target", "url", "link", "网址", "网站链接", "目标", "题目链接", "target/url"],
    "attachments": ["attachments", "attachment", "attach", "file", "files", "附件", "附件路径", "题目文件", "文件路径"],
    "title": ["title", "标题", "题目标题", "题目名"],
    "hint": ["hint", "note", "notes", "提示", "补充说明", "额外要求"],
    "description": ["description", "题目描述", "描述", "说明"],
    "flag_format": ["flag-format", "flag format", "flagformat", "flag格式", "flag_format"],
    "use_browser_mcp": ["use-browser-mcp", "browser-mcp", "browser mcp", "浏览器mcp", "使用浏览器mcp"],
    "use_remote_host": ["use-remote-host", "remote-host", "remote host", "远程主机", "使用远程主机"],
    "max_rounds": ["max-rounds", "max rounds", "最大轮数", "最大迭代轮数"],
}

LIST_FIELDS = {"attachments"}
BOOLEAN_FIELDS = {"use_browser_mcp"}
INTEGER_FIELDS = {"max_rounds"}

_ALIAS_MAP = {}
for _canonical, _aliases in FIELD_ALIASES.items():
    for _alias in _aliases:
        _ALIAS_MAP["".join(ch for ch in str(_alias).lower() if ch.isalnum() or "\u4e00" <= ch <= "\u9fff")] = _canonical


def render_task_template():
    return """# CTF Task Template

Category: {categories}
Target:
Attachments:
- <path-to-attachment>
Title:
Hint:
Description:
Flag-Format: flag\\{{[^{{}}\\n]+\\}}
Use-Browser-MCP: auto
Use-Remote-Host: auto
Max-Rounds:
""".format(categories=CATEGORY_ENUM).strip()


def render_quick_task_template():
    return """Type: {categories}
Target:
Files:
- <path-to-attachment>
Hint:
""".format(categories=CATEGORY_ENUM).strip()


def render_task_from_fields(payload, quick=False):
    payload = dict(payload or {})
    category = str(payload.get("category") or "").strip()
    target = str(payload.get("target") or payload.get("url") or "").strip()
    attachments = [str(item).strip() for item in list(payload.get("attachments") or []) if str(item).strip()]
    title = str(payload.get("title") or "").strip()
    hint = str(payload.get("hint") or "").strip()
    description = str(payload.get("description") or "").strip()
    flag_format = str(payload.get("flag_format") or "").strip()
    use_browser_mcp = _format_boolish(payload.get("use_browser_mcp"), auto_literal="auto")
    use_remote_host = str(payload.get("use_remote_host") or "").strip() or "auto"
    max_rounds = payload.get("max_rounds")

    if quick:
        lines = [
            "Type: {0}".format(category),
            "Target: {0}".format(target),
            "Files:",
        ]
        if attachments:
            for item in attachments:
                lines.append("- {0}".format(item))
        else:
            lines.append("- ")
        lines.append("Hint: {0}".format(hint or description))
        return "\n".join(lines).strip()

    lines = [
        "# CTF Task Template",
        "",
        "Category: {0}".format(category),
        "Target: {0}".format(target),
        "Attachments:",
    ]
    if attachments:
        for item in attachments:
            lines.append("- {0}".format(item))
    else:
        lines.append("- ")
    lines.extend(
        [
            "Title: {0}".format(title),
            "Hint: {0}".format(hint),
            "Description: {0}".format(description),
            "Flag-Format: {0}".format(flag_format),
            "Use-Browser-MCP: {0}".format(use_browser_mcp),
            "Use-Remote-Host: {0}".format(use_remote_host),
            "Max-Rounds: {0}".format("" if max_rounds in (None, "") else max_rounds),
        ]
    )
    return "\n".join(lines).strip()


def build_task_template_payload():
    return {
        "protocol": {
            "name": TASK_TEMPLATE_NAME,
            "version": TASK_TEMPLATE_VERSION,
        },
        "markdown": render_task_template(),
        "quick_markdown": render_quick_task_template(),
        "fields": [
            {"name": "Category", "required": False, "notes": "题型。可选 {0}；留空则自动推断。".format(CATEGORY_ENUM)},
            {"name": "Target", "required": False, "notes": "目标 URL、host:port 或本地文件路径。"},
            {"name": "Attachments", "required": False, "notes": "附件路径列表，支持多行 bullet。"},
            {"name": "Title", "required": False, "notes": "题目标题；留空则自动推断。"},
            {"name": "Hint", "required": False, "notes": "你希望 agent 优先注意的线索。"},
            {"name": "Description", "required": False, "notes": "题目描述或复制的题面。"},
            {"name": "Flag-Format", "required": False, "notes": "flag 校验正则。"},
            {"name": "Use-Browser-MCP", "required": False, "notes": "auto/true/false。"},
            {"name": "Use-Remote-Host", "required": False, "notes": "auto 或指定远程主机名。"},
            {"name": "Max-Rounds", "required": False, "notes": "solver 最大迭代轮数。"},
        ],
        "example": render_task_template(),
        "quick_example": render_quick_task_template(),
        "notes": [
            "宿主 AI 只需要把 task 组织成这份模板，再调用 submit_ctf_task 或 start_ctf_task。",
            "如果只想在对话框里快速投喂，优先使用 quick_markdown。",
            "模板只负责稳定输入，不替代底层 autopilot、远程、MCP 和 solver 编排。",
        ],
    }


def parse_task_template(task):
    text = str(task or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return {
            "detected": False,
            "fields": {},
            "field_names": [],
            "body": "",
            "template": "",
            "protocol": {"name": TASK_TEMPLATE_NAME, "version": TASK_TEMPLATE_VERSION},
        }

    lines = text.split("\n")
    fields = {}
    field_names = []
    body_lines = []
    current_key = None
    current_buffer = []

    def flush_current():
        nonlocal current_key, current_buffer
        if not current_key:
            return
        value = _coerce_value(current_key, current_buffer)
        if value not in ("", None) and value != []:
            fields[current_key] = value
            if current_key not in field_names:
                field_names.append(current_key)
        current_key = None
        current_buffer = []

    for line in lines:
        matched_key, matched_value = _match_field(line)
        if matched_key:
            flush_current()
            current_key = matched_key
            current_buffer = [matched_value] if matched_value is not None else [""]
            continue
        if current_key:
            current_buffer.append(line)
            continue
        body_lines.append(line)

    flush_current()
    body = "\n".join(line for line in body_lines).strip()
    detected = bool(field_names) and (
        len(field_names) >= 2
        or text.lstrip().startswith("# CTF Task Template")
        or "Category:" in text
        or "Type:" in text
    )
    return {
        "detected": detected,
        "fields": fields if detected else {},
        "field_names": field_names if detected else [],
        "body": body,
        "template": render_task_template(),
        "protocol": {"name": TASK_TEMPLATE_NAME, "version": TASK_TEMPLATE_VERSION},
    }


def _match_field(line):
    match = re.match(r"^\s*([A-Za-z\u4e00-\u9fff][A-Za-z0-9_\- /\u4e00-\u9fff]*)\s*[:：]\s*(.*)$", str(line or ""))
    if not match:
        return None, None
    label = _normalize_label(match.group(1))
    canonical = _ALIAS_MAP.get(label)
    if not canonical:
        return None, None
    return canonical, match.group(2)


def _normalize_label(label):
    return "".join(ch for ch in str(label).lower() if ch.isalnum() or "\u4e00" <= ch <= "\u9fff")


def _coerce_value(field_name, raw_lines):
    lines = [str(line or "") for line in list(raw_lines or [])]
    if field_name in LIST_FIELDS:
        return _parse_list_value(lines)

    value = "\n".join(lines).strip()
    if field_name in BOOLEAN_FIELDS:
        return _parse_bool(value)
    if field_name in INTEGER_FIELDS:
        return _parse_int(value)
    if field_name == "use_remote_host":
        text = str(value or "").strip()
        if not text or text.lower() == "auto":
            return None
        return text
    if field_name == "category":
        return str(value or "").strip().lower()
    return value


def _parse_list_value(lines):
    values = []
    for line in lines:
        text = str(line or "").strip()
        if not text:
            continue
        bullet_match = re.match(r"^[-*]\s+(.*)$", text)
        if bullet_match:
            text = bullet_match.group(1).strip()
            if text:
                values.append(text)
            continue
        if "," in text or ";" in text:
            parts = re.split(r"[;,]+", text)
            values.extend(part.strip() for part in parts if part.strip())
            continue
        values.append(text)
    return values


def _parse_bool(value):
    text = str(value or "").strip().lower()
    if not text or text == "auto":
        return None
    if text in {"1", "true", "yes", "on", "enabled", "开启", "是"}:
        return True
    if text in {"0", "false", "no", "off", "disabled", "关闭", "否"}:
        return False
    return None


def _parse_int(value):
    text = str(value or "").strip()
    if not text:
        return None
    match = re.search(r"\d+", text)
    if not match:
        return None
    return int(match.group(0))


def _format_boolish(value, auto_literal="auto"):
    if value is None:
        return auto_literal
    return "true" if bool(value) else "false"
