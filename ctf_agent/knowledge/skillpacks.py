from copy import deepcopy
from pathlib import Path
import re


KNOWLEDGE_PACK_NAME = "ctf-skills-main"
KNOWLEDGE_PACK_MODE = "embedded"
KNOWLEDGE_PACK_VERSION = "2026-03-23"
EMBEDDED_SKILLS_ROOT = Path(__file__).resolve().parent / "embedded_ctf_skills"


def _docs(*relative_paths):
    return [str((EMBEDDED_SKILLS_ROOT / item).resolve()) for item in relative_paths]


COMMON_WEB_TOOLS = ["http", "shell", "strings", "sqlmap"]
COMMON_BINARY_TOOLS = ["strings", "checksec", "pwntools", "ida64", "ghidra"]
COMMON_TRIAGE_TOOLS = ["strings", "file", "exiftool", "run_local_tool"]


SKILLPACKS = {
    "web": {
        "label": "CTF Web Playbook",
        "solver": "web",
        "aliases": ["web", "http", "website", "api", "webapp", "网页", "网站"],
        "keywords": [
            "http",
            "https",
            "api",
            "cookie",
            "jwt",
            "login",
            "upload",
            "ssrf",
            "sqli",
            "sql injection",
            "ssti",
            "xxe",
            "jwt",
            "auth",
            "admin",
            "csrf",
            "xss",
            "flask",
            "django",
            "express",
            "php",
            "nginx",
            "graphql",
        ],
        "attachment_suffixes": [".php", ".html", ".htm", ".js", ".ts", ".vue", ".jsp", ".aspx", ".json"],
        "knowledge_topics": [
            "recon",
            "auth-and-access",
            "jwt",
            "client-side",
            "ssrf-xxe-ssti",
            "upload-and-rce",
            "sqli",
        ],
        "top_tactics": [
            "先做路由、表单、静态资源和 JS 端点梳理，再决定主攻面。",
            "优先检查鉴权、越权、JWT、调试接口和隐藏管理入口。",
            "对上传、模板渲染、文件读取、SSRF、XXE、反序列化保持高优先级假设。",
            "结合响应差分和 OOB 回连验证盲 SSRF、盲命令执行和盲注。",
            "把浏览器链路和 HTTP 链路写回同一份证据板，不重复走查。",
        ],
        "reference_docs": _docs(
            "ctf-web/SKILL.md",
            "ctf-web/auth-and-access.md",
            "ctf-web/auth-jwt.md",
            "ctf-web/client-side.md",
            "ctf-web/server-side.md",
            "ctf-web/server-side-exec.md",
            "ctf-web/server-side-deser.md",
            "ctf-web/server-side-advanced.md",
        ),
        "recommended_tools": COMMON_WEB_TOOLS,
        "recommended_mcp": ["browser-use"],
        "recommended_remote_templates": ["http-replay"],
        "profile_goal": "中文输出，围绕认证、路由、参数、上传、执行链与 OOB 证据持续推进到 flag。",
        "profile_capabilities": [
            "HTTP 侦察与参数差分",
            "登录态与浏览器链路复现",
            "客户端与服务端漏洞假设生成",
            "OOB、上传和自动 exploit 方案排序",
        ],
        "profile_notes": [
            "优先利用低成本侦察缩小攻击面，再升级到高成本利用。",
            "浏览器链路和 HTTP 链路必须共享同一份状态。",
        ],
    },
    "pwn": {
        "label": "CTF Pwn Playbook",
        "solver": "binary",
        "aliases": ["pwn", "overflow", "rop", "heap", "fmt", "format-string", "栈溢出", "堆", "格式化字符串"],
        "keywords": [
            "pwn",
            "elf",
            "checksec",
            "rop",
            "shellcode",
            "overflow",
            "fmt",
            "format string",
            "heap",
            "libc",
            "got",
            "plt",
            "one_gadget",
            "seccomp",
            "syscall",
            "pwntools",
            "nc ",
        ],
        "attachment_suffixes": [".elf", ".bin", ".so", ".o", ".a", ".out"],
        "knowledge_topics": ["checksec", "overflow", "fmt", "rop", "advanced-exploits"],
        "top_tactics": [
            "先确认架构、保护、输入点、泄露点和 win/system 线索。",
            "优先判断是 ret2win、格式化字符串、堆利用还是 ROP 链问题。",
            "本地 strings/checksec 与远程 pwntools 模板联动，尽快固定利用脚本骨架。",
            "如果存在远程服务，尽早把 host:port 交给 pwntools 模板固化交互。",
        ],
        "reference_docs": _docs(
            "ctf-pwn/SKILL.md",
            "ctf-pwn/overflow-basics.md",
            "ctf-pwn/format-string.md",
            "ctf-pwn/rop-and-shellcode.md",
            "ctf-pwn/advanced.md",
            "ctf-pwn/advanced-exploits.md",
        ),
        "recommended_tools": COMMON_BINARY_TOOLS + ["ROPgadget"],
        "recommended_mcp": ["ida-pro-mcp", "ghidra-mcp"],
        "recommended_remote_templates": ["binary-analysis", "pwntools"],
        "profile_goal": "中文输出，围绕保护机制、泄露、控制流与利用链持续推进到 flag。",
        "profile_capabilities": [
            "保护与架构识别",
            "泄露/覆盖/ROP 假设",
            "本地工具与逆向 MCP 联动",
            "远程 pwntools 模板固化",
        ],
        "profile_notes": [
            "优先固定最短利用链，不先追求完美解释。",
        ],
    },
    "re": {
        "label": "CTF Reverse Playbook",
        "solver": "binary",
        "aliases": ["re", "reverse", "rev", "逆向", "反编译"],
        "keywords": [
            "reverse",
            "reversing",
            "ida",
            "ghidra",
            "ghidra",
            "imhex",
            "patch",
            "anti debug",
            "anti-analysis",
            "vm",
            "bytecode",
            "decompile",
            "crackme",
            "keygen",
        ],
        "attachment_suffixes": [".exe", ".dll", ".bin", ".elf", ".so", ".jar", ".apk", ".ipa", ".class"],
        "knowledge_topics": ["tools", "dynamic-debug", "patterns", "languages", "anti-analysis"],
        "top_tactics": [
            "先抽字符串、常量、导入和平台信息，再决定是否进入 GUI 逆向。",
            "优先寻找校验、解密、比较、控制流平坦化或自定义虚拟机入口。",
            "对语言特征、打包痕迹、反调试和补丁恢复保持显式假设。",
            "把动态调试和远程分析结果固化成最小复现脚本。",
        ],
        "reference_docs": _docs(
            "ctf-reverse/SKILL.md",
            "ctf-reverse/tools.md",
            "ctf-reverse/tools-dynamic.md",
            "ctf-reverse/patterns.md",
            "ctf-reverse/patterns-ctf.md",
            "ctf-reverse/languages-compiled.md",
            "ctf-reverse/anti-analysis.md",
        ),
        "recommended_tools": COMMON_BINARY_TOOLS + ["imhex"],
        "recommended_mcp": ["ida-pro-mcp", "ghidra-mcp"],
        "recommended_remote_templates": ["binary-analysis"],
        "profile_goal": "中文输出，围绕校验逻辑、解密逻辑、补丁点和脚本还原推进到 flag。",
        "profile_capabilities": [
            "静态字符串与模式定位",
            "反调试和语言特征识别",
            "逆向 MCP / 动态调试协同",
            "远程分析模板与复现脚本",
        ],
        "profile_notes": [
            "先用轻量手段缩小范围，再进入 GUI/MCP 深挖。",
        ],
    },
    "reverse": {
        "label": "CTF Reverse Playbook",
        "solver": "binary",
        "aliases": ["reverse", "rev", "逆向", "反编译"],
        "keywords": ["reverse", "reversing", "decompile", "逆向", "反编译", "anti debug", "vm"],
        "attachment_suffixes": [".exe", ".dll", ".bin", ".elf", ".so", ".jar", ".apk", ".ipa", ".class"],
        "knowledge_topics": ["tools", "dynamic-debug", "patterns", "languages", "anti-analysis"],
        "top_tactics": [
            "先抽字符串、常量、导入和平台信息，再决定是否进入 GUI 逆向。",
            "优先寻找校验、解密、比较、控制流平坦化或自定义虚拟机入口。",
            "对语言特征、打包痕迹、反调试和补丁恢复保持显式假设。",
            "把动态调试和远程分析结果固化成最小复现脚本。",
        ],
        "reference_docs": _docs(
            "ctf-reverse/SKILL.md",
            "ctf-reverse/tools.md",
            "ctf-reverse/tools-dynamic.md",
            "ctf-reverse/patterns.md",
            "ctf-reverse/patterns-ctf.md",
            "ctf-reverse/languages-compiled.md",
            "ctf-reverse/anti-analysis.md",
        ),
        "recommended_tools": COMMON_BINARY_TOOLS + ["imhex"],
        "recommended_mcp": ["ida-pro-mcp", "ghidra-mcp"],
        "recommended_remote_templates": ["binary-analysis"],
        "profile_goal": "中文输出，围绕校验逻辑、解密逻辑、补丁点和脚本还原推进到 flag。",
        "profile_capabilities": [
            "静态字符串与模式定位",
            "反调试和语言特征识别",
            "逆向 MCP / 动态调试协同",
            "远程分析模板与复现脚本",
        ],
        "profile_notes": [
            "先用轻量手段缩小范围，再进入 GUI/MCP 深挖。",
        ],
    },
    "crypto": {
        "label": "CTF Crypto Playbook",
        "solver": "crypto",
        "aliases": ["crypto", "cryptography", "密码", "rsa", "ecc"],
        "keywords": [
            "crypto",
            "cipher",
            "rsa",
            "ecc",
            "ecdh",
            "prng",
            "mersenne",
            "cbc",
            "ctr",
            "xor",
            "padding oracle",
            "modulus",
            "lattice",
            "base64",
            "hash",
            "签名",
            "密码学",
        ],
        "attachment_suffixes": [".sage", ".sage.py", ".py", ".txt", ".pem", ".pub", ".enc"],
        "knowledge_topics": ["encodings", "classic-ciphers", "modern-ciphers", "rsa-attacks", "prng"],
        "top_tactics": [
            "先判断是编码题、古典密码、现代分组模式、RSA/ECC 还是 PRNG。",
            "优先抽已知参数、明密文关系、模数/指数、nonce/IV 和随机数状态。",
            "把可快速验证的编码与低成本攻击优先跑完，再进入数学攻击。",
            "需要时使用远程 Python/Sage 模板验证假设。",
        ],
        "reference_docs": _docs(
            "ctf-crypto/SKILL.md",
            "ctf-crypto/classic-ciphers.md",
            "ctf-crypto/modern-ciphers.md",
            "ctf-crypto/rsa-attacks.md",
            "ctf-crypto/prng.md",
        ),
        "recommended_tools": ["python", "strings", "run_local_tool"],
        "recommended_mcp": [],
        "recommended_remote_templates": ["binary-analysis"],
        "profile_goal": "中文输出，先识别密码体制，再按最快可验证路径推进到 flag。",
        "profile_capabilities": [
            "编码/古典/现代密码判别",
            "RSA/PRNG 攻击路径建议",
            "参数抽取与数学验证",
        ],
        "profile_notes": [
            "先做轻量编码与参数识别，不直接跳进重数学。",
        ],
    },
    "forensics": {
        "label": "CTF Forensics Playbook",
        "solver": "forensics",
        "aliases": ["forensics", "forensic", "取证", "流量", "内存", "磁盘"],
        "keywords": [
            "forensics",
            "pcap",
            "memory",
            "disk",
            "registry",
            "timeline",
            "stego",
            "metadata",
            "取证",
            "流量",
            "内存",
            "镜像",
            "磁盘",
            "隐写",
        ],
        "attachment_suffixes": [".pcap", ".pcapng", ".raw", ".img", ".dd", ".mem", ".vmem", ".evtx"],
        "knowledge_topics": ["network", "disk-and-memory", "linux-forensics", "windows", "steganography"],
        "top_tactics": [
            "先判定附件属于流量、磁盘、内存、文档、图片还是混合型取证。",
            "优先提取时间线、对象文件、会话数据、元数据和隐藏内容。",
            "对 stego、日志、注册表、浏览器痕迹和恢复文件保持显式假设。",
            "把大文件处理留给远程主机或专用工具，不在聊天层重复推演。",
        ],
        "reference_docs": _docs(
            "ctf-forensics/SKILL.md",
            "ctf-forensics/network.md",
            "ctf-forensics/disk-and-memory.md",
            "ctf-forensics/linux-forensics.md",
            "ctf-forensics/windows.md",
            "ctf-forensics/steganography.md",
        ),
        "recommended_tools": COMMON_TRIAGE_TOOLS,
        "recommended_mcp": [],
        "recommended_remote_templates": ["binary-analysis"],
        "profile_goal": "中文输出，优先从元数据、时间线、对象恢复和隐藏数据中推进到 flag。",
        "profile_capabilities": [
            "流量/磁盘/内存/文档分类",
            "对象提取与 stego 假设",
            "远程主机处理大附件",
        ],
        "profile_notes": [
            "先做分类和对象抽取，再决定具体工具链。",
        ],
    },
    "osint": {
        "label": "CTF OSINT Playbook",
        "solver": "osint",
        "aliases": ["osint", "社工", "开源情报", "geolocation"],
        "keywords": [
            "osint",
            "twitter",
            "x.com",
            "instagram",
            "facebook",
            "dns",
            "whois",
            "geolocation",
            "maps",
            "social media",
            "开源情报",
            "社工",
            "地理定位",
        ],
        "attachment_suffixes": [".png", ".jpg", ".jpeg", ".webp", ".txt", ".html"],
        "knowledge_topics": ["social-media", "web-and-dns", "geolocation-and-media"],
        "top_tactics": [
            "先定义目标实体和已知线索，再拆成社媒、DNS/Web、地理信息三条线。",
            "优先抽唯一标识符、昵称、域名、邮箱、电话、图片背景和时间信息。",
            "保持证据链，避免把猜测当结论。",
        ],
        "reference_docs": _docs(
            "ctf-osint/SKILL.md",
            "ctf-osint/social-media.md",
            "ctf-osint/web-and-dns.md",
            "ctf-osint/geolocation-and-media.md",
        ),
        "recommended_tools": ["browser", "strings", "exiftool", "run_local_tool"],
        "recommended_mcp": ["browser-use"],
        "recommended_remote_templates": ["http-replay"],
        "profile_goal": "中文输出，围绕目标实体和公开线索建立可复查的证据链。",
        "profile_capabilities": [
            "实体与线索拆分",
            "社媒/DNS/地理定位路线建议",
            "图片元数据与浏览器调查",
        ],
        "profile_notes": [
            "需要保留证据链与来源，不直接下定论。",
        ],
    },
    "malware": {
        "label": "CTF Malware Playbook",
        "solver": "malware",
        "aliases": ["malware", "恶意代码", "c2", "样本分析"],
        "keywords": [
            "malware",
            "powershell",
            "dropper",
            "loader",
            "shellcode",
            "c2",
            "beacon",
            "dotnet",
            "obfuscation",
            "packed",
            "恶意",
            "混淆",
            "样本",
        ],
        "attachment_suffixes": [".exe", ".dll", ".ps1", ".vbs", ".js", ".bin", ".zip"],
        "knowledge_topics": ["scripts-and-obfuscation", "pe-and-dotnet", "c2-and-protocols"],
        "top_tactics": [
            "先区分脚本型、PE/.NET、shellcode 还是打包样本。",
            "优先抽配置、C2、解密层、协议特征和落地行为。",
            "需要时切到逆向 MCP，但先保留快速 IOC 和配置恢复路径。",
        ],
        "reference_docs": _docs(
            "ctf-malware/SKILL.md",
            "ctf-malware/scripts-and-obfuscation.md",
            "ctf-malware/pe-and-dotnet.md",
            "ctf-malware/c2-and-protocols.md",
        ),
        "recommended_tools": COMMON_TRIAGE_TOOLS + ["ida64", "ghidra"],
        "recommended_mcp": ["ida-pro-mcp", "ghidra-mcp"],
        "recommended_remote_templates": ["binary-analysis"],
        "profile_goal": "中文输出，优先恢复配置、协议和关键行为，再决定是否重逆向。",
        "profile_capabilities": [
            "脚本与样本分类",
            "配置/C2/协议提取",
            "逆向与远程分析协同",
        ],
        "profile_notes": [
            "先拿 IOC 和配置，再进入深逆向。",
        ],
    },
    "misc": {
        "label": "CTF Misc Playbook",
        "solver": "misc",
        "aliases": ["misc", "miscellaneous", "杂项", "编码", "jail"],
        "keywords": [
            "misc",
            "base64",
            "encoding",
            "jail",
            "sandbox",
            "dns",
            "rf",
            "sdr",
            "qr",
            "game",
            "vm",
            "bashjail",
            "pyjail",
            "miscellaneous",
            "编码",
            "沙箱",
            "二维码",
        ],
        "attachment_suffixes": [".txt", ".zip", ".7z", ".png", ".jpg", ".pcap", ".wav", ".iq"],
        "knowledge_topics": ["encodings", "pyjails", "bashjails", "dns", "rf-sdr", "games-and-vms"],
        "top_tactics": [
            "先判定是否是编码、jail、游戏/虚拟机、DNS、RF/SDR 或混合附件题。",
            "优先跑低成本字符串、编码、元数据和压缩包梳理。",
            "把最可能的 follow-up 路径写清楚，再决定是否切到专门工具或远程主机。",
        ],
        "reference_docs": _docs(
            "ctf-misc/SKILL.md",
            "ctf-misc/encodings.md",
            "ctf-misc/pyjails.md",
            "ctf-misc/bashjails.md",
            "ctf-misc/dns.md",
            "ctf-misc/rf-sdr.md",
            "ctf-misc/games-and-vms.md",
        ),
        "recommended_tools": COMMON_TRIAGE_TOOLS,
        "recommended_mcp": [],
        "recommended_remote_templates": [],
        "profile_goal": "中文输出，先把题目归到具体子类，再沿最短路径推进到 flag。",
        "profile_capabilities": [
            "编码/隐写/jail/DNS/RF 等杂项分类",
            "工具链推荐",
            "follow-up 路径收敛",
        ],
        "profile_notes": [
            "不要把 misc 当成默认垃圾桶，先强制分类。",
        ],
    },
}


_ALIAS_TO_CATEGORY = {}
for _category, _pack in SKILLPACKS.items():
    _ALIAS_TO_CATEGORY[_category] = _category
    for _alias in _pack.get("aliases", []):
        _ALIAS_TO_CATEGORY[str(_alias).strip().lower()] = _category


_EXECUTION_DEFAULTS = {
    "web": {
        "execution_mode": "inline",
        "allowed_tools": ["http_request", "browse_url", "read_file", "diff_http", "scan_for_flags", "search_knowledge", "plan_parallel"],
        "fastest_allowed_tools": ["http_request", "browse_url", "scan_for_flags", "diff_http"],
        "denied_tools": ["run_remote_command"],
        "default_budget": {"max_steps": 8, "max_tool_calls": 4, "max_tokens": 2000000, "timeout_sec": 90},
    },
    "pwn": {
        "execution_mode": "inline",
        "allowed_tools": ["read_file", "run_python", "run_remote_python", "run_remote_command", "decompile_function", "scan_for_flags", "search_knowledge", "plan_parallel"],
        "fastest_allowed_tools": ["run_remote_python", "run_remote_command", "run_python", "scan_for_flags"],
        "denied_tools": [],
        "default_budget": {"max_steps": 8, "max_tool_calls": 4, "max_tokens": 2000000, "timeout_sec": 120},
    },
    "re": {
        "execution_mode": "subagent",
        "allowed_tools": ["read_file", "run_python", "decompile_function", "scan_for_flags", "search_knowledge", "plan_parallel"],
        "fastest_allowed_tools": ["read_file", "decompile_function", "run_python", "scan_for_flags"],
        "denied_tools": [],
        "default_budget": {"max_steps": 8, "max_tool_calls": 4, "max_tokens": 2000000, "timeout_sec": 120},
    },
    "reverse": {
        "execution_mode": "subagent",
        "allowed_tools": ["read_file", "run_python", "decompile_function", "scan_for_flags", "search_knowledge", "plan_parallel"],
        "fastest_allowed_tools": ["read_file", "decompile_function", "run_python", "scan_for_flags"],
        "denied_tools": [],
        "default_budget": {"max_steps": 8, "max_tool_calls": 4, "max_tokens": 2000000, "timeout_sec": 120},
    },
    "crypto": {
        "execution_mode": "inline",
        "allowed_tools": ["read_file", "run_python", "scan_for_flags", "search_knowledge", "plan_parallel"],
        "fastest_allowed_tools": ["read_file", "run_python", "scan_for_flags"],
        "denied_tools": [],
        "default_budget": {"max_steps": 8, "max_tool_calls": 4, "max_tokens": 2000000, "timeout_sec": 90},
    },
    "forensics": {
        "execution_mode": "subagent",
        "allowed_tools": ["read_file", "extract_archive", "run_python", "scan_for_flags", "search_knowledge", "plan_parallel"],
        "fastest_allowed_tools": ["read_file", "extract_archive", "scan_for_flags"],
        "denied_tools": ["run_remote_command"],
        "default_budget": {"max_steps": 8, "max_tool_calls": 4, "max_tokens": 2000000, "timeout_sec": 120},
    },
    "osint": {
        "execution_mode": "subagent",
        "allowed_tools": ["browse_url", "http_request", "read_file", "scan_for_flags", "search_knowledge", "plan_parallel"],
        "fastest_allowed_tools": ["browse_url", "http_request", "scan_for_flags"],
        "denied_tools": [],
        "default_budget": {"max_steps": 8, "max_tool_calls": 4, "max_tokens": 2000000, "timeout_sec": 90},
    },
    "malware": {
        "execution_mode": "subagent",
        "allowed_tools": ["read_file", "run_python", "decompile_function", "scan_for_flags", "search_knowledge", "plan_parallel"],
        "fastest_allowed_tools": ["read_file", "decompile_function", "scan_for_flags"],
        "denied_tools": [],
        "default_budget": {"max_steps": 8, "max_tool_calls": 4, "max_tokens": 2000000, "timeout_sec": 120},
    },
    "misc": {
        "execution_mode": "inline",
        "allowed_tools": ["read_file", "extract_archive", "run_python", "scan_for_flags", "search_knowledge", "plan_parallel"],
        "fastest_allowed_tools": ["read_file", "extract_archive", "run_python", "scan_for_flags"],
        "denied_tools": [],
        "default_budget": {"max_steps": 8, "max_tool_calls": 4, "max_tokens": 2000000, "timeout_sec": 90},
    },
}


def _apply_execution_defaults(pack, speed_mode="standard"):
    category = str(pack.get("category") or "").strip().lower() or "misc"
    defaults = deepcopy(_EXECUTION_DEFAULTS.get(category, _EXECUTION_DEFAULTS["misc"]))
    pack.setdefault("execution_mode", defaults.get("execution_mode", "inline"))
    pack.setdefault("allowed_tools", list(defaults.get("allowed_tools", [])))
    pack.setdefault("denied_tools", list(defaults.get("denied_tools", [])))
    pack.setdefault("default_budget", dict(defaults.get("default_budget", {})))
    pack.setdefault("preferred_mcp", list(pack.get("recommended_mcp", [])))
    pack.setdefault("preferred_remote_templates", list(pack.get("recommended_remote_templates", [])))
    pack.setdefault(
        "initial_prompt_template",
        "Focus on {category}. Goal: {goal}. Start from the cheapest high-signal path and write evidence back to the workspace.",
    )
    pack.setdefault(
        "followup_prompt_template",
        "Continue from the current findings. Prefer the shortest reproducible path and avoid repeating exhausted branches.",
    )
    if str(speed_mode or "").strip().lower() == "fastest":
        pack["allowed_tools"] = list(defaults.get("fastest_allowed_tools", pack.get("allowed_tools", [])))
        pack["denied_tools"] = sorted(set(list(pack.get("denied_tools", [])) + ["search_knowledge", "plan_parallel"]))
    return pack


def supported_categories():
    return list(SKILLPACKS.keys())


def normalize_category(category):
    raw = str(category or "").strip().lower()
    if not raw:
        return ""
    return _ALIAS_TO_CATEGORY.get(raw, raw if raw in SKILLPACKS else "")


def get_skillpack(category, default="misc", speed_mode="standard"):
    normalized = normalize_category(category) or default
    pack = deepcopy(SKILLPACKS.get(normalized, SKILLPACKS[default]))
    pack["category"] = normalized
    pack["knowledge_pack"] = {
        "enabled": True,
        "name": KNOWLEDGE_PACK_NAME,
        "mode": KNOWLEDGE_PACK_MODE,
        "version": KNOWLEDGE_PACK_VERSION,
        "root": str(EMBEDDED_SKILLS_ROOT),
    }
    goal = str(pack.get("profile_goal", "") or "").strip()
    pack = _apply_execution_defaults(pack, speed_mode=speed_mode)
    pack["initial_prompt_template"] = str(pack.get("initial_prompt_template", "")).format(
        category=normalized,
        goal=goal or normalized,
    )
    return pack


def build_knowledge_selection(task_text="", target="", attachments=None, explicit_category=None):
    from ctf_agent.knowledge.skill_resolver import SkillResolver

    resolver = SkillResolver()
    resolution = resolver.resolve(
        task_text=task_text,
        target=target,
        attachments=attachments,
        explicit_category=explicit_category,
        speed_mode="standard",
    )
    return resolver.to_legacy_selection(resolution)
