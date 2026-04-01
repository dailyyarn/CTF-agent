import re


class FlagVerifier(object):
    DEFAULT_PATTERNS = [
        r"flag\{[^{}\n]+\}",
        r"FLAG\{[^{}\n]+\}",
        r"ctf\{[^{}\n]+\}",
        r"aliyunctf\{[^{}\n]+\}",
    ]
    SOURCE_PRIORITY = {
        "binary:validated-ret2win": 120,
        "binary:validated-format-string": 118,
        "binary:validated-stack-overflow": 116,
        "binary:validated-rop": 114,
        "binary:validated-xor-transform": 112,
        "binary:validated-string-check": 110,
        "binary:validated-": 109,
        "binary:remote-runner": 108,
        "binary:reverse-mcp": 104,
        "binary:decoded": 100,
        "binary:strings": 96,
        "web:oob": 94,
        "specialized:forensics": 92,
        "specialized:crypto": 90,
        "specialized:malware": 88,
        "specialized:misc": 86,
    }

    def __init__(self):
        self._compiled_defaults = [re.compile(item) for item in self.DEFAULT_PATTERNS]

    def discover_from_text(self, text):
        if not text:
            return []

        matches = []
        for pattern in self._compiled_defaults:
            matches.extend(pattern.findall(text))
        filtered = []
        seen = set()
        for item in matches:
            value = str(item or "").strip()
            if not value:
                continue
            if self._looks_like_placeholder(value):
                continue
            if value in seen:
                continue
            seen.add(value)
            filtered.append(value)
        return sorted(filtered)

    def match_format(self, flag, flag_format):
        if not flag:
            return False

        if flag_format:
            try:
                return re.fullmatch(flag_format, flag) is not None
            except re.error:
                return flag_format in flag

        return bool(self.discover_from_text(flag))

    def choose_best(self, state, challenge):
        candidates = sorted(
            state.candidate_flags,
            key=lambda item: (item.reproducible, self._source_priority(item.source), item.confidence),
            reverse=True,
        )

        for item in candidates:
            if self.match_format(item.value, challenge.flag_format):
                return item
        return None

    def _source_priority(self, source):
        text = str(source or "").strip().lower()
        if not text:
            return 0
        if text in self.SOURCE_PRIORITY:
            return self.SOURCE_PRIORITY[text]
        for prefix, value in self.SOURCE_PRIORITY.items():
            if text.startswith(prefix):
                return value
        return 0

    def _looks_like_placeholder(self, value):
        text = str(value or "")
        lowered = text.lower()
        placeholder_tokens = ["%s", "%d", "%p", "%x", "%n", "{0}", "{1}", "<flag>", "your_flag_here"]
        if any(token in lowered for token in placeholder_tokens):
            return True
        inner = text[text.find("{") + 1:text.rfind("}")] if "{" in text and "}" in text else text
        if "'" in inner or '"' in inner:
            return True
        return False
