"""Dual-source BM25 knowledge retrieval: skills (playbooks) + wiki (writeups).

Zero external dependencies — pure-Python BM25 with mixed CJK/Latin tokeniser.
Maintains two separate indices so that curated tactical skills and personal
experiential writeups can be queried independently or together.
"""

import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_K1 = 1.5
_B = 0.75
_MAX_CHUNK_CHARS = 2000
_MIN_CHUNK_CHARS = 40
_HEADING_RE = re.compile(r"^#{1,3}\s+", re.MULTILINE)
_CJK_RANGE = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]")
_LATIN_WORD = re.compile(r"[a-z0-9_]{2,}")
_IMAGE_LINK_RE = re.compile(r"!\[.*?\]\(.*?\)", re.S)
_HTML_TAG_RE = re.compile(r"<[^>]+>")

# Map directory names to canonical CTF categories
_CATEGORY_MAP = {
    "pwn": "pwn", "heap": "pwn", "rop": "pwn", "iot": "pwn",
    "linux": "pwn", "glibc": "pwn",
    "web": "web", "http": "web", "sql": "web",
    "reverse": "reverse", "re": "reverse",
    "misc": "misc", "stego": "misc",
    "crypto": "crypto", "rsa": "crypto",
    "forensic": "forensics", "pcap": "forensics", "network": "forensics",
    "malware": "malware",
    "osint": "osint",
}


def _tokenize(text):
    """Mixed tokeniser: Latin words + CJK unigrams + CJK bigrams."""
    lowered = text.lower()
    tokens = _LATIN_WORD.findall(lowered)
    cjk = _CJK_RANGE.findall(lowered)
    tokens.extend(cjk)
    for i in range(len(cjk) - 1):
        tokens.append(cjk[i] + cjk[i + 1])
    return tokens


def _clean_markdown(text):
    """Strip images and HTML tags that add noise to indexing."""
    text = _IMAGE_LINK_RE.sub("", text)
    text = _HTML_TAG_RE.sub("", text)
    return text


class _Chunk:
    __slots__ = ("text", "source", "category", "heading", "tokens", "token_count")

    def __init__(self, text, source, category, heading):
        self.text = text
        self.source = source
        self.category = category
        self.heading = heading
        self.tokens = _tokenize(_clean_markdown(text) + " " + heading + " " + category)
        self.token_count = len(self.tokens)


class _BM25Index:
    """In-memory BM25 index."""

    def __init__(self, chunks):
        self.chunks = chunks
        self.n = len(chunks)
        self.avgdl = sum(c.token_count for c in chunks) / max(self.n, 1)
        self.df = Counter()
        for chunk in chunks:
            for token in set(chunk.tokens):
                self.df[token] += 1

    def query(self, query_text, top_k=5, category_hint=None):
        q_tokens = _tokenize(query_text)
        if not q_tokens:
            return []

        scored = []
        for idx, chunk in enumerate(self.chunks):
            cat_weight = 1.0
            if category_hint and chunk.category:
                if category_hint.lower() in chunk.category.lower():
                    cat_weight = 1.25
                else:
                    cat_weight = 0.7

            tf_map = Counter(chunk.tokens)
            score = 0.0
            for token in q_tokens:
                tf = tf_map.get(token, 0)
                if tf == 0:
                    continue
                df = self.df.get(token, 0)
                idf = math.log((self.n - df + 0.5) / (df + 0.5) + 1.0)
                numerator = tf * (_K1 + 1)
                denominator = tf + _K1 * (1 - _B + _B * chunk.token_count / self.avgdl)
                score += idf * numerator / denominator

            if score > 0:
                scored.append((score * cat_weight, idx))

        scored.sort(key=lambda x: -x[0])
        return [(self.chunks[i], s) for s, i in scored[:top_k]]


def _split_markdown(text, source, category):
    """Split a markdown document into chunks by headings."""
    parts = _HEADING_RE.split(text)
    headings = _HEADING_RE.findall(text)
    chunks = []
    current_heading = ""
    for i, part in enumerate(parts):
        if i > 0 and i - 1 < len(headings):
            current_heading = headings[i - 1].strip().strip("#").strip()
        part = part.strip()
        if len(part) < _MIN_CHUNK_CHARS:
            continue
        if len(part) > _MAX_CHUNK_CHARS:
            for j in range(0, len(part), _MAX_CHUNK_CHARS):
                sub = part[j:j + _MAX_CHUNK_CHARS]
                h = "{0} (part {1})".format(current_heading, j // _MAX_CHUNK_CHARS + 1) if j > 0 else current_heading
                chunks.append(_Chunk(sub, source, category, h))
        else:
            chunks.append(_Chunk(part, source, category, current_heading))
    if not chunks and len(text.strip()) >= _MIN_CHUNK_CHARS:
        chunks.append(_Chunk(text.strip()[:_MAX_CHUNK_CHARS], source, category, ""))
    return chunks


def _infer_category(filepath, root):
    rel = os.path.relpath(filepath, root).lower().replace("\\", "/")
    for token, cat in _CATEGORY_MAP.items():
        if token in rel:
            return cat
    return "general"


class KnowledgeRetriever:
    """
    Dual-source knowledge retriever.

    * **skills** – curated tactical playbooks (``embedded_ctf_skills/``)
    * **wiki** – personal writeups and study notes

    Both are indexed independently.  ``query()`` searches across both and
    merges results; ``query_skills()`` / ``query_wiki()`` search one source.
    """

    def __init__(self, skills_root=None, wiki_root=None):
        self._skills_root = skills_root
        self._wiki_root = wiki_root
        self._skills_index = None  # type: Optional[_BM25Index]
        self._wiki_index = None    # type: Optional[_BM25Index]
        self._loaded = False

    def load(self, skills_root=None, wiki_root=None):
        skills_root = skills_root or self._skills_root
        wiki_root = wiki_root or self._wiki_root
        skills_chunks = self._load_roots(skills_root, "skills")
        wiki_chunks = self._load_roots(wiki_root, "wiki")
        self._skills_index = _BM25Index(skills_chunks) if skills_chunks else None
        self._wiki_index = _BM25Index(wiki_chunks) if wiki_chunks else None
        self._loaded = True

    def is_loaded(self):
        return self._loaded

    def query(self, question, top_k=5, category_hint=None, source_filter=None):
        """
        Search across both knowledge sources.

        Returns list of dicts:
        ``{text, source_file, category, heading, score, source_type}``
        """
        if not self._loaded:
            self.load()

        results = []  # type: List[Dict[str, Any]]

        if source_filter != "wiki" and self._skills_index:
            for chunk, score in self._skills_index.query(question, top_k=top_k, category_hint=category_hint):
                results.append({
                    "text": chunk.text,
                    "source_file": chunk.source,
                    "category": chunk.category,
                    "heading": chunk.heading,
                    "score": score * 1.15,
                    "source_type": "skills",
                })

        if source_filter != "skills" and self._wiki_index:
            for chunk, score in self._wiki_index.query(question, top_k=top_k, category_hint=category_hint):
                results.append({
                    "text": chunk.text,
                    "source_file": chunk.source,
                    "category": chunk.category,
                    "heading": chunk.heading,
                    "score": score,
                    "source_type": "wiki",
                })

        results.sort(key=lambda r: -r["score"])
        return results[:top_k]

    def query_skills(self, question, top_k=5, category_hint=None):
        return self.query(question, top_k=top_k, category_hint=category_hint, source_filter="skills")

    def query_wiki(self, question, top_k=5, category_hint=None):
        return self.query(question, top_k=top_k, category_hint=category_hint, source_filter="wiki")

    @property
    def stats(self):
        return {
            "skills_chunks": self._skills_index.n if self._skills_index else 0,
            "wiki_chunks": self._wiki_index.n if self._wiki_index else 0,
            "loaded": self._loaded,
        }

    def _load_dir(self, root, source_type):
        root = str(root)
        chunks = []
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                if not fname.lower().endswith(".md"):
                    continue
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue
                if not content.strip():
                    continue
                category = _infer_category(fpath, root)
                source = "{0}:{1}".format(source_type, os.path.relpath(fpath, root).replace("\\", "/"))
                chunks.extend(_split_markdown(content, source, category))
        return chunks

    def _load_roots(self, roots, source_type):
        if roots in [None, "", []]:
            return []
        if isinstance(roots, (str, os.PathLike)):
            roots = [roots]
        chunks = []
        seen = set()
        for item in list(roots or []):
            root = str(item or "").strip()
            if not root or root in seen or not os.path.isdir(root):
                continue
            seen.add(root)
            chunks.extend(self._load_dir(root, source_type))
        return chunks
