"""Personal library search (RAG). Everything here runs on this Mac.

A library item is a dict: name, text, notes, chunks (list of str), vecs (base64 float32 matrix or "" if not indexed), dim.
Embeddings come from the local Ollama model; if it is unavailable the library still works with keyword matching.
select() returns ordinary ingest.Document objects, so the pipeline (masking, routes, checks) is unchanged and the
cloud route still only ever sees masked, locally checked text.
"""
import base64
import re
from typing import Callable, Dict, List, Optional

import numpy as np


from . import config, egress, finance, providers
from .ingest import Document

CHUNK, OVERLAP, TOP_K = 800, 100, 5
WHOLE_LIMIT = 6000  # a library this small is sent whole; bigger ones are searched
BATCH = 32
_WORD = re.compile(r"[a-z0-9]{3,}")


def chunk(text: str) -> List[str]:
    text = text.strip()
    out, pos = [], 0
    while pos < len(text):
        end = min(len(text), pos + CHUNK)
        if end < len(text):  # prefer to cut at a line or sentence end near the limit
            cut = max(text.rfind("\n", pos, end), text.rfind(". ", pos, end))
            if cut > pos + CHUNK // 2:
                end = cut + 1
        out.append(text[pos:end].strip())
        if end >= len(text):
            break
        pos = max(end - OVERLAP, pos + 1)
    return [c for c in out if c]


def _profile() -> Dict[str, str]:
    prof = config.profile("embed")
    for url in [prof.get("base_url") or providers.default_base_url("ollama")] + [u for u, _ in providers.fallbacks(prof)]:
        if not providers.is_local_url(url):
            raise egress.EgressBlocked("Embeddings must run on this machine or a listed private-network Ollama address")
    return prof


def _embed_all(texts: List[str], embedder: Callable) -> np.ndarray:
    prof = _profile()
    rows: List[List[float]] = []
    for i in range(0, len(texts), BATCH):
        rows += embedder(prof, texts[i:i + BATCH])
    return np.asarray(rows, dtype=np.float32)


def build(name: str, text: str, notes: List[str], embedder: Optional[Callable] = None, kind: str = "file", chat: str = "",
          financial: str = "", summary: str = "") -> Dict:
    """Chunk and index one document. Never raises for an embedding failure: the item is then keyword-searched."""
    embedder = embedder or providers.embed  # looked up per call, not at import
    chunks = chunk(text)
    item = {"name": name, "text": text, "notes": list(notes), "chunks": chunks, "vecs": "", "dim": 0, "kind": kind, "chat": chat}
    if kind == "file":
        item.update(financial=financial, summary=summary)  # decided at intake, before chunking; chunks of such a file never go to a cloud
    try:
        m = _embed_all(chunks, embedder)
        item["vecs"], item["dim"] = base64.b64encode(m.tobytes()).decode(), int(m.shape[1])
        item["notes"].append("Indexed for search on this Mac.")
    except (providers.ProviderError, egress.EgressBlocked, ValueError, IndexError):
        item["notes"].append("Search index unavailable; keyword matching is used for this file.")
    return item


def _matrix(item: Dict) -> Optional[np.ndarray]:
    if not item.get("vecs"):
        return None
    return np.frombuffer(base64.b64decode(item["vecs"]), dtype=np.float32).reshape(-1, item["dim"])


def _keyword_scores(question: str, chunks: List[str]) -> List[float]:
    q = set(_WORD.findall(question.lower()))
    return [len(q & set(_WORD.findall(c.lower()))) / (1 + len(c) / 2000) for c in chunks]


_GENERIC = {"fake", "txt", "pdf", "file", "files", "statement", "statements", "document", "documents", "notes", "chat",
            "earlier", "summarise", "summarize", "claude", "please", "what", "with", "from", "that", "this", "about", "for", "and", "the", "my"}


def _tokens(s: str) -> set:
    return {t for t in re.findall(r"[a-z0-9]{2,}", s.lower().replace("-", "")) if t not in _GENERIC}


def relevant(question: str, library: List[Dict]) -> List[Dict]:
    """Of a library, the files the question is about: those (or whose folder) named in it, else those sharing its words.
    If nothing stands out, all of them. Keeps unrelated notes and old chats out of the context (and out of Claude's)."""
    if len(library) < 2:
        return library
    q = _tokens(question)
    named = [d for d in library if q & (_tokens(d["name"]) | _tokens(d.get("folder", "")))]  # a folder named in the question brings all its files
    if named:
        return named
    shared = [d for d in library if q & _tokens(d["text"])]
    return shared or library


def _financial(name: str, text: str):
    reason = finance.classify(name, text)
    return (reason, finance.sanitize(name, text).text if reason and finance.sanitize(name, text).ok else "")


def _doc(d: Dict, name: str = "", text: str = None) -> Document:
    """A library item as a Document. Files are classified here too, so items saved before intake classification existed are covered."""
    reason, summary = (d["financial"], d.get("summary", "")) if "financial" in d else (_financial(d["name"], d["text"]) if d.get("kind", "file") == "file" else ("", ""))
    return Document(name or d["name"], d["text"] if text is None else text, d["notes"] if text is None else [], reason, summary, d["name"] if reason else "")


def select(question: str, library: List[Dict], embedder: Optional[Callable] = None, k: int = TOP_K) -> List[Document]:
    """The documents (or best passages) to use for this question."""
    embedder = embedder or providers.embed
    library = relevant(question, library)
    if sum(len(d["text"]) for d in library) <= WHOLE_LIMIT:
        return [_doc(d) for d in library]
    flat = [(di, ci, c) for di, d in enumerate(library) for ci, c in enumerate(d["chunks"])]
    if not flat:
        return []
    scores: Optional[List[float]] = None
    mats = [_matrix(d) for d in library]
    if all(m is not None for m in mats) and len({m.shape[1] for m in mats}) == 1:
        try:
            qv = _embed_all([question], embedder)[0]
            allm = np.vstack(mats)
            denom = np.linalg.norm(allm, axis=1) * np.linalg.norm(qv)
            scores = list((allm @ qv) / np.maximum(denom, 1e-9))
        except (providers.ProviderError, egress.EgressBlocked, ValueError, IndexError):
            scores = None
    if scores is None:
        scores = _keyword_scores(question, [c for _, _, c in flat])
    top = sorted(sorted(range(len(flat)), key=lambda i: scores[i], reverse=True)[:k], key=lambda i: (flat[i][0], flat[i][1]))
    return [_doc(library[flat[i][0]], f"{library[flat[i][0]]['name']} (part {flat[i][1] + 1})", flat[i][2]) for i in top]
