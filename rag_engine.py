from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from typing import Any


class RagError(Exception):
    pass


@dataclass
class RagChunk:
    source: str
    chunk_id: int
    text: str

    @property
    def label(self) -> str:
        return f"{self.source}#chunk-{self.chunk_id}"

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "chunk_id": self.chunk_id, "label": self.label, "text": self.text}


def safe_decode(data: bytes | None) -> str:
    if not data:
        return ""
    return data.decode("utf-8", errors="replace")


def normalize_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n{5,}", "\n\n\n", text)
    return text.strip()


def chunk_text(source: str, text: str, chunk_chars: int = 3200, overlap: int = 350) -> list[RagChunk]:
    text = normalize_text(text)
    if not text:
        return []
    if overlap >= chunk_chars:
        raise ValueError("overlap must be smaller than chunk_chars")
    chunks: list[RagChunk] = []
    start = 0
    chunk_id = 1
    while start < len(text):
        end = min(len(text), start + chunk_chars)
        if end < len(text):
            split_at = text.rfind("\n", start + int(chunk_chars * 0.55), end)
            if split_at > start:
                end = split_at
        body = text[start:end].strip()
        if body:
            chunks.append(RagChunk(source=source, chunk_id=chunk_id, text=body))
            chunk_id += 1
        if end >= len(text):
            break
        start = max(0, end - overlap)
    return chunks


def build_corpus(
    uploaded_name: str,
    uploaded_jmx: bytes | None,
    correlated_jmx: bytes | None,
    report_json: bytes | None,
    extra_files: list[tuple[str, bytes]] | None = None,
) -> list[RagChunk]:
    docs: list[tuple[str, str]] = []
    if uploaded_jmx:
        docs.append((uploaded_name or "uploaded_recorded.jmx", safe_decode(uploaded_jmx)))
    if correlated_jmx:
        docs.append(("auto_correlated.jmx", safe_decode(correlated_jmx)))
    if report_json:
        docs.append(("auto_correlation_report.json", safe_decode(report_json)))
    help_text = """
JMeter Auto Correlation + RAG project notes:
- The app accepts a recorded JMX upload and generates auto_correlated.jmx.
- Invalid XML characters and unsupported third-party correlation plugin classes are removed before generation.
- Safe correlation mode avoids replacing static short values like 0/1, version strings, browser headers, API keys, usernames, emails, and passwords.
- The generated JMX uses stock JMeter components: HTTP Cookie Manager, User Defined Variables, and JSR223PostProcessor with Groovy.
- The RAG assistant indexes the uploaded JMX, generated JMX, correlation report, and optional extra files.
""".strip()
    docs.append(("project_help.md", help_text))
    for name, data in extra_files or []:
        docs.append((name, safe_decode(data)))

    chunks: list[RagChunk] = []
    for source, text in docs:
        chunks.extend(chunk_text(source, text))
    return chunks


def fingerprint(chunks: list[RagChunk], embedding_model: str) -> str:
    h = hashlib.sha256()
    h.update(embedding_model.encode("utf-8"))
    for chunk in chunks:
        h.update(chunk.source.encode("utf-8", errors="ignore"))
        h.update(str(chunk.chunk_id).encode("ascii"))
        h.update(chunk.text.encode("utf-8", errors="ignore"))
    return h.hexdigest()


def get_openai_client(api_key: str | None):
    key = (api_key or os.getenv("OPENAI_API_KEY") or "").strip()
    if not key:
        raise RagError("OpenAI API key is required. Enter it in the sidebar or set OPENAI_API_KEY before running Streamlit.")
    try:
        from openai import OpenAI
    except Exception as exc:
        raise RagError("The openai package is not installed. Run: pip install -r requirements.txt") from exc
    return OpenAI(api_key=key)


def embed_texts(api_key: str | None, texts: list[str], model: str, batch_size: int = 64) -> list[list[float]]:
    if not texts:
        return []
    client = get_openai_client(api_key)
    vectors: list[list[float]] = []
    for start in range(0, len(texts), batch_size):
        batch = texts[start:start + batch_size]
        try:
            response = client.embeddings.create(model=model, input=batch)
        except Exception as exc:
            raise RagError(f"OpenAI embeddings request failed: {exc}") from exc
        for item in response.data:
            vectors.append(list(item.embedding))
    return vectors


def build_openai_index(api_key: str | None, chunks: list[RagChunk], embedding_model: str) -> dict[str, Any]:
    if not chunks:
        raise RagError("No text is available to index.")
    vectors = embed_texts(api_key, [c.text for c in chunks], embedding_model)
    if len(vectors) != len(chunks):
        raise RagError("Embedding count did not match chunk count.")
    return {
        "mode": "openai_embeddings",
        "embedding_model": embedding_model,
        "fingerprint": fingerprint(chunks, embedding_model),
        "chunks": [c.to_dict() for c in chunks],
        "embeddings": vectors,
    }


def dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def norm(a: list[float]) -> float:
    return math.sqrt(sum(x * x for x in a)) or 1.0


def cosine(a: list[float], b: list[float]) -> float:
    return dot(a, b) / (norm(a) * norm(b))


def retrieve_openai(api_key: str | None, index: dict[str, Any], query: str, top_k: int) -> list[dict[str, Any]]:
    chunks = index.get("chunks", [])
    embeddings = index.get("embeddings", [])
    if not chunks or not embeddings:
        return []
    embedding_model = index.get("embedding_model", "text-embedding-3-small")
    q = embed_texts(api_key, [query], embedding_model)[0]
    scored: list[dict[str, Any]] = []
    for chunk, emb in zip(chunks, embeddings):
        scored.append({**chunk, "score": cosine(q, emb)})
    scored.sort(key=lambda row: row["score"], reverse=True)
    return scored[:top_k]


def keyword_score(query: str, text: str) -> float:
    terms = [t for t in re.findall(r"[A-Za-z0-9_.$/-]{3,}", query.lower())]
    if not terms:
        return 0.0
    text_l = text.lower()
    hits = sum(text_l.count(t) for t in terms)
    unique = sum(1 for t in set(terms) if t in text_l)
    return float(unique * 4 + hits)


def retrieve_keyword(chunks: list[RagChunk], query: str, top_k: int) -> list[dict[str, Any]]:
    scored = []
    for c in chunks:
        score = keyword_score(query, c.text)
        if score > 0:
            scored.append({**c.to_dict(), "score": score})
    scored.sort(key=lambda row: row["score"], reverse=True)
    return scored[:top_k]


def format_context(retrieved: list[dict[str, Any]], max_chars: int = 16000) -> str:
    blocks: list[str] = []
    used = 0
    for idx, row in enumerate(retrieved, start=1):
        header = f"[S{idx}] Source: {row.get('label') or row.get('source')}\n"
        body = str(row.get("text", "")).strip()
        block = header + body
        remaining = max_chars - used
        if remaining <= 0:
            break
        if len(block) > remaining:
            block = block[:remaining] + "\n... truncated ..."
        blocks.append(block)
        used += len(block)
    return "\n\n---\n\n".join(blocks)


def extract_output_text(response: Any) -> str:
    output_text = getattr(response, "output_text", None)
    if output_text:
        return str(output_text)
    parts: list[str] = []
    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            text = getattr(content, "text", None)
            if text:
                parts.append(str(text))
    if parts:
        return "\n".join(parts)
    return str(response)


def answer_with_openai(api_key: str | None, question: str, retrieved: list[dict[str, Any]], model: str) -> str:
    if not retrieved:
        return "I could not find relevant project context for that question. Upload a JMX and build the RAG index first."
    client = get_openai_client(api_key)
    context = format_context(retrieved)
    instructions = (
        "You are a JMeter performance testing and correlation assistant. Answer only from the provided project context. "
        "Cite evidence as [S1], [S2], etc. If the context does not contain the answer, say what is missing. "
        "Do not reveal API keys or ask the user to paste secrets into the chat."
    )
    user_input = f"Project context:\n{context}\n\nQuestion:\n{question}"
    try:
        response = client.responses.create(model=model, instructions=instructions, input=user_input)
        return extract_output_text(response).strip()
    except AttributeError:
        try:
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": instructions},
                    {"role": "user", "content": user_input},
                ],
            )
            return completion.choices[0].message.content.strip()
        except Exception as exc:
            raise RagError(f"OpenAI chat completion request failed: {exc}") from exc
    except Exception as exc:
        raise RagError(f"OpenAI response request failed: {exc}") from exc


def answer_with_keyword_context(question: str, retrieved: list[dict[str, Any]]) -> str:
    if not retrieved:
        return "No matching local project text was found. Build the OpenAI RAG index or upload more context files."
    lines = ["Local keyword retrieval found these chunks. Build the OpenAI index for semantic answers.", ""]
    for idx, row in enumerate(retrieved, start=1):
        snippet = str(row.get("text", "")).strip().replace("\n", " ")
        if len(snippet) > 600:
            snippet = snippet[:600] + "..."
        lines.append(f"[S{idx}] {row.get('label')} - score {row.get('score'):.2f}\n{snippet}")
    return "\n\n".join(lines)
