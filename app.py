from __future__ import annotations

import json
import os
from pathlib import Path

import streamlit as st

from jmx_auto_correlator import (
    JmxAutoCorrelationError,
    auto_correlate_jmx_bytes,
    auto_preview_jmx_bytes,
    make_output_zip,
    run_jmeter_cli,
)
from rag_engine import (
    RagError,
    answer_with_keyword_context,
    answer_with_openai,
    build_corpus,
    build_openai_index,
    fingerprint,
    retrieve_keyword,
    retrieve_openai,
)


APP_DIR = Path(__file__).parent
SAMPLE_JMX_PATH = APP_DIR / "sample_recorded.jmx"

st.set_page_config(page_title="JMeter Auto Correlation + OpenAI RAG", layout="wide")


@st.cache_data(show_spinner=False)
def load_sample_jmx() -> bytes:
    return SAMPLE_JMX_PATH.read_bytes() if SAMPLE_JMX_PATH.exists() else b""


def limited_text(text: str, max_chars: int = 14000) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n... truncated in UI ..."


def get_uploaded_extra_files() -> list[tuple[str, bytes]]:
    files = st.session_state.get("rag_extra_files") or []
    result: list[tuple[str, bytes]] = []
    for file in files:
        result.append((file.name, file.getvalue()))
    return result


def generate_if_needed(jmx_bytes: bytes, jmx_name: str) -> None:
    current_key = (jmx_name, len(jmx_bytes), hash(jmx_bytes[:5000]))
    if st.session_state.get("last_generation_key") == current_key and "patched_jmx" in st.session_state:
        return
    with st.spinner("Repairing JMX, removing unsupported plugins, and applying safe auto-correlation..."):
        patched, summary, report = auto_correlate_jmx_bytes(jmx_bytes)
    st.session_state["last_generation_key"] = current_key
    st.session_state["uploaded_jmx_bytes"] = jmx_bytes
    st.session_state["uploaded_jmx_name"] = jmx_name
    st.session_state["patched_jmx"] = patched
    st.session_state["correlation_summary"] = summary.to_dict()
    st.session_state["report_json"] = report
    st.session_state.pop("rag_index", None)
    st.session_state.pop("rag_index_fingerprint", None)


def show_upload_area() -> tuple[bytes | None, str]:
    st.title("JMeter Auto Correlation + OpenAI RAG")
    st.caption("Upload only your recorded JMX. The app generates a safer auto-correlated JMX and lets you ask RAG questions about it.")

    uploaded = st.file_uploader("Upload JMX file", type=["jmx", "xml"], key="main_jmx_upload")
    use_sample = st.checkbox("Use bundled sample instead", value=False)

    if uploaded is not None:
        return uploaded.getvalue(), uploaded.name
    if use_sample:
        return load_sample_jmx(), "sample_recorded.jmx"
    return None, ""


def show_auto_tab(jmx_bytes: bytes | None, jmx_name: str) -> None:
    st.subheader("Auto Correlation")
    if not jmx_bytes:
        st.info("Upload a recorded JMX at the top of the page.")
        return

    try:
        generate_if_needed(jmx_bytes, jmx_name)
    except JmxAutoCorrelationError as exc:
        st.error(str(exc))
        st.warning("Use the original recorded JMX, not a previously corrupted generated file. The earlier unsafe output may have overwritten credentials or static URL characters.")
        return

    summary = st.session_state.get("correlation_summary", {})
    patched = st.session_state.get("patched_jmx", b"")
    report = st.session_state.get("report_json", b"{}")

    st.success("Generated auto_correlated.jmx using safe mode.")
    metrics = st.columns(7)
    metrics[0].metric("Samplers", summary.get("sampler_count", 0))
    metrics[1].metric("Candidates", summary.get("candidates_detected", 0))
    metrics[2].metric("Values", summary.get("original_values_detected", 0))
    metrics[3].metric("Nodes changed", summary.get("replacement_nodes_changed", 0))
    metrics[4].metric("Occurrences", summary.get("replacement_occurrences", 0))
    metrics[5].metric("Smart Capture", summary.get("smart_capture_processors_added", 0))
    metrics[6].metric("Plugins removed", summary.get("unsupported_plugin_elements_removed", 0))

    warnings = summary.get("warnings", [])
    if warnings:
        st.warning("\n".join(f"- {w}" for w in warnings))

    col1, col2, col3 = st.columns(3)
    with col1:
        st.download_button("Download auto_correlated.jmx", data=patched, file_name="auto_correlated.jmx", mime="application/xml", use_container_width=True)
    with col2:
        st.download_button("Download auto_correlation_report.json", data=report, file_name="auto_correlation_report.json", mime="application/json", use_container_width=True)
    with col3:
        st.download_button("Download package zip", data=make_output_zip(patched, report), file_name="auto_correlated_package.zip", mime="application/zip", use_container_width=True)

    with st.expander("Detected correlation candidates", expanded=True):
        candidates = summary.get("candidates", [])
        if candidates:
            rows = []
            for c in candidates:
                rows.append({
                    "variable": c.get("variable"),
                    "key": c.get("key"),
                    "category": c.get("category"),
                    "confidence": c.get("confidence"),
                    "values": len(c.get("original_values", [])),
                    "first sampler": c.get("first_sampler_name"),
                })
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.info("No safe dynamic values were detected.")

    with st.expander("Full correlation report", expanded=False):
        st.json(summary)

    with st.expander("Generated JMX preview", expanded=False):
        st.code(limited_text(patched.decode("utf-8", errors="replace")), language="xml")


def build_rag_chunks() -> list:
    return build_corpus(
        uploaded_name=st.session_state.get("uploaded_jmx_name", "uploaded.jmx"),
        uploaded_jmx=st.session_state.get("uploaded_jmx_bytes"),
        correlated_jmx=st.session_state.get("patched_jmx"),
        report_json=st.session_state.get("report_json"),
        extra_files=get_uploaded_extra_files(),
    )


def show_rag_tab(api_key: str, embedding_model: str, response_model: str, top_k: int) -> None:
    st.subheader("OpenAI RAG Assistant")
    st.caption("Ask questions about the uploaded JMX, generated auto_correlated.jmx, and auto-correlation report.")

    st.file_uploader(
        "Optional extra knowledge files",
        type=["txt", "log", "json", "xml", "jmx", "csv", "properties", "har", "md"],
        accept_multiple_files=True,
        key="rag_extra_files",
    )

    chunks = build_rag_chunks()
    st.write(f"Corpus chunks available: **{len(chunks)}**")
    current_fp = fingerprint(chunks, embedding_model) if chunks else ""

    col1, col2 = st.columns([1, 1])
    with col1:
        build_clicked = st.button("Build OpenAI RAG index", type="primary", use_container_width=True, disabled=not bool(chunks))
    with col2:
        clear_clicked = st.button("Clear chat/index", use_container_width=True)

    if clear_clicked:
        for key in ["rag_index", "rag_index_fingerprint", "rag_messages"]:
            st.session_state.pop(key, None)
        st.rerun()

    if build_clicked:
        if not api_key and not os.getenv("OPENAI_API_KEY"):
            st.error("Enter your OpenAI API key in the sidebar or set OPENAI_API_KEY.")
        else:
            try:
                with st.spinner("Creating embeddings with OpenAI..."):
                    st.session_state["rag_index"] = build_openai_index(api_key, chunks, embedding_model)
                    st.session_state["rag_index_fingerprint"] = current_fp
                st.success("OpenAI RAG index built.")
            except RagError as exc:
                st.error(str(exc))

    if st.session_state.get("rag_index_fingerprint") == current_fp and st.session_state.get("rag_index"):
        st.success("OpenAI index is ready for the current files.")
    elif st.session_state.get("rag_index"):
        st.warning("Files or model settings changed. Rebuild the OpenAI RAG index for best results.")
    else:
        st.info("Build the OpenAI RAG index to enable semantic retrieval. Keyword fallback still works without an index.")

    if "rag_messages" not in st.session_state:
        st.session_state["rag_messages"] = []

    for msg in st.session_state["rag_messages"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    question = st.chat_input("Ask about the JMX, correlation changes, errors, variables, or samplers")
    if question:
        st.session_state["rag_messages"].append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.markdown(question)

        with st.chat_message("assistant"):
            try:
                if st.session_state.get("rag_index") and st.session_state.get("rag_index_fingerprint") == current_fp:
                    retrieved = retrieve_openai(api_key, st.session_state["rag_index"], question, top_k)
                    answer = answer_with_openai(api_key, question, retrieved, response_model)
                else:
                    retrieved = retrieve_keyword(chunks, question, top_k)
                    answer = answer_with_keyword_context(question, retrieved)
                st.markdown(answer)
                with st.expander("Retrieved sources", expanded=False):
                    for i, row in enumerate(retrieved, start=1):
                        st.markdown(f"**[S{i}] {row.get('label')}** score `{row.get('score', 0):.4f}`")
                        st.code(limited_text(str(row.get("text", "")), 1200), language="text")
            except RagError as exc:
                answer = str(exc)
                st.error(answer)
        st.session_state["rag_messages"].append({"role": "assistant", "content": answer})


def show_validation_tab() -> None:
    st.subheader("Optional JMeter CLI validation")
    patched = st.session_state.get("patched_jmx")
    if not patched:
        st.info("Generate auto_correlated.jmx first.")
        return
    st.warning("Run this only on a trusted local machine. JMeter will send the recorded traffic from the Streamlit server.")
    c1, c2, c3 = st.columns(3)
    with c1:
        jmeter_bin = st.text_input("JMeter executable", value="jmeter")
    with c2:
        make_report = st.checkbox("Generate HTML report", value=False)
    with c3:
        timeout = st.number_input("Timeout seconds", min_value=30, max_value=7200, value=300, step=30)
    if st.button("Run JMeter CLI", type="primary", use_container_width=True):
        try:
            with st.spinner("Running JMeter CLI..."):
                st.session_state["jmeter_result"] = run_jmeter_cli(patched, jmeter_bin, make_report, int(timeout))
        except JmxAutoCorrelationError as exc:
            st.error(str(exc))

    result = st.session_state.get("jmeter_result")
    if result:
        st.markdown(f"**Exit code:** `{result.get('returncode')}`")
        st.code(result.get("command", ""), language="bash")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**stdout**")
            st.code(limited_text(result.get("stdout", "")), language="text")
        with c2:
            st.markdown("**stderr**")
            st.code(limited_text(result.get("stderr", "")), language="text")
        if result.get("jtl_bytes"):
            st.download_button("Download results.jtl", result["jtl_bytes"], "results.jtl", mime="text/csv", use_container_width=True)
        if result.get("report_zip_bytes"):
            st.download_button("Download html-report.zip", result["report_zip_bytes"], "html-report.zip", mime="application/zip", use_container_width=True)


def show_help_tab() -> None:
    st.subheader("Help")
    st.markdown(
        """
### Why the previous generated JMX failed
The earlier heuristic correlated very short static values such as `0` and version strings. That caused replacements like `${AUTHUSER}` inside browser headers, URLs, CSS file hashes, and timestamps. This version uses safe mode and only replaces exact values for matching parameter/header/body keys.

### Recommended usage
1. Upload the original recorded JMX, not a previously corrupted generated file.
2. Download `auto_correlated.jmx`.
3. Open the JMX in stock JMeter 5.4.3+.
4. Use the RAG tab to ask questions about the generated variables, removed plugins, or report.

### OpenAI RAG setup
Paste your OpenAI API key in the sidebar, or start Streamlit with `OPENAI_API_KEY` set as an environment variable.

### Safety rules applied by the generator
- Does not correlate emails, usernames, passwords, OTPs, or captcha values.
- Does not correlate `0`, `1`, booleans, numeric-only values, or version strings.
- Does not globally replace substrings across the entire JMX.
- Removes unsupported third-party correlation plugin elements.
- Uses stock JMeter `JSR223PostProcessor` and `HTTP Cookie Manager`.
        """
    )


with st.sidebar:
    st.header("OpenAI RAG settings")
    api_key = st.text_input("OpenAI API key", value=os.getenv("OPENAI_API_KEY", ""), type="password", help="Stored only in Streamlit session memory unless you set it as an environment variable.")
    embedding_model = st.selectbox("Embedding model", ["text-embedding-3-small", "text-embedding-3-large"], index=0)
    response_model = st.text_input("Response model", value="gpt-5-mini", help="Change this if your OpenAI project does not have access to the default model.")
    top_k = st.slider("Retrieved chunks", min_value=3, max_value=12, value=6)

jmx_bytes, jmx_name = show_upload_area()

tab_auto, tab_rag, tab_validation, tab_help = st.tabs(["Auto Correlation", "RAG Assistant", "Optional Validation", "Help"])

with tab_auto:
    show_auto_tab(jmx_bytes, jmx_name)

with tab_rag:
    if jmx_bytes and "patched_jmx" not in st.session_state:
        try:
            generate_if_needed(jmx_bytes, jmx_name)
        except JmxAutoCorrelationError:
            pass
    show_rag_tab(api_key, embedding_model, response_model, top_k)

with tab_validation:
    show_validation_tab()

with tab_help:
    show_help_tab()
