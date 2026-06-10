# JMeter Auto Correlation + OpenAI RAG

This Streamlit app accepts only a recorded JMeter `.jmx` upload and generates a safer `auto_correlated.jmx`.
It also includes an OpenAI-powered RAG assistant that can answer questions from the uploaded JMX, generated JMX, correlation report, and optional extra files.

## Run

```bash
cd jmeter_correlation_streamlit
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Windows PowerShell:

```powershell
cd jmeter_correlation_streamlit
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

## OpenAI key

Use either the sidebar field or an environment variable:

```bash
export OPENAI_API_KEY="sk-..."
streamlit run app.py
```

PowerShell:

```powershell
$env:OPENAI_API_KEY="sk-..."
streamlit run app.py
```

## What this version fixes

The previous generated script could corrupt the JMX by correlating short/static values such as `0`, `1`, and version strings, causing replacements like `${AUTHUSER}` inside user agents, URLs, hashes, and timestamps.

This version uses safe mode:

- No global substring replacement across the JMX.
- No correlation for emails, usernames, passwords, OTPs, captcha fields, API keys, browser headers, short numeric values, or version strings.
- Replaces only exact values for matching dynamic parameter/header/body keys.
- Repairs common invalid XML/JMX characters before parsing.
- Removes unsupported third-party correlation plugin classes, including `io.github.vasanthshanmugam.jmeter.plugins.correlation.CorrelationPostProcessor`.
- Uses stock JMeter components: `HTTP Cookie Manager`, `User Defined Variables`, and `JSR223PostProcessor` with Groovy.

## Recommended workflow

1. Upload the original recorded JMX, not a previously corrupted generated JMX.
2. Download `auto_correlated.jmx`.
3. Open it in JMeter 5.4.3 or later.
4. Use the RAG tab to ask questions about correlation candidates, variables, samplers, removed plugins, and errors.

## Files

- `app.py` - Streamlit UI.
- `jmx_auto_correlator.py` - safe JMX repair and auto-correlation engine.
- `rag_engine.py` - OpenAI embeddings and Responses API RAG engine with keyword fallback.
- `sample_recorded.jmx` - bundled sample.
