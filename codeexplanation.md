Below is the explanation of how the project code is organized and how each part works.

## 1. Overall architecture

The application has three main responsibilities:

```text
Streamlit UI
   ↓
JMX auto-correlation engine
   ↓
OpenAI RAG assistant
```

So the project should be understood in three layers:

```text
app.py
    Handles the web page, file upload, tabs, buttons, downloads, and chat UI.

jmx_auto_correlator.py
    Handles JMX repair, safe auto-correlation, plugin cleanup, variable replacement,
    JSR223 Smart Capture insertion, report generation, and optional JMeter CLI run.

rag_engine.py
    Handles document chunking, OpenAI embeddings, retrieval, and OpenAI answer generation.
```

The important point is: **Streamlit does not perform the correlation itself**. It only calls functions from the backend Python files.

---

## 2. Important note about old vs new files

In the latest version, the app should use:

```python
from jmx_auto_correlator import (
    JmxAutoCorrelationError,
    auto_correlate_jmx_bytes,
    auto_preview_jmx_bytes,
    make_output_zip,
    run_jmeter_cli,
)

from rag_engine import (
    RagError,
    build_corpus,
    build_openai_index,
    retrieve_openai,
    retrieve_keyword,
    answer_with_openai,
    answer_with_keyword_context,
)
```

The older/manual version used:

```python
from jmx_correlator import ...
```

That older version had manual rule builder logic. For your current requirement, you should use the **fully automated version**, not the old rule-based `jmx_correlator.py`.

So:

```text
Use:
jmx_auto_correlator.py

Do not use for current flow:
jmx_correlator.py
sample_rules.json
manual rule builder code
```

If your Streamlit page still shows tabs like:

```text
Rule Builder
Patch JMX
Sampler Explorer
```

then you are running the old `app.py`.

For your expected version, the tabs should be more like:

```text
Auto Correlation
RAG Assistant
Optional Validation
Help
```

---

## 3. `app.py` explanation

`app.py` is the Streamlit web application.

Its job is to:

```text
1. Show upload option.
2. Read uploaded JMX file.
3. Call the auto-correlation engine.
4. Show summary metrics.
5. Provide download buttons.
6. Show RAG assistant on the same page.
7. Optionally run JMeter CLI for validation.
```

### Main upload flow

The upload widget should look like this:

```python
uploaded = st.file_uploader(
    "Upload recorded JMX",
    type=["jmx", "xml"]
)
```

When the user uploads a file:

```python
jmx_bytes = uploaded.getvalue()
```

The app sends those bytes to the backend:

```python
patched_jmx, summary, report_json = auto_correlate_jmx_bytes(jmx_bytes)
```

That one call does all correlation work.

Then the UI shows download buttons:

```python
st.download_button(
    "Download auto_correlated.jmx",
    data=patched_jmx,
    file_name="auto_correlated.jmx",
    mime="application/xml"
)
```

and:

```python
st.download_button(
    "Download auto_correlation_report.json",
    data=report_json,
    file_name="auto_correlation_report.json",
    mime="application/json"
)
```

The UI does not ask for manual rules.

---

## 4. `jmx_auto_correlator.py` explanation

This is the most important file for JMeter automation.

It is responsible for converting this:

```text
Recorded JMX with hard-coded dynamic values
```

into this:

```text
Safe auto-correlated JMX with variables and runtime capture logic
```

---

# 4.1 Error class

```python
class JmxAutoCorrelationError(Exception):
    pass
```

This is a custom exception used by the app. Instead of showing raw Python errors, the Streamlit UI can catch this and show a clean error message.

Example:

```python
try:
    patched_jmx, summary, report_json = auto_correlate_jmx_bytes(jmx_bytes)
except JmxAutoCorrelationError as exc:
    st.error(str(exc))
```

---

# 4.2 Data classes

The file uses data classes to organize information.

### `XmlRepairReport`

```python
@dataclass
class XmlRepairReport:
    decode_encoding: str = "utf-8-sig"
    invalid_decode_bytes_replaced: bool = False
    leading_bytes_removed: int = 0
    invalid_numeric_character_references_removed: int = 0
    raw_invalid_xml_characters_removed: int = 0
    unescaped_ampersands_escaped: int = 0
```

This stores what was repaired in the uploaded JMX.

It helps with errors like:

```text
reference to invalid character number
invalid XML character
unescaped &
broken encoded body
```

So when a bad JMX is uploaded, the app does not fail immediately. It tries to repair the XML first.

---

### `Candidate`

```python
@dataclass
class Candidate:
    variable: str
    key: str
    category: str
    confidence: float
    reason: str
    first_sampler_index: int
    first_sampler_name: str
    original_values: set[str]
    raw_values: set[str]
    locations: list[str]
    capture_keys: set[str]
```

A `Candidate` means:

```text
This value looks dynamic and may need correlation.
```

Example:

```text
key: csrf_token
value: abc123xyz789...
variable: CSRF_TOKEN
category: csrf
```

The app stores:

```text
Where it was found
Why it was selected
What variable name should replace it
What original values need replacement
```

---

### `AutoCorrelationSummary`

```python
@dataclass
class AutoCorrelationSummary:
    sampler_count: int = 0
    candidates_detected: int = 0
    replacement_nodes_changed: int = 0
    replacement_occurrences: int = 0
    smart_capture_processors_added: int = 0
    default_variables_added: int = 0
    cookie_manager_added: bool = False
    unsupported_plugin_elements_removed: int = 0
    warnings: list[str] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
```

This becomes the report file:

```text
auto_correlation_report.json
```

It tells you:

```text
How many samplers were found
How many dynamic values were detected
How many replacements were done
Whether Cookie Manager was added
Whether unsupported plugin classes were removed
What warnings were generated
```

---

## 5. XML/JMX repair logic

The uploaded JMX may not be valid XML. Your earlier error was like:

```text
reference to invalid character number
```

The repair starts here:

```python
def repair_jmx_bytes(data: bytes) -> tuple[str, XmlRepairReport]:
```

It does several things:

```text
1. Decodes bytes safely.
2. Removes junk before XML root.
3. Removes invalid XML numeric references.
4. Removes raw invalid XML characters.
5. Escapes unescaped ampersands.
```

Example problem:

```xml
abc & xyz
```

XML requires:

```xml
abc &amp; xyz
```

So this line handles unsafe ampersands:

```python
amp_pattern = re.compile(
    r"&(?!#\d+;|#x[0-9A-Fa-f]+;|[A-Za-z_][A-Za-z0-9_.:-]*;)"
)
```

Then:

```python
text, amp_count = amp_pattern.subn("&amp;", text)
```

After repair, parsing happens here:

```python
def parse_jmx_bytes(jmx_bytes: bytes) -> tuple[ET.ElementTree, XmlRepairReport]:
```

This checks that the root is actually:

```xml
<jmeterTestPlan>
```

If not, it raises a clean error.

---

## 6. JMeter hashTree navigation

JMeter JMX files use this structure:

```xml
<TestPlan />
<hashTree>
    <ThreadGroup />
    <hashTree>
        <HTTPSamplerProxy />
        <hashTree />
    </hashTree>
</hashTree>
```

So every JMeter element normally has a matching `hashTree`.

This function walks those pairs:

```python
def iter_jmeter_pairs(root: ET.Element):
```

It returns:

```text
parent_hash_tree
element
child_hash_tree
```

This is important because when adding or removing JMeter elements, the code must also add or remove the matching `hashTree`.

If we only remove the element and not its `hashTree`, the JMX can become corrupted.

---

## 7. Unsupported plugin cleanup

Your previous error was:

```text
CannotResolveClassException:
io.github.vasanthshanmugam.jmeter.plugins.correlation.CorrelationPostProcessor
```

The code removes that class here:

```python
UNSUPPORTED_PLUGIN_CLASS_NAMES = {
    "io.github.vasanthshanmugam.jmeter.plugins.correlation.CorrelationPostProcessor",
}
```

And the cleanup function is:

```python
def remove_unsupported_plugin_elements(root: ET.Element) -> tuple[int, list[str]]:
```

It removes both:

```text
plugin element
its matching hashTree
```

This makes the generated JMX open in normal JMeter without requiring that third-party plugin.

---

## 8. HTTP sampler discovery

This function finds all HTTP requests:

```python
def get_samplers(root: ET.Element) -> list[SamplerInfo]:
```

It looks for:

```xml
<HTTPSamplerProxy>
```

For every sampler, it collects:

```text
index
name
method
domain
path
sampler XML element
child hashTree
```

Example output:

```text
Sampler 1: GET /login
Sampler 2: POST /login
Sampler 3: GET /dashboard
Sampler 4: POST /api/order
```

The app shows this in the discovery report.

---

## 9. Safe candidate detection

This is where the app decides what should be correlated.

Main function:

```python
def detect_candidates(root: ET.Element) -> dict[str, Candidate]:
```

It checks:

```text
HTTP arguments
query parameters
headers
raw request bodies
```

It looks for known dynamic keys such as:

```text
csrf
xsrf
access_token
refresh_token
id_token
samlresponse
relaystate
__viewstate
jsessionid
sessionid
nonce
state
orderid
cartid
paymentid
transactionid
correlationid
traceid
etag
```

The key classification happens here:

```python
def classify_key(key: str) -> tuple[str | None, str]:
```

Example:

```text
csrf_token       -> category csrf
access_token     -> category access_token
JSESSIONID       -> category session
orderId          -> category business_id
```

---

## 10. Why the new version is safer

The earlier generated script failed because it correlated unsafe values like:

```text
0
1
4.7.0
AuthUser
browser version numbers
```

That caused bad replacements inside unrelated strings, for example:

```text
Chrome/148.${AUTHUSER}.${AUTHUSER}
```

The safe version prevents that in this function:

```python
def is_safe_dynamic_value(key: str, value: str, category: str | None):
```

It excludes:

```text
empty values
0
1
true
false
null
short values
numeric-only values
version-like values
already parameterized values
email
username
password
OTP
captcha
browser headers
API keys
static request headers
```

Important checks include:

```python
if decoded.isdigit():
    return False, 0.0, "numeric-only value excluded"
```

```python
if looks_like_version(decoded):
    return False, 0.0, "version-like value excluded"
```

```python
if is_credential_key(key) or is_static_key(key):
    return False, 0.0, "excluded key"
```

So now it avoids corrupting normal request data.

---

## 11. Variable name generation

This function creates JMeter variable names:

```python
def var_name_for_key(key: str, category: str) -> str:
```

Example mappings:

```text
csrf              -> CSRF_TOKEN
_csrf             -> CSRF_TOKEN
X-CSRF-Token      -> X_CSRF_TOKEN
access_token      -> ACCESS_TOKEN
JSESSIONID        -> JSESSIONID
orderId           -> ORDERID
transaction_id    -> TRANSACTION_ID
```

The final JMeter request will use variables like:

```text
${CSRF_TOKEN}
${ACCESS_TOKEN}
${JSESSIONID}
${ORDERID}
```

---

## 12. Replacement logic

The app replaces values only in safe locations.

### Request arguments

```python
def replace_argument_values(root, candidates):
```

Example before:

```text
csrf_token=abc123xyz
```

After:

```text
csrf_token=${CSRF_TOKEN}
```

---

### Headers

```python
def replace_header_values(root, candidates):
```

Example before:

```text
Authorization: Bearer eyJ...
```

After:

```text
Authorization: Bearer ${ACCESS_TOKEN}
```

It intentionally skips headers like:

```text
User-Agent
Accept
Accept-Language
Accept-Encoding
```

---

### Query string

```python
def replace_path_query_values(root, candidates):
```

Example before:

```text
/api/order?transaction_id=abc123xyz
```

After:

```text
/api/order?transaction_id=${TRANSACTION_ID}
```

---

### Raw request body

```python
def replace_raw_body_values(root, candidates):
```

Example before:

```json
{
  "csrf_token": "abc123xyz",
  "orderId": "ORD-938374"
}
```

After:

```json
{
  "csrf_token": "${CSRF_TOKEN}",
  "orderId": "${ORDERID}"
}
```

The important part is that it does **key-aware replacement**, not global blind replacement.

So it will not replace every matching text everywhere in the JMX.

---

## 13. User Defined Variables

This function adds fallback variables:

```python
def add_or_update_udv(root, candidates):
```

It creates values under:

```text
Test Plan → User Defined Variables
```

Example:

```text
CSRF_TOKEN = old recorded fallback value
ACCESS_TOKEN = old recorded fallback value
```

Why?

Because when JMeter starts, variables must exist. During replay, the Smart Capture JSR223 PostProcessor updates them with fresh values.

So the fallback value is only a starting value.

---

## 14. HTTP Cookie Manager

This function checks whether the script already has a Cookie Manager:

```python
def has_cookie_manager(root):
```

If not, it adds one:

```python
def ensure_cookie_manager(root):
```

Cookie handling should usually be done by JMeter’s built-in HTTP Cookie Manager instead of manually correlating cookie headers. JMeter’s component reference lists HTTP Cookie Manager as a standard configuration element and JSR223 PostProcessor as a standard post-processor, so the generated JMX avoids requiring the missing third-party correlation plugin. ([jmeter.apache.org][1])

---

## 15. Smart Capture JSR223 PostProcessor

This is the runtime extraction logic.

Main function:

```python
def make_smart_capture_script(candidates):
```

It generates a Groovy script.

Then:

```python
def ensure_smart_capture(root, candidates):
```

adds this generated Groovy script as a JMeter:

```text
JSR223 PostProcessor
```

The generated processor name is:

```text
Auto Correlate - Smart Capture
```

The JSR223 code runs after samplers and reads:

```groovy
prev.getResponseDataAsString()
prev.getResponseHeaders()
```

Then it searches for dynamic values in:

```text
HTML input fields
HTML meta tags
JSON fields
response headers
query strings
Set-Cookie headers
Bearer tokens
ETags
CSRF/XSRF headers
session IDs
```

When it finds a fresh value, it updates JMeter variables:

```groovy
vars.put("CSRF_TOKEN", found)
```

JMeter’s JSR223 PostProcessor receives the previous sampler result and can extract values for use in future requests, which is exactly why the generated script uses it for runtime correlation. ([jmeter.apache.org][2])

---

## 16. Main correlation function

The whole backend flow is here:

```python
def auto_correlate_jmx_bytes(jmx_bytes: bytes):
```

It performs the complete pipeline:

```text
1. Repair and parse uploaded JMX.
2. Remove unsupported plugin elements.
3. Count HTTP samplers.
4. Detect safe dynamic candidates.
5. Add default User Defined Variables.
6. Add HTTP Cookie Manager if missing.
7. Replace request argument values.
8. Replace query string values.
9. Replace header values.
10. Replace raw body values.
11. Add Smart Capture JSR223 PostProcessor.
12. Validate generated JMX.
13. Return:
    - patched JMX
    - summary object
    - report JSON
```

Simplified version:

```python
def auto_correlate_jmx_bytes(jmx_bytes):
    tree, repair_report = parse_jmx_bytes(jmx_bytes)
    root = tree.getroot()

    remove_unsupported_plugin_elements(root)

    candidates = detect_candidates(root)

    add_or_update_udv(root, candidates)
    ensure_cookie_manager(root)

    replace_argument_values(root, candidates)
    replace_path_query_values(root, candidates)
    replace_header_values(root, candidates)
    replace_raw_body_values(root, candidates)

    ensure_smart_capture(root, candidates)

    patched = tree_to_bytes(tree)
    validate_generated_jmx(patched)

    return patched, summary, report_json
```

---

## 17. Output ZIP generation

This function creates the downloadable package:

```python
def make_output_zip(patched_jmx: bytes, report_json: bytes) -> bytes:
```

It writes:

```text
auto_correlated.jmx
auto_correlation_report.json
```

into one ZIP file.

---

## 18. Optional JMeter run

This function runs JMeter from Python:

```python
def run_jmeter_cli(
    jmx_bytes: bytes,
    jmeter_bin: str = "jmeter",
    make_report: bool = False,
    timeout_seconds: int = 300
)
```

It writes the generated JMX into a temporary folder and runs:

```bash
jmeter -n -t auto_correlated.jmx -l results.jtl
```

If HTML report is selected, it adds:

```bash
-e -o html-report
```

Then it returns:

```text
exit code
stdout
stderr
results.jtl bytes
html-report.zip bytes
```

This is useful for validating the generated script directly from the Streamlit page.

---

# 19. `rag_engine.py` explanation

This file handles the RAG application.

RAG means:

```text
Retrieve relevant project text
        ↓
Send that context to OpenAI
        ↓
Answer based on uploaded/generated files
```

The RAG engine indexes:

```text
uploaded recorded JMX
generated auto_correlated.jmx
auto_correlation_report.json
optional extra files
project help notes
```

---

## 19.1 Chunk structure

```python
@dataclass
class RagChunk:
    source: str
    chunk_id: int
    text: str
```

Each chunk is a small piece of a document.

Example:

```text
source: auto_correlation_report.json
chunk_id: 3
text: "... candidates_detected ..."
```

The RAG engine does not send the whole JMX blindly to OpenAI. It splits the content into chunks first.

---

## 19.2 Text decoding

```python
def safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")
```

This prevents the app from crashing if the uploaded file has strange characters.

---

## 19.3 Chunking

```python
def chunk_text(source, text, chunk_chars=2800, overlap=350):
```

It splits a large file into chunks of about 2800 characters.

The overlap keeps context between chunks.

Example:

```text
Chunk 1: characters 0-2800
Chunk 2: characters 2450-5250
Chunk 3: characters 4900-7700
```

This improves retrieval because a useful section is less likely to be split badly.

---

## 19.4 Building the corpus

```python
def build_corpus(
    uploaded_name,
    uploaded_jmx,
    correlated_jmx,
    report_json,
    extra_files=None
):
```

This creates the full searchable knowledge base.

It adds:

```text
uploaded JMX
auto_correlated.jmx
auto_correlation_report.json
project_help.md
optional extra uploaded files
```

Then it chunks them.

---

## 19.5 OpenAI client

```python
def get_openai_client(api_key: str | None = None):
```

It checks:

```text
1. API key entered in Streamlit sidebar
2. OPENAI_API_KEY environment variable
```

Then creates:

```python
OpenAI(api_key=key)
```

The official OpenAI Python SDK supports creating a client with an API key and shows the common `OPENAI_API_KEY` environment-variable pattern; it also shows `client.responses.create(...)` as the primary text-generation interface. ([GitHub][3])

---

## 19.6 Embeddings

```python
def embed_texts(api_key, texts, model="text-embedding-3-small"):
```

This sends text chunks to OpenAI’s embeddings API.

The result is a list of vectors:

```text
chunk text → embedding vector
```

OpenAI’s embeddings API returns vector representations of input text and supports embedding models such as `text-embedding-3-small` and `text-embedding-3-large`. ([OpenAI Platform][4])

---

## 19.7 Building the vector index

```python
def build_openai_index(api_key, chunks, embedding_model):
```

This stores:

```text
chunks
embeddings
embedding model
fingerprint
```

The fingerprint is a hash of:

```text
model name
chunk source
chunk text
```

This helps avoid rebuilding the index unnecessarily when the same files are uploaded.

---

## 19.8 Retrieval

```python
def retrieve_openai(api_key, index, query, top_k=6):
```

This works like this:

```text
1. Convert user question into an embedding.
2. Compare question embedding with every chunk embedding.
3. Sort by cosine similarity.
4. Return top matching chunks.
```

Example question:

```text
Why was my JMX not opening in JMeter?
```

Likely retrieved chunks:

```text
auto_correlation_report.json
project_help.md
generated JMX plugin cleanup section
```

---

## 19.9 Answer generation

```python
def answer_with_openai(api_key, question, retrieved, model="gpt-5.5"):
```

This sends:

```text
retrieved context
+
user question
```

to OpenAI.

The prompt tells the model:

```text
Answer only from provided project context.
Cite sources as [S1], [S2], etc.
If answer is missing, say what is missing.
Do not reveal or ask for API keys.
```

So the RAG answer is grounded in the uploaded/generated project files.

---

## 20. RAG flow inside Streamlit

The Streamlit RAG tab should work like this:

```text
User uploads JMX
   ↓
App generates auto_correlated.jmx
   ↓
App generates auto_correlation_report.json
   ↓
RAG tab builds corpus
   ↓
OpenAI embeddings are generated
   ↓
User asks question
   ↓
Relevant chunks are retrieved
   ↓
OpenAI answers from retrieved context
```

Example UI logic:

```python
chunks = build_corpus(
    uploaded_name=uploaded.name,
    uploaded_jmx=jmx_bytes,
    correlated_jmx=patched_jmx,
    report_json=report_json,
    extra_files=extra_files,
)

index = build_openai_index(
    api_key=openai_api_key,
    chunks=chunks,
    embedding_model=embedding_model,
)

retrieved = retrieve_openai(
    api_key=openai_api_key,
    index=index,
    query=user_question,
    top_k=top_k,
)

answer = answer_with_openai(
    api_key=openai_api_key,
    question=user_question,
    retrieved=retrieved,
    model=response_model,
)
```

---

## 21. Where the OpenAI API key is used

The API key is only needed in `rag_engine.py`.

It is used in:

```python
get_openai_client()
```

Then reused by:

```python
embed_texts()
answer_with_openai()
```

It should not be written to:

```text
auto_correlated.jmx
auto_correlation_report.json
download ZIP
JMeter logs
```

Recommended usage:

```powershell
$env:OPENAI_API_KEY="sk-..."
streamlit run app.py
```

or inside Streamlit sidebar:

```text
OpenAI API key input
```

The key should be entered as a password field:

```python
openai_api_key = st.text_input(
    "OpenAI API key",
    type="password"
)
```

---

## 22. `requirements.txt`

For the OpenAI RAG version, it should contain at least:

```text
streamlit>=1.36
openai>=1.99.0
```

If your `requirements.txt` only has:

```text
streamlit
```

then the RAG tab will fail because this import will not work:

```python
from openai import OpenAI
```

Install dependencies with:

```bash
pip install -r requirements.txt
```

---

## 23. End-to-end execution flow

Full flow:

```text
User opens Streamlit app
        ↓
User uploads recorded JMX
        ↓
app.py reads uploaded bytes
        ↓
jmx_auto_correlator.py repairs XML
        ↓
Unsupported plugin elements are removed
        ↓
HTTP samplers are detected
        ↓
Safe dynamic candidates are detected
        ↓
User Defined Variables are added
        ↓
HTTP Cookie Manager is added
        ↓
Exact request/header/body replacements are done
        ↓
Smart Capture JSR223 PostProcessor is inserted
        ↓
Generated JMX is validated
        ↓
User downloads auto_correlated.jmx
        ↓
RAG tab indexes uploaded/generated files
        ↓
User asks question
        ↓
rag_engine.py retrieves relevant chunks
        ↓
OpenAI generates grounded answer
```

---

## 24. What to modify for your project

For safer correlation tuning, modify these sections in `jmx_auto_correlator.py`:

```python
KNOWN_DYNAMIC_KEY_PATTERNS
```

Add your application-specific dynamic keys here.

Example:

```python
"business_id": [
    "orderid",
    "cartid",
    "paymentid",
    "bookingid",
    "invoiceid",
    "workflowid"
]
```

To exclude more fields from correlation, modify:

```python
STATIC_KEY_NAMES
CREDENTIAL_KEY_PATTERNS
STATIC_VALUE_LITERALS
```

For RAG behavior, modify this in `rag_engine.py`:

```python
instructions = (
    "You are a JMeter performance testing assistant..."
)
```

That controls how the assistant answers.

---

## 25. Simple summary

The project works like this:

```text
app.py
    Web page and user interaction.

jmx_auto_correlator.py
    Repairs JMX, removes bad plugins, detects dynamic values, adds variables,
    injects Smart Capture, and generates auto_correlated.jmx.

rag_engine.py
    Builds a RAG knowledge base from uploaded/generated files and uses OpenAI
    embeddings + response generation to answer questions.

requirements.txt
    Installs Streamlit and OpenAI SDK.

README.md
    Explains how to run the app.
```

The key backend function for correlation is:

```python
auto_correlate_jmx_bytes()
```

The key backend functions for RAG are:

```python
build_corpus()
build_openai_index()
retrieve_openai()
answer_with_openai()
```

[1]: https://jmeter.apache.org/usermanual/component_reference.html?utm_source=chatgpt.com "Apache JMeter - User's Manual: Component Reference"
[2]: https://jmeter.apache.org/api/org/apache/jmeter/extractor/JSR223PostProcessor.html?utm_source=chatgpt.com "JSR223PostProcessor (Apache JMeter dist API)"
[3]: https://github.com/openai/openai-python/blob/main/README.md "openai-python/README.md at main · openai/openai-python · GitHub"
[4]: https://platform.openai.com/docs/api-reference/embeddings?.zst=&utm_source=chatgpt.com "Embeddings | OpenAI API Reference"
