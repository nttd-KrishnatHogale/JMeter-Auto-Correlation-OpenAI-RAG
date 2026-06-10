from __future__ import annotations

import base64
import io
import json
import math
import re
import shutil
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, unquote


class JmxAutoCorrelationError(Exception):
    pass


@dataclass
class XmlRepairReport:
    decode_encoding: str = "utf-8-sig"
    invalid_decode_bytes_replaced: bool = False
    leading_bytes_removed: int = 0
    invalid_numeric_character_references_removed: int = 0
    raw_invalid_xml_characters_removed: int = 0
    unescaped_ampersands_escaped: int = 0

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class Candidate:
    variable: str
    key: str
    category: str
    confidence: float
    reason: str
    first_sampler_index: int
    first_sampler_name: str
    original_values: set[str] = field(default_factory=set)
    raw_values: set[str] = field(default_factory=set)
    locations: list[str] = field(default_factory=list)
    capture_keys: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "variable": self.variable,
            "key": self.key,
            "category": self.category,
            "confidence": round(self.confidence, 3),
            "reason": self.reason,
            "first_sampler_index": self.first_sampler_index,
            "first_sampler_name": self.first_sampler_name,
            "original_values": sorted(self.original_values),
            "locations": self.locations,
            "capture_keys": sorted(self.capture_keys),
        }


@dataclass
class AutoCorrelationSummary:
    sampler_count: int = 0
    candidates_detected: int = 0
    original_values_detected: int = 0
    replacement_nodes_changed: int = 0
    replacement_occurrences: int = 0
    smart_capture_processors_added: int = 0
    smart_capture_processors_skipped: int = 0
    default_variables_added: int = 0
    default_variables_skipped: int = 0
    cookie_manager_added: bool = False
    unsupported_plugin_elements_removed: int = 0
    unsupported_plugin_classes: list[str] = field(default_factory=list)
    xml_repair_report: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    automation_mode: str = "safe_jmx_only_smart_correlation"
    important_note: str = (
        "A JMX normally stores recorded requests, not server responses. This automation therefore uses safe heuristics: "
        "it correlates only known dynamic fields or high-entropy token-like values, replaces only exact parameter/header/body values, "
        "and injects a stock JSR223 Smart Capture post-processor to capture fresh values during replay."
    )

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class SamplerInfo:
    index: int
    name: str
    method: str
    domain: str
    path: str
    sampler: ET.Element
    child_tree: ET.Element


UNSUPPORTED_PLUGIN_CLASS_PREFIXES = (
    "io.github.vasanthshanmugam.jmeter.plugins.correlation.",
)
UNSUPPORTED_PLUGIN_CLASS_NAMES = {
    "io.github.vasanthshanmugam.jmeter.plugins.correlation.CorrelationPostProcessor",
}

CREDENTIAL_KEY_PATTERNS = [
    "password", "passwd", "pwd", "email", "e-mail", "username", "user_name", "login", "remember_me",
    "otp", "mfa", "captcha", "credential", "secret",
]

STATIC_KEY_NAMES = {
    "v", "ver", "version", "authuser", "ci", "rid", "aid", "type", "t", "zx", "ei", "hl", "gl",
    "source", "sourceid", "client", "fmt", "afmt", "seq", "event", "c", "cver", "cbr", "cbrver",
    "cos", "cosver", "host", "origin", "referer", "user-agent", "accept", "accept-language", "accept-encoding",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user", "upgrade-insecure-requests",
    "cache-control", "pragma", "content-type", "content-length", "connection", "key", "api_key", "apikey",
}

KNOWN_DYNAMIC_KEY_PATTERNS = {
    "csrf": [
        "csrf", "_csrf", "csrf_token", "csrftoken", "csrf-token", "x-csrf-token", "xsrf", "x-xsrf-token",
        "requestverificationtoken", "__requestverificationtoken", "authenticity_token",
    ],
    "access_token": ["access_token", "accesstoken", "auth_token", "authtoken", "bearer", "jwt"],
    "refresh_token": ["refresh_token", "refreshtoken"],
    "id_token": ["id_token", "idtoken"],
    "saml": ["samlrequest", "samlresponse", "relaystate"],
    "viewstate": ["__viewstate", "__eventvalidation", "__viewstategenerator"],
    "session": [
        "jsessionid", "phpsessid", "sessionid", "session_id", "sid", "gsessionid", "session_token", "session-token",
    ],
    "etag": ["etag", "if-none-match", "x-etag"],
    "nonce": ["nonce", "state", "oauth_state", "code_verifier", "code_challenge"],
    "business_id": [
        "orderid", "order_id", "cartid", "cart_id", "paymentid", "payment_id", "paymentnonce", "payment_nonce",
        "transactionid", "transaction_id", "requestid", "request_id", "correlationid", "correlation_id", "traceid", "trace_id",
    ],
}

STATIC_VALUE_LITERALS = {
    "", "0", "1", "true", "false", "null", "undefined", "none", "yes", "no", "get", "post", "put", "delete",
    "xmlhttp", "document", "empty", "cors", "navigate", "same-origin", "include", "omit",
}

GENERATED_TESTNAME = "Auto Correlate - Smart Capture"
GENERATED_COOKIE_MANAGER_NAME = "HTTP Cookie Manager - Auto Added"
GENERATED_MARKER = "Generated by JMeter Auto Correlation Streamlit app"


def is_valid_xml_char(codepoint: int) -> bool:
    return (
        codepoint == 0x9
        or codepoint == 0xA
        or codepoint == 0xD
        or 0x20 <= codepoint <= 0xD7FF
        or 0xE000 <= codepoint <= 0xFFFD
        or 0x10000 <= codepoint <= 0x10FFFF
    )


def repair_jmx_bytes(data: bytes) -> tuple[str, XmlRepairReport]:
    if not data:
        raise JmxAutoCorrelationError("Uploaded JMX file is empty.")

    report = XmlRepairReport()
    text = data.decode("utf-8-sig", errors="replace")
    report.invalid_decode_bytes_replaced = "\ufffd" in text

    xml_pos = text.find("<?xml")
    root_pos = text.find("<jmeterTestPlan")
    candidates = [pos for pos in (xml_pos, root_pos) if pos >= 0]
    if candidates:
        first = min(candidates)
        if first > 0:
            report.leading_bytes_removed = first
            text = text[first:]

    def repl_numeric(match: re.Match[str]) -> str:
        raw = match.group(1)
        try:
            if raw.lower().startswith("x"):
                cp = int(raw[1:], 16)
            else:
                cp = int(raw, 10)
        except ValueError:
            report.invalid_numeric_character_references_removed += 1
            return ""
        if is_valid_xml_char(cp):
            return match.group(0)
        report.invalid_numeric_character_references_removed += 1
        return ""

    text = re.sub(r"&#(x[0-9A-Fa-f]+|[0-9]+);", repl_numeric, text)

    cleaned_chars: list[str] = []
    for ch in text:
        if is_valid_xml_char(ord(ch)):
            cleaned_chars.append(ch)
        else:
            report.raw_invalid_xml_characters_removed += 1
    text = "".join(cleaned_chars)

    amp_pattern = re.compile(r"&(?!#\d+;|#x[0-9A-Fa-f]+;|[A-Za-z_][A-Za-z0-9_.:-]*;)")
    text, amp_count = amp_pattern.subn("&amp;", text)
    report.unescaped_ampersands_escaped = amp_count
    return text, report


def parse_jmx_bytes(jmx_bytes: bytes) -> tuple[ET.ElementTree, XmlRepairReport]:
    text, repair_report = repair_jmx_bytes(jmx_bytes)
    try:
        root = ET.fromstring(text.encode("utf-8"))
    except ET.ParseError as exc:
        raise JmxAutoCorrelationError(f"Invalid JMX/XML after automatic recovery: {exc}") from exc
    if root.tag != "jmeterTestPlan":
        raise JmxAutoCorrelationError("The uploaded file does not look like a JMeter .jmx file. Root should be jmeterTestPlan.")
    return ET.ElementTree(root), repair_report


def tree_to_bytes(tree: ET.ElementTree) -> bytes:
    try:
        ET.indent(tree, space="  ", level=0)
    except Exception:
        pass
    buffer = io.BytesIO()
    tree.write(buffer, encoding="UTF-8", xml_declaration=True)
    return buffer.getvalue()


def string_prop(name: str, value: str | None = "") -> ET.Element:
    node = ET.Element("stringProp", {"name": name})
    node.text = "" if value is None else str(value)
    return node


def bool_prop(name: str, value: bool) -> ET.Element:
    node = ET.Element("boolProp", {"name": name})
    node.text = "true" if bool(value) else "false"
    return node


def element_prop(name: str, element_type: str) -> ET.Element:
    return ET.Element("elementProp", {"name": name, "elementType": element_type})


def get_prop(element: ET.Element, prop_name: str, default: str = "") -> str:
    for child in element.iter():
        if child.attrib.get("name") == prop_name and child.text is not None:
            return child.text
    return default


def set_direct_string_prop(parent: ET.Element, prop_name: str, value: str) -> bool:
    for child in list(parent):
        if child.tag == "stringProp" and child.attrib.get("name") == prop_name:
            old = child.text or ""
            child.text = value
            return old != value
    parent.append(string_prop(prop_name, value))
    return True


def iter_jmeter_pairs(root: ET.Element) -> Iterable[tuple[ET.Element, ET.Element, ET.Element]]:
    for hash_tree in root.iter("hashTree"):
        children = list(hash_tree)
        idx = 0
        while idx < len(children) - 1:
            element = children[idx]
            child_tree = children[idx + 1]
            if child_tree.tag == "hashTree":
                yield hash_tree, element, child_tree
                idx += 2
            else:
                idx += 1


def child_pairs(hash_tree: ET.Element) -> Iterable[tuple[ET.Element, ET.Element]]:
    children = list(hash_tree)
    idx = 0
    while idx < len(children) - 1:
        element = children[idx]
        child_tree = children[idx + 1]
        if child_tree.tag == "hashTree":
            yield element, child_tree
            idx += 2
        else:
            idx += 1


def remove_hash_tree_pair(parent_hash_tree: ET.Element, element: ET.Element, child_tree: ET.Element) -> None:
    parent_hash_tree.remove(element)
    parent_hash_tree.remove(child_tree)


def remove_unsupported_plugin_elements(root: ET.Element) -> tuple[int, list[str]]:
    removed = 0
    classes: list[str] = []
    changed = True
    while changed:
        changed = False
        for parent_tree, element, child_tree in list(iter_jmeter_pairs(root)):
            tag = element.tag
            unsupported = tag in UNSUPPORTED_PLUGIN_CLASS_NAMES or any(tag.startswith(p) for p in UNSUPPORTED_PLUGIN_CLASS_PREFIXES)
            if unsupported:
                classes.append(tag)
                remove_hash_tree_pair(parent_tree, element, child_tree)
                removed += 1
                changed = True
                break
    return removed, sorted(set(classes))


def get_samplers(root: ET.Element) -> list[SamplerInfo]:
    samplers: list[SamplerInfo] = []
    for _parent, element, child_tree in iter_jmeter_pairs(root):
        if element.tag == "HTTPSamplerProxy":
            samplers.append(
                SamplerInfo(
                    index=len(samplers) + 1,
                    name=element.attrib.get("testname", ""),
                    method=get_prop(element, "HTTPSampler.method", ""),
                    domain=get_prop(element, "HTTPSampler.domain", ""),
                    path=get_prop(element, "HTTPSampler.path", ""),
                    sampler=element,
                    child_tree=child_tree,
                )
            )
    return samplers


def sampler_summary(root: ET.Element) -> list[dict[str, Any]]:
    return [
        {
            "#": s.index,
            "name": s.name,
            "method": s.method,
            "domain": s.domain,
            "path": s.path[:220],
        }
        for s in get_samplers(root)
    ]


def normalize_key(key: str) -> str:
    key = unquote(str(key or "")).strip()
    key = re.sub(r"^HTTPArgument\.", "", key)
    return key


def key_compact(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", normalize_key(key).lower())


def is_credential_key(key: str) -> bool:
    k = normalize_key(key).lower()
    if not k:
        return False
    for pattern in CREDENTIAL_KEY_PATTERNS:
        if pattern in k:
            return True
    return False


def is_static_key(key: str) -> bool:
    k = normalize_key(key).lower()
    kc = key_compact(key)
    return k in STATIC_KEY_NAMES or kc in {key_compact(x) for x in STATIC_KEY_NAMES}


def classify_key(key: str) -> tuple[str | None, str]:
    k = normalize_key(key).lower()
    kc = key_compact(key)
    if not k:
        return None, "empty key"
    if is_credential_key(k):
        return None, "credential/user input key excluded"
    if is_static_key(k):
        return None, "static/browser/API key excluded"
    for category, patterns in KNOWN_DYNAMIC_KEY_PATTERNS.items():
        for pattern in patterns:
            pc = key_compact(pattern)
            if kc == pc or pc in kc:
                return category, f"known dynamic key '{key}'"
    return None, "key is not a known dynamic field"


def value_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_like_version(value: str) -> bool:
    return bool(re.fullmatch(r"\d+(?:\.\d+){1,4}", value or ""))


def looks_like_uuid(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value or ""))


def looks_like_jwt(value: str) -> bool:
    return bool(re.fullmatch(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", value or ""))


def is_safe_dynamic_value(key: str, value: str, category: str | None) -> tuple[bool, float, str]:
    raw = "" if value is None else str(value).strip()
    if not raw:
        return False, 0.0, "empty value"
    decoded = unquote(raw).strip()
    if decoded.lower() in STATIC_VALUE_LITERALS or raw.lower() in STATIC_VALUE_LITERALS:
        return False, 0.0, "static literal excluded"
    if raw.startswith("${") and raw.endswith("}"):
        return False, 0.0, "already parameterized"
    if looks_like_version(decoded):
        return False, 0.0, "version-like value excluded"
    if decoded.isdigit():
        return False, 0.0, "numeric-only value excluded"
    if len(decoded) < 8 and category not in {"csrf", "viewstate"}:
        return False, 0.0, "value too short"
    if is_credential_key(key) or is_static_key(key):
        return False, 0.0, "excluded key"

    entropy = value_entropy(decoded)
    unique_ratio = len(set(decoded)) / max(1, len(decoded))
    confidence = 0.0
    reasons: list[str] = []

    if category:
        confidence += 0.55
        reasons.append(f"category={category}")
    if len(decoded) >= 16:
        confidence += 0.15
        reasons.append("length>=16")
    if len(decoded) >= 32:
        confidence += 0.10
        reasons.append("length>=32")
    if entropy >= 3.2:
        confidence += 0.12
        reasons.append("high entropy")
    if unique_ratio >= 0.35:
        confidence += 0.05
        reasons.append("diverse characters")
    if looks_like_uuid(decoded):
        confidence += 0.20
        reasons.append("UUID-like")
    if looks_like_jwt(decoded):
        confidence += 0.25
        reasons.append("JWT-like")

    # Do not correlate unknown random-looking long blobs unless they are in request parameters with a meaningful key.
    if not category and confidence < 0.32:
        return False, confidence, "not enough dynamic evidence"
    if category and confidence < 0.50:
        return False, confidence, "dynamic key found but value not token-like"
    return True, min(confidence, 0.98), "; ".join(reasons)


def var_name_for_key(key: str, category: str) -> str:
    k = normalize_key(key)
    k = re.sub(r"\[[^\]]+\]", "", k)
    base = re.sub(r"[^A-Za-z0-9]+", "_", k).strip("_").upper()
    if not base:
        base = category.upper()
    if base[0].isdigit():
        base = "VAR_" + base
    aliases = {
        "_CSRF": "CSRF_TOKEN",
        "CSRF": "CSRF_TOKEN",
        "CSRFTOKEN": "CSRF_TOKEN",
        "CSRF_TOKEN": "CSRF_TOKEN",
        "X_CSRF_TOKEN": "X_CSRF_TOKEN",
        "AUTHENTICITY_TOKEN": "AUTHENTICITY_TOKEN",
        "REQUESTVERIFICATIONTOKEN": "REQUEST_VERIFICATION_TOKEN",
        "__REQUESTVERIFICATIONTOKEN": "REQUEST_VERIFICATION_TOKEN",
        "JSESSIONID": "JSESSIONID",
    }
    return aliases.get(base, base)


def raw_query_pairs(path: str) -> list[tuple[str, str]]:
    if "?" not in path:
        return []
    query = path.split("?", 1)[1]
    pairs: list[tuple[str, str]] = []
    for part in query.split("&"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        pairs.append((k, v))
    return pairs


def iter_http_arguments(sampler: ET.Element) -> Iterable[ET.Element]:
    for arg in sampler.iter("elementProp"):
        if arg.attrib.get("elementType") == "HTTPArgument":
            yield arg


def argument_name_value(arg: ET.Element) -> tuple[str, str]:
    return get_prop(arg, "Argument.name", ""), get_prop(arg, "Argument.value", "")


def iter_headers(sampler_child_tree: ET.Element) -> Iterable[ET.Element]:
    for child, _grand in child_pairs(sampler_child_tree):
        if child.tag != "HeaderManager":
            continue
        for header in child.iter("elementProp"):
            if header.attrib.get("elementType") == "Header":
                yield header


def header_name_value(header: ET.Element) -> tuple[str, str]:
    return get_prop(header, "Header.name", ""), get_prop(header, "Header.value", "")


def add_candidate(
    candidates: dict[str, Candidate],
    key: str,
    raw_value: str,
    category: str,
    confidence: float,
    reason: str,
    sampler: SamplerInfo,
    location: str,
) -> None:
    variable = var_name_for_key(key, category)
    decoded = unquote(raw_value).strip()
    lookup_key = variable
    if lookup_key not in candidates:
        candidates[lookup_key] = Candidate(
            variable=variable,
            key=normalize_key(key),
            category=category,
            confidence=confidence,
            reason=reason,
            first_sampler_index=sampler.index,
            first_sampler_name=sampler.name,
        )
    candidate = candidates[lookup_key]
    candidate.confidence = max(candidate.confidence, confidence)
    if reason not in candidate.reason:
        candidate.reason = (candidate.reason + "; " + reason).strip("; ")
    candidate.original_values.add(decoded or raw_value)
    candidate.raw_values.add(raw_value)
    candidate.capture_keys.add(normalize_key(key))
    candidate.locations.append(f"Sampler {sampler.index} ({sampler.name}): {location}")


def detect_candidates(root: ET.Element) -> dict[str, Candidate]:
    candidates: dict[str, Candidate] = {}
    samplers = get_samplers(root)

    for sampler in samplers:
        # HTTP form/query arguments
        for arg in iter_http_arguments(sampler.sampler):
            name, value = argument_name_value(arg)
            if not name:
                # Raw body argument. Try to discover known field names inside it later.
                continue
            category, key_reason = classify_key(name)
            if category is None:
                continue
            ok, confidence, value_reason = is_safe_dynamic_value(name, value, category)
            if ok:
                add_candidate(candidates, name, value, category, confidence, f"{key_reason}; {value_reason}", sampler, f"Request argument {name}")

        # Query parameters inside HTTPSampler.path
        for raw_key, raw_value in raw_query_pairs(sampler.path):
            key = unquote(raw_key)
            value = raw_value
            category, key_reason = classify_key(key)
            if category is None:
                continue
            ok, confidence, value_reason = is_safe_dynamic_value(key, unquote(value), category)
            if ok:
                add_candidate(candidates, key, value, category, confidence, f"{key_reason}; {value_reason}", sampler, f"Query parameter {key}")

        # Headers
        for header in iter_headers(sampler.child_tree):
            name, value = header_name_value(header)
            header_l = name.lower()
            if header_l == "authorization" and value.lower().startswith("bearer "):
                token = value.split(None, 1)[1].strip()
                ok, confidence, value_reason = is_safe_dynamic_value("access_token", token, "access_token")
                if ok:
                    add_candidate(candidates, "access_token", token, "access_token", confidence, f"Authorization Bearer header; {value_reason}", sampler, "Authorization bearer token")
                continue
            category, key_reason = classify_key(name)
            if category is None:
                continue
            ok, confidence, value_reason = is_safe_dynamic_value(name, value, category)
            if ok:
                add_candidate(candidates, name, value, category, confidence, f"{key_reason}; {value_reason}", sampler, f"Header {name}")

        # Raw body argument: key-aware only, not broad replacement.
        for arg in iter_http_arguments(sampler.sampler):
            name, body = argument_name_value(arg)
            if name or not body or len(body) > 200000:
                continue
            # JSON-like or form-like known dynamic fields.
            for category, keys in KNOWN_DYNAMIC_KEY_PATTERNS.items():
                for key in keys:
                    # JSON: "key":"value"
                    for match in re.finditer(r'(?is)(["\']' + re.escape(key) + r'["\']\s*:\s*["\'])([^"\']{8,4096})(["\'])', body):
                        value = match.group(2)
                        ok, confidence, value_reason = is_safe_dynamic_value(key, value, category)
                        if ok:
                            add_candidate(candidates, key, value, category, confidence, f"raw JSON field; {value_reason}", sampler, f"Raw JSON field {key}")
                    # Form: key=value
                    for match in re.finditer(r'(?is)(^|[&?])(' + re.escape(key) + r')=([^&\s]{8,4096})', body):
                        value = match.group(3)
                        ok, confidence, value_reason = is_safe_dynamic_value(key, unquote(value), category)
                        if ok:
                            add_candidate(candidates, key, value, category, confidence, f"raw form field; {value_reason}", sampler, f"Raw form field {key}")

    # Avoid unsafe generic authuser/session/email/password mappings.
    for name in list(candidates.keys()):
        cand = candidates[name]
        if any(is_credential_key(k) for k in cand.capture_keys):
            del candidates[name]
            continue
        if all(len(v) < 8 or v.lower() in STATIC_VALUE_LITERALS or v.isdigit() for v in cand.original_values):
            del candidates[name]
            continue
    return candidates


def replace_argument_values(root: ET.Element, candidates: dict[str, Candidate]) -> tuple[int, int]:
    nodes = 0
    occurrences = 0
    by_key: dict[str, Candidate] = {}
    for cand in candidates.values():
        for key in cand.capture_keys:
            by_key[key_compact(key)] = cand

    for sampler in get_samplers(root):
        for arg in iter_http_arguments(sampler.sampler):
            name, value = argument_name_value(arg)
            if not name:
                continue
            cand = by_key.get(key_compact(name))
            if not cand:
                continue
            if is_credential_key(name) or is_static_key(name):
                continue
            decoded_value = unquote(value).strip()
            if value in cand.raw_values or decoded_value in cand.original_values:
                if set_direct_string_prop(arg, "Argument.value", "${" + cand.variable + "}"):
                    nodes += 1
                occurrences += 1
    return nodes, occurrences


def replace_header_values(root: ET.Element, candidates: dict[str, Candidate]) -> tuple[int, int]:
    nodes = 0
    occurrences = 0
    by_key: dict[str, Candidate] = {}
    for cand in candidates.values():
        for key in cand.capture_keys:
            by_key[key_compact(key)] = cand

    for sampler in get_samplers(root):
        for header in iter_headers(sampler.child_tree):
            name, value = header_name_value(header)
            if name.lower() in {"user-agent", "accept", "accept-language", "accept-encoding"}:
                continue
            if name.lower() == "authorization" and value.lower().startswith("bearer "):
                cand = candidates.get("ACCESS_TOKEN") or candidates.get("AUTH_TOKEN")
                if cand:
                    token = value.split(None, 1)[1].strip()
                    if token in cand.raw_values or token in cand.original_values:
                        if set_direct_string_prop(header, "Header.value", "Bearer ${" + cand.variable + "}"):
                            nodes += 1
                        occurrences += 1
                continue
            cand = by_key.get(key_compact(name))
            if not cand:
                continue
            if value in cand.raw_values or unquote(value).strip() in cand.original_values:
                if set_direct_string_prop(header, "Header.value", "${" + cand.variable + "}"):
                    nodes += 1
                occurrences += 1
    return nodes, occurrences


def replace_path_query_values(root: ET.Element, candidates: dict[str, Candidate]) -> tuple[int, int]:
    nodes = 0
    occurrences = 0
    by_key: dict[str, Candidate] = {}
    for cand in candidates.values():
        for key in cand.capture_keys:
            by_key[key_compact(key)] = cand

    for sampler in get_samplers(root):
        path = sampler.path
        if "?" not in path:
            continue
        prefix, query = path.split("?", 1)
        changed = False
        new_parts: list[str] = []
        for part in query.split("&"):
            if not part:
                new_parts.append(part)
                continue
            if "=" not in part:
                new_parts.append(part)
                continue
            raw_key, raw_value = part.split("=", 1)
            key = unquote(raw_key)
            cand = by_key.get(key_compact(key))
            if cand and not is_credential_key(key) and not is_static_key(key):
                decoded_value = unquote(raw_value).strip()
                if raw_value in cand.raw_values or decoded_value in cand.original_values:
                    # Use a plain JMeter variable. JMeter does not URL-encode variables in the path field.
                    new_parts.append(raw_key + "=${" + cand.variable + "}")
                    changed = True
                    occurrences += 1
                    continue
            new_parts.append(part)
        if changed:
            new_path = prefix + "?" + "&".join(new_parts)
            if set_direct_string_prop(sampler.sampler, "HTTPSampler.path", new_path):
                nodes += 1
    return nodes, occurrences


def replace_raw_body_values(root: ET.Element, candidates: dict[str, Candidate]) -> tuple[int, int]:
    nodes = 0
    occurrences = 0
    by_key: dict[str, Candidate] = {}
    for cand in candidates.values():
        for key in cand.capture_keys:
            by_key[key_compact(key)] = cand

    for sampler in get_samplers(root):
        for arg in iter_http_arguments(sampler.sampler):
            name, body = argument_name_value(arg)
            if name or not body or len(body) > 200000:
                continue
            new_body = body
            body_occ = 0
            for key_comp, cand in by_key.items():
                keys = sorted(cand.capture_keys, key=len, reverse=True)
                for key in keys:
                    if is_credential_key(key) or is_static_key(key):
                        continue
                    var = "${" + cand.variable + "}"
                    # JSON field replacement for exact value.
                    for value in sorted(cand.raw_values | cand.original_values, key=len, reverse=True):
                        if not value or len(value) < 8:
                            continue
                        escaped_key = re.escape(key)
                        escaped_value = re.escape(value)
                        new_body, count1 = re.subn(
                            r'(["\']' + escaped_key + r'["\']\s*:\s*["\'])' + escaped_value + r'(["\'])',
                            r'\1' + var + r'\2',
                            new_body,
                        )
                        encoded_value = re.escape(quote(value, safe=""))
                        new_body, count2 = re.subn(
                            r'((?:^|[&?])' + escaped_key + r'=)' + encoded_value + r'(?=(&|$))',
                            r'\1' + var,
                            new_body,
                        )
                        body_occ += count1 + count2
            if new_body != body:
                if set_direct_string_prop(arg, "Argument.value", new_body):
                    nodes += 1
                occurrences += body_occ
    return nodes, occurrences


def ensure_testplan_udv(root: ET.Element) -> ET.Element:
    test_plan = None
    for element in root.iter("TestPlan"):
        test_plan = element
        break
    if test_plan is None:
        raise JmxAutoCorrelationError("Could not find TestPlan element in JMX.")

    for child in list(test_plan):
        if child.tag == "elementProp" and child.attrib.get("name") == "TestPlan.user_defined_variables":
            collection = None
            for grand in child:
                if grand.tag == "collectionProp" and grand.attrib.get("name") == "Arguments.arguments":
                    collection = grand
                    break
            if collection is None:
                collection = ET.SubElement(child, "collectionProp", {"name": "Arguments.arguments"})
            return collection

    udv = ET.Element(
        "elementProp",
        {
            "name": "TestPlan.user_defined_variables",
            "elementType": "Arguments",
            "guiclass": "ArgumentsPanel",
            "testclass": "Arguments",
            "testname": "User Defined Variables",
        },
    )
    collection = ET.SubElement(udv, "collectionProp", {"name": "Arguments.arguments"})
    test_plan.insert(0, udv)
    return collection


def add_or_update_udv(root: ET.Element, candidates: dict[str, Candidate]) -> tuple[int, int]:
    collection = ensure_testplan_udv(root)
    existing: dict[str, ET.Element] = {}
    for child in collection:
        if child.tag == "elementProp":
            name = get_prop(child, "Argument.name", child.attrib.get("name", ""))
            if name:
                existing[name] = child

    added = 0
    skipped = 0
    for cand in sorted(candidates.values(), key=lambda c: c.variable):
        fallback = sorted(cand.original_values, key=len, reverse=True)[0] if cand.original_values else "NOT_FOUND"
        if not fallback or fallback.startswith("${"):
            fallback = "NOT_FOUND"
        if cand.variable in existing:
            skipped += 1
            continue
        arg = ET.Element("elementProp", {"name": cand.variable, "elementType": "Argument"})
        arg.append(string_prop("Argument.name", cand.variable))
        arg.append(string_prop("Argument.value", fallback))
        arg.append(string_prop("Argument.desc", f"{GENERATED_MARKER}. Fallback value; Smart Capture overwrites during replay."))
        arg.append(string_prop("Argument.metadata", "="))
        collection.append(arg)
        added += 1
    return added, skipped


def has_cookie_manager(root: ET.Element) -> bool:
    return any(element.tag == "CookieManager" for element in root.iter())


def ensure_cookie_manager(root: ET.Element) -> bool:
    if has_cookie_manager(root):
        return False
    # Add under the first ThreadGroup so it is in scope for that thread group.
    for _parent, element, child_tree in iter_jmeter_pairs(root):
        if element.tag == "ThreadGroup":
            cm = ET.Element("CookieManager", {
                "guiclass": "CookiePanel",
                "testclass": "CookieManager",
                "testname": GENERATED_COOKIE_MANAGER_NAME,
                "enabled": "true",
            })
            cm.append(ET.Element("collectionProp", {"name": "CookieManager.cookies"}))
            cm.append(bool_prop("CookieManager.clearEachIteration", False))
            cm.append(bool_prop("CookieManager.controlledByThreadGroup", False))
            child_tree.insert(0, ET.Element("hashTree"))
            child_tree.insert(0, cm)
            return True
    return False


def remove_existing_smart_capture(root: ET.Element) -> int:
    removed = 0
    changed = True
    while changed:
        changed = False
        for parent_tree, element, child_tree in list(iter_jmeter_pairs(root)):
            if element.tag == "JSR223PostProcessor" and element.attrib.get("testname") == GENERATED_TESTNAME:
                remove_hash_tree_pair(parent_tree, element, child_tree)
                removed += 1
                changed = True
                break
    return removed


def make_smart_capture_script(candidates: dict[str, Candidate]) -> str:
    configs = []
    for cand in sorted(candidates.values(), key=lambda c: c.variable):
        keys = set(cand.capture_keys)
        # Add common aliases based on category without including credentials.
        if cand.category == "csrf":
            keys.update(["csrf", "csrf_token", "csrfToken", "_csrf", "authenticity_token", "X-CSRF-Token", "X-XSRF-Token", "__RequestVerificationToken"])
        elif cand.category == "session":
            keys.update(["JSESSIONID", "jsessionid", "sessionId", "session_id", "sid", "SID", "gsessionid", "session_token"])
        elif cand.category == "access_token":
            keys.update(["access_token", "accessToken", "authToken", "token", "jwt"])
        elif cand.category == "refresh_token":
            keys.update(["refresh_token", "refreshToken"])
        elif cand.category == "etag":
            keys.update(["ETag", "etag"])
        keys = {k for k in keys if not is_credential_key(k) and not is_static_key(k)}
        configs.append({"var": cand.variable, "category": cand.category, "keys": sorted(keys)})
    encoded = base64.b64encode(json.dumps(configs).encode("utf-8")).decode("ascii")
    return f'''import groovy.json.JsonSlurper
import java.util.regex.Pattern

String responseText = ''
try {{ responseText = prev.getResponseDataAsString() ?: '' }} catch (Throwable ignored) {{ responseText = '' }}
String responseHeaders = ''
try {{ responseHeaders = prev.getResponseHeaders() ?: '' }} catch (Throwable ignored) {{ responseHeaders = '' }}
String text = responseText + '\n' + responseHeaders
if (text.trim().length() == 0) {{
    return
}}

String configJson = new String(java.util.Base64.getDecoder().decode('{encoded}'), 'UTF-8')
def configs = new JsonSlurper().parseText(configJson)

def cleanValue = {{ value ->
    if (value == null) return null
    String cleaned = value.toString().trim()
    cleaned = cleaned.replaceAll(/^[\\s\"'=:\\[]+/, '')
    cleaned = cleaned.replaceAll(/[\\s\"',;\\]}}<>]+$/, '')
    if (cleaned.length() == 0) return null
    if (cleaned.equalsIgnoreCase('null') || cleaned.equalsIgnoreCase('undefined')) return null
    if (cleaned.startsWith('${{') && cleaned.endsWith('}}')) return null
    return cleaned
}}

def findFirst = {{ patternText ->
    try {{
        def matcher = Pattern.compile(patternText.toString()).matcher(text)
        if (matcher.find()) {{
            return cleanValue(matcher.group(1))
        }}
    }} catch (Throwable ignored) {{
        return null
    }}
    return null
}}

def genericPatternsForKey = {{ key ->
    String q = Pattern.quote(key.toString())
    return [
        /(?is)<input[^>]*(?:name|id)=[\"']/ + q + /[\"'][^>]*value=[\"']([^\"']+)[\"']/,
        /(?is)<input[^>]*value=[\"']([^\"']+)[\"'][^>]*(?:name|id)=[\"']/ + q + /[\"']/,
        /(?is)<meta[^>]*(?:name|id)=[\"']/ + q + /[\"'][^>]*content=[\"']([^\"']+)[\"']/,
        /(?is)[\"']/ + q + /[\"']\\s*:\\s*[\"']([^\"']+)[\"']/,
        /(?is)\\b/ + q + /\\b\\s*[:=]\\s*[\"']?([^&\"'<>\\s,;}}]+)/,
        /(?is)[?&]/ + q + /=([^&\"'<>\\s]+)/
    ]
}}

def categoryPatterns = {{ category ->
    switch (category.toString()) {{
        case 'access_token':
            return [
                /(?is)[\"'](?:access_token|accessToken|authToken|jwt)[\"']\\s*:\\s*[\"']([^\"']+)[\"']/,
                /(?im)^Authorization:\\s*Bearer\\s+(.+)$/
            ]
        case 'refresh_token':
            return [/(?is)[\"'](?:refresh_token|refreshToken)[\"']\\s*:\\s*[\"']([^\"']+)[\"']/]
        case 'id_token':
            return [/(?is)[\"'](?:id_token|idToken)[\"']\\s*:\\s*[\"']([^\"']+)[\"']/]
        case 'csrf':
            return [
                /(?im)^X-(?:CSRF|XSRF)-Token:\\s*(.+)$/,
                /(?is)[\"'](?:csrf|csrf_token|csrfToken|xsrfToken|_csrf|authenticity_token|__RequestVerificationToken)[\"']\\s*:\\s*[\"']([^\"']+)[\"']/
            ]
        case 'etag':
            return [/(?im)^ETag:\\s*\"?([^\"\\r\\n]+)\"?/]
        case 'session':
            return [
                /(?im)^Set-Cookie:\\s*(?:[^=;]*session[^=;]*|JSESSIONID|sid|SID|gsessionid)=([^;\\r\\n]+)/,
                /(?is)(?:jsessionid|sessionId|session_id|sid|SID|gsessionid|session_token)=([^&;\"'<>\\s]+)/
            ]
        default:
            return []
    }}
}}

configs.each {{ cfg ->
    String found = null
    def keys = cfg.keys ?: []
    for (key in keys) {{
        if (key == null || key.toString().trim().length() == 0) continue
        for (patternText in genericPatternsForKey(key)) {{
            found = findFirst(patternText)
            if (found != null) break
        }}
        if (found != null) break
    }}
    if (found == null) {{
        for (patternText in categoryPatterns(cfg.category ?: '')) {{
            found = findFirst(patternText)
            if (found != null) break
        }}
    }}
    if (found != null) {{
        vars.put(cfg.var.toString(), found)
        log.debug('Auto-correlation captured ' + cfg.var + ' from ' + sampler.getName())
    }}
}}
'''


def ensure_smart_capture(root: ET.Element, candidates: dict[str, Candidate]) -> tuple[int, int]:
    skipped = remove_existing_smart_capture(root)
    if not candidates:
        return 0, skipped
    script = make_smart_capture_script(candidates)
    processor = ET.Element("JSR223PostProcessor", {
        "guiclass": "TestBeanGUI",
        "testclass": "JSR223PostProcessor",
        "testname": GENERATED_TESTNAME,
        "enabled": "true",
    })
    processor.append(string_prop("cacheKey", "auto_correlation_smart_capture_v3"))
    processor.append(string_prop("filename", ""))
    processor.append(string_prop("parameters", ""))
    processor.append(string_prop("scriptLanguage", "groovy"))
    processor.append(string_prop("script", script))

    # Put it under the first ThreadGroup scope so it applies to all samplers in the thread group.
    for _parent, element, child_tree in iter_jmeter_pairs(root):
        if element.tag == "ThreadGroup":
            child_tree.insert(0, ET.Element("hashTree"))
            child_tree.insert(0, processor)
            return 1, skipped
    return 0, skipped


def auto_preview_jmx_bytes(jmx_bytes: bytes) -> dict[str, Any]:
    tree, repair = parse_jmx_bytes(jmx_bytes)
    root = tree.getroot()
    removed, classes = remove_unsupported_plugin_elements(root)
    candidates = detect_candidates(root)
    return {
        "samplers": sampler_summary(root),
        "candidates": [c.to_dict() for c in sorted(candidates.values(), key=lambda c: c.variable)],
        "unsupported_plugin_elements_removed": removed,
        "unsupported_plugin_classes": classes,
        "xml_repair_report": repair.to_dict(),
    }


def validate_generated_jmx(jmx_bytes: bytes) -> None:
    try:
        root = ET.fromstring(jmx_bytes)
    except ET.ParseError as exc:
        raise JmxAutoCorrelationError(f"Generated JMX is not valid XML: {exc}") from exc
    bad_refs = []
    for element in root.iter():
        if element.tag in UNSUPPORTED_PLUGIN_CLASS_NAMES or any(element.tag.startswith(p) for p in UNSUPPORTED_PLUGIN_CLASS_PREFIXES):
            bad_refs.append(element.tag)
    if bad_refs:
        raise JmxAutoCorrelationError(f"Generated JMX still contains unsupported plugin classes: {sorted(set(bad_refs))}")
    text = jmx_bytes.decode("utf-8", errors="replace")
    # Guard against the earlier failure mode: tiny values replacing parts of static strings.
    if "${AUTHUSER}" in text or "${V}" in text:
        raise JmxAutoCorrelationError("Unsafe low-value correlation detected in generated JMX. Generation was stopped.")


def auto_correlate_jmx_bytes(jmx_bytes: bytes) -> tuple[bytes, AutoCorrelationSummary, bytes]:
    tree, repair_report = parse_jmx_bytes(jmx_bytes)
    root = tree.getroot()
    summary = AutoCorrelationSummary(xml_repair_report=repair_report.to_dict())

    removed, classes = remove_unsupported_plugin_elements(root)
    summary.unsupported_plugin_elements_removed = removed
    summary.unsupported_plugin_classes = classes
    if removed:
        summary.warnings.append("Removed unsupported third-party/plugin-only JMeter elements so the JMX can open in stock JMeter.")
    if any(v for v in repair_report.to_dict().values() if isinstance(v, bool) and v) or any(v for v in repair_report.to_dict().values() if isinstance(v, int) and v > 0):
        summary.warnings.append("The uploaded JMX/XML was automatically repaired before parsing. See xml_repair_report.")

    summary.sampler_count = len(get_samplers(root))
    candidates = detect_candidates(root)
    summary.candidates_detected = len(candidates)
    summary.original_values_detected = sum(len(c.original_values) for c in candidates.values())
    summary.candidates = [c.to_dict() for c in sorted(candidates.values(), key=lambda c: c.variable)]

    added_udv, skipped_udv = add_or_update_udv(root, candidates)
    summary.default_variables_added = added_udv
    summary.default_variables_skipped = skipped_udv

    cookie_added = ensure_cookie_manager(root)
    summary.cookie_manager_added = cookie_added
    if cookie_added:
        summary.warnings.append("HTTP Cookie Manager was added automatically for cookie-based sessions.")

    n, o = replace_argument_values(root, candidates)
    summary.replacement_nodes_changed += n
    summary.replacement_occurrences += o
    n, o = replace_path_query_values(root, candidates)
    summary.replacement_nodes_changed += n
    summary.replacement_occurrences += o
    n, o = replace_header_values(root, candidates)
    summary.replacement_nodes_changed += n
    summary.replacement_occurrences += o
    n, o = replace_raw_body_values(root, candidates)
    summary.replacement_nodes_changed += n
    summary.replacement_occurrences += o

    added_smart, skipped_smart = ensure_smart_capture(root, candidates)
    summary.smart_capture_processors_added = added_smart
    summary.smart_capture_processors_skipped = skipped_smart

    if not candidates:
        summary.warnings.append("No safe dynamic values were detected. Output includes XML repair/plugin cleanup/cookie handling only.")
    summary.warnings.append("Safe mode avoids correlating short/static values such as 0, 1, versions, browser headers, API keys, emails, and passwords.")

    patched = tree_to_bytes(tree)
    validate_generated_jmx(patched)
    report_bytes = json.dumps(summary.to_dict(), indent=2).encode("utf-8")
    return patched, summary, report_bytes


def make_output_zip(patched_jmx: bytes, report_json: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("auto_correlated.jmx", patched_jmx)
        zf.writestr("auto_correlation_report.json", report_json)
    return buffer.getvalue()


def run_jmeter_cli(jmx_bytes: bytes, jmeter_bin: str = "jmeter", make_report: bool = False, timeout_seconds: int = 300) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        jmx_path = tmp_path / "auto_correlated.jmx"
        jtl_path = tmp_path / "results.jtl"
        report_dir = tmp_path / "html-report"
        jmx_path.write_bytes(jmx_bytes)
        cmd = [jmeter_bin, "-n", "-t", str(jmx_path), "-l", str(jtl_path)]
        if make_report:
            cmd.extend(["-e", "-o", str(report_dir)])
        try:
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout_seconds)
        except FileNotFoundError as exc:
            raise JmxAutoCorrelationError(f"JMeter executable not found: {jmeter_bin}") from exc
        except subprocess.TimeoutExpired as exc:
            raise JmxAutoCorrelationError(f"JMeter run timed out after {timeout_seconds} seconds.") from exc
        result: dict[str, Any] = {
            "command": " ".join(cmd),
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "jtl_bytes": jtl_path.read_bytes() if jtl_path.exists() else b"",
            "report_zip_bytes": b"",
        }
        if make_report and report_dir.exists():
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                for path in report_dir.rglob("*"):
                    if path.is_file():
                        zf.write(path, path.relative_to(report_dir))
            result["report_zip_bytes"] = zip_buffer.getvalue()
        return result
