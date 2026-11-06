"""Content and input detectors. Pure functions, stdlib only.

Detectors here are heuristics. They raise alerts and taint sessions; they are
not a security boundary. A clean result means "no known pattern found".
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit, parse_qsl

HIGH, MEDIUM, LOW = "high", "medium", "low"


@dataclass
class Finding:
    kind: str
    severity: str
    excerpt: str = ""

    def as_dict(self) -> dict:
        return {"kind": self.kind, "severity": self.severity, "excerpt": self.excerpt}


# --- invisible / smuggling characters --------------------------------------

def _is_tag(o: int) -> bool:
    return 0xE0000 <= o <= 0xE007F


def _is_supp_variation_selector(o: int) -> bool:
    return 0xE0100 <= o <= 0xE01EF


ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


def scan_unicode(text: str) -> list[Finding]:
    tags = vs = zw = bidi = 0
    for ch in text:
        o = ord(ch)
        if _is_tag(o):
            tags += 1
        elif _is_supp_variation_selector(o):
            vs += 1
        elif o in ZERO_WIDTH:
            zw += 1
        elif o in BIDI:
            bidi += 1
    out = []
    if tags:
        out.append(Finding("unicode-tag-characters", HIGH, f"{tags} Unicode tag characters (invisible ASCII smuggling)"))
    if vs >= 4:
        out.append(Finding("variation-selector-smuggling", HIGH, f"{vs} supplementary variation selectors (emoji smuggling)"))
    if zw >= 3:
        # Common in newsletters (preview-text padding) and unable to carry readable text
        # on their own, so log-only.
        out.append(Finding("zero-width-characters", LOW, f"{zw} zero-width characters"))
    if bidi:
        out.append(Finding("bidi-controls", MEDIUM, f"{bidi} bidirectional control characters"))
    return out


def strip_invisible(text: str) -> str:
    return "".join(
        ch for ch in text
        if not (_is_tag(ord(ch)) or _is_supp_variation_selector(ord(ch))
                or ord(ch) in ZERO_WIDTH or ord(ch) in BIDI)
    )


# --- instruction-like text ---------------------------------------------------

_OVERRIDE = re.compile(
    r"(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)?"
    r"(previous|prior|above|earlier|system|original)\s+(instructions|prompts?|rules|directions)"
    r"|\byou\s+are\s+now\s+(an?\s+|in\s+)?\w+"
    r"|\bnew\s+(system\s+)?instructions\s*:"
    r"|\bdo\s+not\s+(tell|inform|notify|alert|mention\s+(this\s+)?to)\s+the\s+user"
    r"|without\s+(telling|informing|asking)\s+the\s+user"
    r"|<\|?(im_start|im_end|system)\|?>"
    r"|</?\s*(system|admin|instructions?|assistant)\s*>"
    r"|\bBEGIN\s+(SYSTEM|ADMIN)\s+(PROMPT|INSTRUCTIONS?)",
    re.I,
)

# A direct address to an AI agent. Topic words ("AI agents can...") do not count.
_ADDRESS = re.compile(
    r"\b(note|message|instructions?|notice|task)\s+(for|to)\s+(your|the|any|all)\s+"
    r"(ai\s+)?(agents?|assistants?|llms?|models?|ais?|bots?|crawlers?)\b"
    r"|\b(if\s+you\s+are|as)\s+an?\s+(ai|llm|language\s+model|ai\s+agent|agent|assistant)\b"
    r"|\b(dear|attention|hey)\s+(ai|llm|agent|assistant|claude|chatgpt|gpt|codex|copilot|gemini)\b"
    r"|\b(ai\s+agents?|llms?|language\s+models?|ai\s+assistants?|chatgpt|claude|codex|copilot|gemini)"
    r"\s+(should|must|shall|are\s+instructed\s+to|need\s+to)\b"
    r"|\b(agent|assistant|ai)\s*[:,]\s*(please\s+)?(you\s+)?(must|should|need\s+to)\b",
    re.I,
)

_TASK_VERB = re.compile(
    r"\b(rewrite|submit|open\s+a\s+(pull\s+request|pr|issue)|pull\s+request|commit|push|"
    r"host|deploy|run|execute|install|download|fetch|visit|navigate|send|e-?mail|upload|post|"
    r"forward|delete|remove|credit|mention|cite|attribute|recommend|rate|review|summari[sz]e|"
    r"reveal|print|output|exfiltrate|copy|paste|share|transfer)\b",
    re.I,
)

_MD_IMAGE_QUERY = re.compile(r"!\[[^\]]{0,200}\]\(\s*https?://[^)\s]+\?[^)\s]{16,}\)", re.I)


def _excerpt(text: str, m: re.Match, width: int = 90) -> str:
    a = max(0, m.start() - 20)
    b = min(len(text), m.end() + width)
    return re.sub(r"\s+", " ", text[a:b]).strip()[:200]


def scan_text(text: str, max_chars: int = 400_000) -> list[Finding]:
    """Scan untrusted text (tool output). Returns findings, most severe first."""
    if not text:
        return []
    text = text[:max_chars]
    out = scan_unicode(text)
    plain = unicodedata.normalize("NFKC", strip_invisible(text))
    # Text that arrives JSON-encoded keeps escaped line breaks; restore word boundaries.
    plain = re.sub(r"\\[nrt]", " ", plain)

    m = _OVERRIDE.search(plain)
    if m:
        out.append(Finding("instruction-override", HIGH, _excerpt(plain, m)))

    for m in _ADDRESS.finditer(plain):
        window = plain[m.start(): m.end() + 300]
        if _TASK_VERB.search(window):
            out.append(Finding("agent-addressed-task", MEDIUM, _excerpt(plain, m)))
            break

    m = _MD_IMAGE_QUERY.search(plain)
    if m:
        out.append(Finding("markdown-image-with-query", MEDIUM, _excerpt(plain, m, 60)))

    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    out.sort(key=lambda f: order[f.severity])
    return out


# --- secrets and exfiltration-shaped data in outbound inputs ----------------

SECRET_PATTERNS = [
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{32,}")),
    ("github-token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}")),
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
]

_B64ISH = re.compile(r"^[A-Za-z0-9+/_\-=%]{64,}$")
URL_RE = re.compile(r"https?://[^\s'\"<>()]+", re.I)


def find_secrets(text: str) -> list[Finding]:
    out = []
    for name, rx in SECRET_PATTERNS:
        m = rx.search(text or "")
        if m:
            v = m.group(0)
            out.append(Finding(f"secret:{name}", HIGH, v[:6] + "…" + f"({len(v)} chars)"))
    return out


def url_exfil_findings(url: str) -> list[Finding]:
    """Findings for a single URL that is about to be requested."""
    out = []
    try:
        parts = urlsplit(url)
    except ValueError:
        return out
    blob = (parts.query or "") + "&" + (parts.fragment or "")
    for _, value in parse_qsl(blob, keep_blank_values=True):
        if _B64ISH.match(value):
            out.append(Finding("url-encoded-blob", HIGH, f"query value of {len(value)} chars"))
            break
    if len(parts.path) > 200 and _B64ISH.match(parts.path.strip("/").split("/")[-1] or ""):
        out.append(Finding("url-path-blob", HIGH, f"path segment of {len(parts.path)} chars"))
    out += find_secrets(url)
    return out


def urls_in(text: str) -> list[str]:
    return URL_RE.findall(text or "")
