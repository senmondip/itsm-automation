#!/usr/bin/env python3
"""
runbook-linter - Runbook linter for ServiceNow / ITIL change and operations runbooks.

WHAT IT DOES
    Checks runbooks for the three sections ITIL change reviewers most often
    find missing or hollow:
      * Rollback   (a.k.a. back-out / revert / fallback plan)
      * Validation (a.k.a. verification / post-implementation checks / smoke test)
      * Escalation (a.k.a. escalation path / on-call / points of contact)

    For each runbook it reports:
      ERROR    a required section is missing entirely
      WARNING  a section exists but is empty or only holds a placeholder
               (TBD, N/A, TODO, "none", ...), or an escalation section names
               nobody to escalate to
      INFO     a section exists but looks weak (rollback with no concrete
               steps, validation with no expected result, escalation with no
               time/severity trigger)

    Runbooks can come from local files/directories, from ServiceNow
    (Knowledge Base articles by default, via the Table API), or both.

WHAT IT ASSUMES
    * Python 3.8+, standard library only (no pip installs required).
    * Local runbooks are Markdown, plain text, reStructuredText or HTML.
      Sections are recognised from Markdown/RST headings, HTML <h1>-<h6>,
      bold-only lines, ALL-CAPS lines and Title-Case "Label:" lines.
    * ServiceNow access (only when --servicenow is used):
        SN_INSTANCE   instance base URL, e.g. https://<your-instance-host>
        SN_TOKEN      OAuth bearer token, OR
        SN_USER + SN_PASSWORD  for basic auth
      The account needs read access to the chosen table (kb_knowledge by
      default). The password is deliberately env-only so it never shows up
      in shell history or the process list.
    * SN_CA_BUNDLE (optional) points at a CA bundle for TLS-intercepting
      corporate proxies. TLS verification is never disabled.

HOW TO RUN
    # Lint a directory of Markdown/HTML runbooks
    ./runbook_linter.py --path ./runbooks

    # Several paths, JSON report to a file, fail the build on warnings too
    ./runbook_linter.py --path ops/ --path dr/failover.md \
        --json --output report.json --fail-on warning

    # Lint published ServiceNow KB articles whose title mentions "runbook"
    export SN_INSTANCE=https://<your-instance-host>
    export SN_USER=svc_linter SN_PASSWORD=...        # or: export SN_TOKEN=...
    ./runbook_linter.py --servicenow \
        --sn-query 'workflow_state=published^short_descriptionLIKErunbook'

    # Read one runbook from stdin
    cat change.md | ./runbook_linter.py --path -

EXIT CODES
    0  no findings at or above --fail-on severity
    1  findings at or above --fail-on severity
    2  usage / configuration error (bad flags, missing path or credentials)
    3  runtime error talking to ServiceNow
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

if sys.version_info < (3, 8):  # pragma: no cover - guard for ancient interpreters
    sys.stderr.write("runbook-linter: Python 3.8 or newer is required.\n")
    sys.exit(2)

VERSION = "1.0.0"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_RUNTIME = 3

SEVERITY_RANK = {"info": 0, "warning": 1, "error": 2}

DEFAULT_EXTENSIONS = (".md", ".markdown", ".txt", ".rst", ".html", ".htm")
HTML_EXTENSIONS = {".html", ".htm"}

# Heading levels. Explicit markup (Markdown/HTML h1-h6) uses 1-6. Weaker,
# inferred headings get higher numbers so they nest *under* explicit ones:
# a "Steps:" label inside "## Rollback" stays part of the rollback section
# instead of terminating it.
LEVEL_ALLCAPS = 7
LEVEL_BOLD = 7
LEVEL_LABEL = 8


class UsageError(Exception):
    """Bad flags, paths or credentials - exit 2."""


class RuntimeFailure(Exception):
    """Remote system failed - exit 3."""


# --------------------------------------------------------------------------
# Section definitions
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SectionSpec:
    key: str
    label: str
    pattern: "re.Pattern[str]"
    examples: Tuple[str, ...]


SECTION_SPECS: Dict[str, SectionSpec] = {
    "rollback": SectionSpec(
        key="rollback",
        label="Rollback",
        pattern=re.compile(
            r"\b(roll[\s-]?back|back[\s-]?out|revert(?:ing)?|reversion|"
            r"fall[\s-]?back|undo)\b",
            re.I,
        ),
        examples=("Rollback", "Back-out plan", "Revert procedure"),
    ),
    "validation": SectionSpec(
        key="validation",
        label="Validation",
        pattern=re.compile(
            r"\b(validat\w*|verif\w*|"
            r"post[\s-]?(?:implementation|change|deploy\w*|install\w*)\s+"
            r"(?:checks?|tests?|testing|reviews?)|"
            r"smoke[\s-]?tests?|health[\s-]?checks?|testing|test\s+plan|"
            r"(?:success|acceptance)\s+criteria)\b",
            re.I,
        ),
        examples=("Validation", "Verification", "Post-implementation checks"),
    ),
    "escalation": SectionSpec(
        key="escalation",
        label="Escalation",
        pattern=re.compile(
            r"\b(escalat\w*|on[\s-]?call|points?\s+of\s+contact|contacts?|"
            r"support\s+(?:groups?|teams?)|assignment\s+groups?)\b",
            re.I,
        ),
        examples=("Escalation", "Escalation path", "On-call contacts"),
    ),
}

# Content that means "someone meant to fill this in later".
PLACEHOLDER_RE = re.compile(
    r"\b(?:tbd|tbc|todo|fixme|to\s+be\s+(?:confirmed|determined|added|updated|defined)|"
    r"fill\s+(?:in|me)|lorem\s+ipsum)\b"
    r"|^\s*(?:n/?a|none|nil|-+|\.{3}|same\s+as\s+above|see\s+above)\s*\.?\s*$"
    r"|<\s*(?:insert|add|placeholder|your)[^>]*>",
    re.I | re.M,
)

# Lines that look like concrete, executable steps.
STEP_RE = re.compile(
    r"^\s*(?:[-*+\u2022]|\d+[.)]|[a-z][.)])\s+\S"  # bullets / numbered steps
    r"|^\s*```"                                      # fenced code
    r"|^ {4,}\S"                                     # indented code
    r"|^\s*[$#>]\s+\S",                              # shell prompts
    re.M | re.I,
)

CONTACT_RE = re.compile(
    r"[\w.+-]+@[\w-]+\.[\w.-]+"                      # email
    r"|\+?\d[\d\s().-]{7,}\d"                        # phone number
    r"|(?<!\w)@[\w.-]{2,}"                           # @handle / @channel
    r"|https?://\S+"                                 # link to rota / group page
    r"|\b(?:group|team|pager\w*|on[\s-]?call|manager|duty|rota|roster|"
    r"slack|channel|bridge|hotline|service\s+desk|sme|owner|lead)\b",
    re.I,
)

ESCALATION_TRIGGER_RE = re.compile(
    r"\b\d+\s*(?:s|sec|secs|seconds?|m|mins?|minutes?|h|hrs?|hours?)\b"
    r"|\b(?:sla|ola|p[1-5]|sev(?:erity)?\s*[1-5]|priority\s*[1-5]|"
    r"immediately|after|within|if|when|unresolved|exceed\w*)\b",
    re.I,
)

EXPECTED_RESULT_RE = re.compile(
    r"\b(?:expect\w*|should|confirm\w*|ensure|returns?|status|healthy|"
    r"success\w*|pass(?:es|ed)?|no\s+errors?|http\s*\d{3}|\d{3}\s+ok|"
    r"up|running|green|matches)\b",
    re.I,
)


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class Document:
    source: str                 # file path or "table:number"
    title: str
    text: str                   # normalised text (HTML already converted)
    url: Optional[str] = None
    converted_from_html: bool = False


@dataclass
class Heading:
    line: int                   # 1-based line number of the heading
    body_start: int             # 0-based index of first body line
    text: str
    level: int
    inline: str = ""            # content after "Label:" on the same line


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    section: Optional[str] = None
    line: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "code": self.code,
            "section": self.section,
            "line": self.line,
            "message": self.message,
        }


@dataclass
class SectionResult:
    found: bool
    line: Optional[int] = None
    heading: Optional[str] = None
    words: int = 0


@dataclass
class DocumentReport:
    doc: Document
    sections: Dict[str, SectionResult] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.doc.source,
            "title": self.doc.title,
            "url": self.doc.url,
            "line_numbers_refer_to": (
                "text converted from HTML" if self.doc.converted_from_html else "source"
            ),
            "sections": {
                k: {"found": v.found, "line": v.line, "heading": v.heading, "words": v.words}
                for k, v in self.sections.items()
            },
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------
# HTML -> heading-preserving text
# --------------------------------------------------------------------------

class _HTMLToText(HTMLParser):
    """Flatten HTML to Markdown-ish text so one heading parser handles both.

    ServiceNow KB articles are HTML; authors use a mix of <h2>, <p><strong>
    and plain paragraphs as headings, so we keep h-tags as '#' headings and
    <strong>/<b> as '**' so the bold-line heuristic still works.
    """

    BLOCK = {"p", "div", "br", "tr", "table", "ul", "ol", "section", "article",
             "header", "footer", "blockquote", "hr", "dl", "dt", "dd"}
    SKIP = {"script", "style", "head", "title"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self._skip_depth = 0
        self._pre_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if tag in self.SKIP:
            self._skip_depth += 1
        elif re.fullmatch(r"h[1-6]", tag):
            self.parts.append("\n\n" + "#" * int(tag[1]) + " ")
        elif tag == "li":
            self.parts.append("\n- ")
        elif tag == "pre":
            self._pre_depth += 1
            self.parts.append("\n```\n")
        elif tag in ("strong", "b"):
            self.parts.append("**")
        elif tag in ("td", "th"):
            self.parts.append(" | ")
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self.SKIP:
            self._skip_depth = max(0, self._skip_depth - 1)
        elif re.fullmatch(r"h[1-6]", tag):
            self.parts.append("\n")
        elif tag == "pre":
            self._pre_depth = max(0, self._pre_depth - 1)
            self.parts.append("\n```\n")
        elif tag in ("strong", "b"):
            self.parts.append("**")
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._pre_depth:
            self.parts.append(data)
        else:
            self.parts.append(re.sub(r"\s+", " ", data))

    def text(self) -> str:
        raw = "".join(self.parts)
        lines = [ln.rstrip() for ln in raw.splitlines()]
        # "** Rollback **" from <strong> Rollback </strong> -> "**Rollback**"
        lines = [re.sub(r"\*\*\s+(.*?)\s+\*\*", r"**\1**", ln) for ln in lines]
        return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip() + "\n"


def html_to_text(html: str) -> str:
    parser = _HTMLToText()
    parser.feed(html)
    parser.close()
    return parser.text()


# --------------------------------------------------------------------------
# Heading detection
# --------------------------------------------------------------------------

ATX_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
UNDERLINE_RE = re.compile(r"^\s*([=\-~^*+#`'\"])\1{2,}\s*$")
BOLD_LINE_RE = re.compile(r"^\s*(\*\*|__)(.+?)\1\s*:?\s*$")
LABEL_RE = re.compile(r"^\s*(?:\*\*|__)?([A-Za-z][A-Za-z0-9 /&()'.-]{1,60}?)(?:\*\*|__)?\s*:(?:\*\*|__)?\s*(.*)$")
NUMBERED_RE = re.compile(r"^\s*(?:\d+(?:\.\d+)*[.)]?|[A-Z][.)])\s+(.+?)\s*$")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")

SMALL_WORDS = {"a", "an", "and", "or", "of", "the", "to", "for", "in", "on",
               "with", "by", "at", "if", "vs", "via", "per"}


def _is_titleish(text: str) -> bool:
    """True for 'Rollback Plan' / 'Back-out and Recovery', false for prose."""
    words = re.findall(r"[A-Za-z][\w'-]*", text)
    if not words or len(words) > 6:
        return False
    return all(w[0].isupper() or w.lower() in SMALL_WORDS for w in words)


def _matches_any_section(text: str) -> bool:
    return any(spec.pattern.search(text) for spec in SECTION_SPECS.values())


def find_headings(lines: List[str]) -> List[Heading]:
    headings: List[Heading] = []
    in_fence = False
    underline_levels: List[str] = []  # RST: level = order of first appearance
    skip_next = False

    for i, line in enumerate(lines):
        if skip_next:
            skip_next = False
            continue
        # Never look for headings inside code: '# restart nginx' in a bash
        # block is a comment, not a section.
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence or not line.strip():
            continue

        stripped = line.strip()

        m = ATX_RE.match(line)
        if m:
            headings.append(Heading(i + 1, i + 1, m.group(2).strip("*_ "), len(m.group(1))))
            continue

        # Setext (Markdown) and RST underlined headings.
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        um = UNDERLINE_RE.match(nxt)
        if (um and len(stripped) <= 80 and not LIST_ITEM_RE.match(line)
                and len(nxt.strip()) >= min(3, len(stripped))):
            char = um.group(1)
            if char not in underline_levels:
                underline_levels.append(char)
            level = min(6, underline_levels.index(char) + 1)
            headings.append(Heading(i + 1, i + 2, stripped.strip("*_ :"), level))
            skip_next = True
            continue

        m = BOLD_LINE_RE.match(line)
        if m and len(m.group(2).split()) <= 8:
            headings.append(Heading(i + 1, i + 1, m.group(2).strip(" :"), LEVEL_BOLD))
            continue

        m = LABEL_RE.match(line)
        if m and len(m.group(1).split()) <= 6 and not LIST_ITEM_RE.match(line):
            label, rest = m.group(1).strip(), m.group(2).strip()
            if rest and _matches_any_section(label):
                # "Rollback: redeploy previous build" - inline section.
                headings.append(Heading(i + 1, i + 1, label, LEVEL_LABEL, inline=rest))
                continue
            if not rest and (_is_titleish(label) or _matches_any_section(label)):
                headings.append(Heading(i + 1, i + 1, label, LEVEL_LABEL))
                continue

        # Numbered headings ("5. Rollback Plan") are only trusted when they
        # name a section we care about; otherwise every numbered step in a
        # procedure would be mistaken for a heading.
        m = NUMBERED_RE.match(line)
        if m and _is_titleish(m.group(1)) and _matches_any_section(m.group(1)) \
                and not m.group(1).endswith("."):
            headings.append(Heading(i + 1, i + 1, m.group(1).strip("*_ :"), LEVEL_LABEL))
            continue

        letters = re.sub(r"[^A-Za-z]", "", stripped)
        if (len(letters) >= 4 and letters.isupper() and len(stripped.split()) <= 6
                and not stripped.endswith(".")):
            headings.append(Heading(i + 1, i + 1, stripped.strip(" :"), LEVEL_ALLCAPS))

    return headings


def section_body(lines: List[str], headings: List[Heading], idx: int) -> str:
    """Text owned by headings[idx]: up to the next heading of same/higher rank."""
    h = headings[idx]
    end = len(lines)
    for later in headings[idx + 1:]:
        if later.level <= h.level:
            end = later.line - 1
            break
    body = "\n".join(lines[h.body_start:end]).strip()
    return (h.inline + "\n" + body).strip() if h.inline else body


# --------------------------------------------------------------------------
# Linting
# --------------------------------------------------------------------------

def _word_count(text: str) -> int:
    return len(re.findall(r"[A-Za-z0-9][\w'./-]*", text))


def lint_document(doc: Document, sections: List[str], min_words: int) -> DocumentReport:
    report = DocumentReport(doc)
    lines = doc.text.splitlines()
    headings = find_headings(lines)

    for key in sections:
        spec = SECTION_SPECS[key]
        # A heading may satisfy several sections ("Rollback and Validation").
        # We take the first matching heading as canonical; later duplicates
        # are almost always sub-headings ("Rollback > Verify rollback").
        idx = next((n for n, h in enumerate(headings) if spec.pattern.search(h.text)), None)
        if idx is None:
            report.sections[key] = SectionResult(found=False)
            examples = ", ".join('"%s"' % e for e in spec.examples)
            report.findings.append(Finding(
                "error", "missing-%s" % key,
                "No %s section found. Add a heading such as %s."
                % (spec.label.lower(), examples),
                section=key,
            ))
            continue

        h = headings[idx]
        body = section_body(lines, headings, idx)
        words = _word_count(body)
        report.sections[key] = SectionResult(True, h.line, h.text, words)
        report.findings.extend(_quality_checks(key, spec, h, body, words, min_words))

    report.findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.line or 0))
    return report


def _quality_checks(key: str, spec: SectionSpec, h: Heading, body: str,
                    words: int, min_words: int) -> List[Finding]:
    out: List[Finding] = []
    where = 'under "%s"' % h.text

    if PLACEHOLDER_RE.search(body) or (words and not body.strip(" .-")):
        snippet = PLACEHOLDER_RE.search(body)
        token = snippet.group(0).strip() if snippet else body.strip()
        out.append(Finding(
            "warning", "placeholder-%s" % key,
            "%s section %s contains placeholder text (%r). Replace it with real content."
            % (spec.label, where, token[:40]),
            section=key, line=h.line,
        ))
        return out  # further heuristics on placeholder text are just noise

    if words < min_words:
        out.append(Finding(
            "warning", "empty-%s" % key,
            "%s section %s has only %d word(s) (minimum %d). Document the actual procedure."
            % (spec.label, where, words, min_words),
            section=key, line=h.line,
        ))
        return out

    if key == "rollback" and not STEP_RE.search(body):
        out.append(Finding(
            "info", "rollback-no-steps",
            "Rollback section %s has no numbered/bulleted steps or commands; "
            "an on-call engineer may not be able to execute it under pressure." % where,
            section=key, line=h.line,
        ))
    elif key == "validation" and not (STEP_RE.search(body) and EXPECTED_RESULT_RE.search(body)):
        missing = "concrete checks" if not STEP_RE.search(body) else "expected results"
        out.append(Finding(
            "info", "validation-vague",
            "Validation section %s lacks %s; state what to check and what 'good' looks like."
            % (where, missing),
            section=key, line=h.line,
        ))
    elif key == "escalation":
        if not CONTACT_RE.search(body):
            out.append(Finding(
                "warning", "escalation-no-contact",
                "Escalation section %s names no group, rota, channel, email or phone number."
                % where,
                section=key, line=h.line,
            ))
        elif not ESCALATION_TRIGGER_RE.search(body):
            out.append(Finding(
                "info", "escalation-no-trigger",
                "Escalation section %s says who but not when (time limit, priority or failure condition)."
                % where,
                section=key, line=h.line,
            ))
    return out


# --------------------------------------------------------------------------
# Sources: local files
# --------------------------------------------------------------------------

def iter_local_documents(paths: List[str], extensions: Tuple[str, ...]) -> Iterator[Document]:
    for raw in paths:
        if raw == "-":
            if sys.stdin.isatty():
                raise UsageError("--path - given but nothing is piped on stdin.")
            text = sys.stdin.read()
            is_html = bool(re.search(r"<(h[1-6]|p|div|ul|ol|table|body)\b", text, re.I))
            yield _make_local_doc("<stdin>", text, is_html)
            continue

        p = Path(raw).expanduser()
        if not p.exists():
            raise UsageError("Path does not exist: %s" % raw)
        if p.is_file():
            yield _read_file(p)
            continue

        matched = 0
        for f in sorted(p.rglob("*")):
            rel_parts = f.relative_to(p).parts
            # Skip .git, .venv and friends - they never hold runbooks and can be huge.
            if any(part.startswith(".") for part in rel_parts):
                continue
            if f.is_file() and f.suffix.lower() in extensions:
                matched += 1
                yield _read_file(f)
        if not matched:
            sys.stderr.write("runbook-linter: warning: no files with extensions %s under %s\n"
                             % (", ".join(extensions), raw))


def _read_file(path: Path) -> Document:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise UsageError("Cannot read %s: %s" % (path, exc.strerror or exc))
    return _make_local_doc(str(path), text, path.suffix.lower() in HTML_EXTENSIONS)


def _make_local_doc(source: str, text: str, is_html: bool) -> Document:
    if is_html:
        text = html_to_text(text)
    title = next((ln.strip("# *=").strip() for ln in text.splitlines() if ln.strip()), source)
    return Document(source=source, title=title[:120], text=text, converted_from_html=is_html)


# --------------------------------------------------------------------------
# Sources: ServiceNow Table API
# --------------------------------------------------------------------------

@dataclass
class ServiceNowConfig:
    base_url: str
    table: str
    query: str
    body_field: str
    title_field: str
    limit: int
    timeout: float
    auth_header: str
    ssl_context: ssl.SSLContext


def build_servicenow_config(args: argparse.Namespace) -> ServiceNowConfig:
    instance = (args.sn_instance or os.environ.get("SN_INSTANCE", "")).strip()
    if not instance:
        raise UsageError("ServiceNow instance not set. Use --sn-instance or export SN_INSTANCE "
                         "(e.g. https://<your-instance-host>).")
    if "://" not in instance:
        instance = "https://" + instance
    parsed = urllib.parse.urlparse(instance)
    if parsed.scheme != "https" or not parsed.netloc:
        raise UsageError("SN_INSTANCE must be an https URL or hostname, got %r." % instance)
    base_url = "%s://%s" % (parsed.scheme, parsed.netloc)

    token = os.environ.get("SN_TOKEN", "").strip()
    user = (args.sn_user or os.environ.get("SN_USER", "")).strip()
    password = os.environ.get("SN_PASSWORD", "")
    if token:
        auth = "Bearer " + token
    elif user and password:
        auth = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
    else:
        missing = "SN_PASSWORD" if user else "SN_USER and SN_PASSWORD"
        raise UsageError("ServiceNow credentials missing: export SN_TOKEN, or %s." % missing)

    ca_bundle = os.environ.get("SN_CA_BUNDLE", "").strip()
    if ca_bundle and not Path(ca_bundle).is_file():
        raise UsageError("SN_CA_BUNDLE points to a missing file: %s" % ca_bundle)
    ctx = ssl.create_default_context(cafile=ca_bundle or None)

    if args.sn_limit < 1:
        raise UsageError("--sn-limit must be at least 1.")

    return ServiceNowConfig(
        base_url=base_url, table=args.sn_table, query=args.sn_query,
        body_field=args.sn_body_field, title_field=args.sn_title_field,
        limit=args.sn_limit, timeout=args.sn_timeout, auth_header=auth, ssl_context=ctx,
    )


def _sn_get(cfg: ServiceNowConfig, params: Dict[str, str]) -> dict:
    url = "%s/api/now/table/%s?%s" % (cfg.base_url, urllib.parse.quote(cfg.table),
                                      urllib.parse.urlencode(params))
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "Authorization": cfg.auth_header,
        "User-Agent": "runbook-linter/%s" % VERSION,
    })
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout, context=cfg.ssl_context) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        hints = {
            401: "authentication failed - check SN_TOKEN or SN_USER/SN_PASSWORD",
            403: "account lacks read access (ACL/role) on table %r" % cfg.table,
            404: "table %r not found, or SN_INSTANCE is not a ServiceNow instance" % cfg.table,
            429: "rate limited by the instance - retry later or lower --sn-limit",
        }
        detail = hints.get(exc.code, exc.read(300).decode("utf-8", "replace").strip())
        raise RuntimeFailure("ServiceNow HTTP %d: %s" % (exc.code, detail))
    except urllib.error.URLError as exc:
        raise RuntimeFailure("Cannot reach %s: %s" % (cfg.base_url, exc.reason))
    except (TimeoutError, OSError) as exc:
        raise RuntimeFailure("Network error talking to %s: %s" % (cfg.base_url, exc))
    try:
        return json.loads(raw)
    except ValueError:
        # Typically an SSO login page or a hibernating developer instance.
        raise RuntimeFailure("ServiceNow returned non-JSON (SSO redirect or instance asleep?): %r"
                             % raw[:120])


def iter_servicenow_documents(cfg: ServiceNowConfig) -> Iterator[Document]:
    page_size = min(100, cfg.limit)
    fields = ["sys_id", "number", cfg.title_field, cfg.body_field]
    offset = fetched = 0
    while fetched < cfg.limit:
        params = {
            "sysparm_query": cfg.query,
            "sysparm_fields": ",".join(dict.fromkeys(fields)),
            "sysparm_limit": str(min(page_size, cfg.limit - fetched)),
            "sysparm_offset": str(offset),
            "sysparm_exclude_reference_link": "true",
        }
        records = _sn_get(cfg, params).get("result", [])
        if not isinstance(records, list):
            raise RuntimeFailure("Unexpected ServiceNow response shape: 'result' is not a list.")
        if not records:
            break
        for rec in records:
            # ServiceNow silently drops unknown fields from sysparm_fields
            # rather than erroring, so check explicitly.
            if cfg.body_field not in rec:
                raise UsageError("Field %r not returned by table %r; check --sn-body-field."
                                 % (cfg.body_field, cfg.table))
            sys_id = rec.get("sys_id", "")
            ident = rec.get("number") or sys_id
            yield Document(
                source="%s:%s" % (cfg.table, ident),
                title=str(rec.get(cfg.title_field) or ident),
                text=html_to_text(str(rec.get(cfg.body_field) or "")),
                url="%s/nav_to.do?uri=%s.do?sys_id=%s" % (cfg.base_url, cfg.table, sys_id),
                converted_from_html=True,
            )
        fetched += len(records)
        offset += len(records)
        if len(records) < page_size:
            break


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def summarize(reports: List[DocumentReport]) -> dict:
    counts = {"error": 0, "warning": 0, "info": 0}
    for r in reports:
        for f in r.findings:
            counts[f.severity] += 1
    return {
        "documents": len(reports),
        "clean": sum(1 for r in reports if not r.findings),
        "errors": counts["error"],
        "warnings": counts["warning"],
        "info": counts["info"],
    }


def render_text(reports: List[DocumentReport], min_sev: str) -> str:
    out: List[str] = []
    threshold = SEVERITY_RANK[min_sev]
    for r in reports:
        shown = [f for f in r.findings if SEVERITY_RANK[f.severity] >= threshold]
        if not shown:
            continue
        header = r.doc.source
        if r.doc.title and r.doc.title != r.doc.source:
            header += "  (%s)" % r.doc.title
        out.append(header)
        if r.doc.url:
            out.append("  " + r.doc.url)
        for f in shown:
            loc = ("L%d" % f.line) if f.line else "-"
            out.append("  %-7s %-6s %-26s %s" % (f.severity.upper(), loc, f.code, f.message))
        out.append("")

    s = summarize(reports)
    out.append("Linted %d runbook(s): %d error(s), %d warning(s), %d info. %d clean."
               % (s["documents"], s["errors"], s["warnings"], s["info"], s["clean"]))
    if any(r.doc.converted_from_html for r in reports):
        out.append("Note: line numbers for HTML/ServiceNow sources refer to the text after HTML conversion.")
    return "\n".join(out) + "\n"


def render_json(reports: List[DocumentReport], args: argparse.Namespace) -> str:
    payload = {
        "tool": "runbook-linter",
        "version": VERSION,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "required_sections": args.sections,
        "fail_on": args.fail_on,
        "summary": summarize(reports),
        "documents": [r.to_dict() for r in reports],
    }
    return json.dumps(payload, indent=2) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_sections(value: str) -> List[str]:
    keys = [v.strip().lower() for v in value.split(",") if v.strip()]
    unknown = [k for k in keys if k not in SECTION_SPECS]
    if unknown or not keys:
        raise argparse.ArgumentTypeError(
            "unknown section(s) %s; choose from %s"
            % (", ".join(unknown) or "(none)", ", ".join(SECTION_SPECS)))
    return list(dict.fromkeys(keys))


def parse_extensions(value: str) -> Tuple[str, ...]:
    exts = tuple("." + e.strip().lower().lstrip(".") for e in value.split(",") if e.strip())
    if not exts:
        raise argparse.ArgumentTypeError("at least one extension is required")
    return exts


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="runbook-linter",
        description="Lint ITIL/ServiceNow runbooks for missing or hollow rollback, "
                    "validation and escalation sections.",
        epilog="Exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage/config error, "
               "3 ServiceNow error. ServiceNow credentials come from SN_TOKEN or "
               "SN_USER/SN_PASSWORD environment variables.",
    )
    src = p.add_argument_group("local sources")
    src.add_argument("--path", action="append", default=[], metavar="PATH",
                     help="Runbook file or directory (recursive). Repeatable. Use '-' for stdin.")
    src.add_argument("--ext", type=parse_extensions, default=DEFAULT_EXTENSIONS, metavar="LIST",
                     help="Comma-separated extensions to include when scanning directories "
                          "(default: %s)." % ",".join(e.lstrip(".") for e in DEFAULT_EXTENSIONS))

    sn = p.add_argument_group("ServiceNow source")
    sn.add_argument("--servicenow", action="store_true",
                    help="Also fetch runbooks from ServiceNow via the Table API.")
    sn.add_argument("--sn-instance", metavar="URL",
                    help="Instance base URL (default: $SN_INSTANCE).")
    sn.add_argument("--sn-user", metavar="USER",
                    help="Basic-auth user (default: $SN_USER). Password is read from $SN_PASSWORD only.")
    sn.add_argument("--sn-table", default="kb_knowledge", metavar="TABLE",
                    help="Table holding runbooks (default: %(default)s).")
    sn.add_argument("--sn-query", default="workflow_state=published", metavar="ENCODED_QUERY",
                    help="Encoded query selecting runbooks (default: %(default)s).")
    sn.add_argument("--sn-body-field", default="text", metavar="FIELD",
                    help="Field holding the HTML body (default: %(default)s).")
    sn.add_argument("--sn-title-field", default="short_description", metavar="FIELD",
                    help="Field holding the title (default: %(default)s).")
    sn.add_argument("--sn-limit", type=int, default=200, metavar="N",
                    help="Maximum records to fetch (default: %(default)s).")
    sn.add_argument("--sn-timeout", type=float, default=30.0, metavar="SECONDS",
                    help="HTTP timeout per request (default: %(default)s).")

    rules = p.add_argument_group("rules")
    rules.add_argument("--sections", type=parse_sections, default=list(SECTION_SPECS),
                       metavar="LIST",
                       help="Comma-separated sections to require (default: %s)."
                            % ",".join(SECTION_SPECS))
    rules.add_argument("--min-words", type=int, default=5, metavar="N",
                       help="Words a section needs before it counts as non-empty (default: %(default)s).")
    rules.add_argument("--fail-on", choices=["error", "warning", "info", "never"], default="error",
                       help="Lowest severity that causes exit code 1 (default: %(default)s).")

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="Emit a JSON report instead of text.")
    out.add_argument("--output", metavar="FILE", help="Write the report to FILE instead of stdout.")
    out.add_argument("--min-severity", choices=["error", "warning", "info"], default="info",
                     help="Hide text findings below this severity (JSON always has all). "
                          "Default: %(default)s.")
    p.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    return p


def collect_documents(args: argparse.Namespace) -> List[Document]:
    docs: List[Document] = []
    if args.path:
        docs.extend(iter_local_documents(args.path, args.ext))
    if args.servicenow:
        docs.extend(iter_servicenow_documents(build_servicenow_config(args)))
    return docs


def exit_code_for(reports: Iterable[DocumentReport], fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    threshold = SEVERITY_RANK[fail_on]
    hit = any(SEVERITY_RANK[f.severity] >= threshold for r in reports for f in r.findings)
    return EXIT_FINDINGS if hit else EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.path and not args.servicenow:
        parser.error("nothing to lint: give at least one --path and/or --servicenow")
    if args.min_words < 0:
        parser.error("--min-words must be >= 0")

    try:
        docs = collect_documents(args)
    except UsageError as exc:
        sys.stderr.write("runbook-linter: error: %s\n" % exc)
        return EXIT_USAGE
    except RuntimeFailure as exc:
        sys.stderr.write("runbook-linter: error: %s\n" % exc)
        return EXIT_RUNTIME

    if not docs:
        sys.stderr.write("runbook-linter: error: no runbooks found to lint.\n")
        return EXIT_USAGE

    reports = [lint_document(d, args.sections, args.min_words) for d in docs]
    rendered = render_json(reports, args) if args.json else render_text(reports, args.min_severity)

    if args.output:
        try:
            Path(args.output).expanduser().write_text(rendered, encoding="utf-8")
        except OSError as exc:
            sys.stderr.write("runbook-linter: error: cannot write %s: %s\n"
                             % (args.output, exc.strerror or exc))
            return EXIT_USAGE
        sys.stderr.write("runbook-linter: report written to %s\n" % args.output)
    else:
        sys.stdout.write(rendered)

    return exit_code_for(reports, args.fail_on)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("runbook-linter: interrupted\n")
        sys.exit(130)
