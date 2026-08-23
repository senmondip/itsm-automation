#!/usr/bin/env python3
"""
itil-change-record-generator

WHAT IT DOES
    Builds an ITIL-shaped Change Record (aligned with the fields used by the
    ServiceNow `change_request` table: type, risk, impact, priority, CAB
    requirement, schedule window, and implementation/backout/test plans).
    By default it only builds and prints the record locally (dry run). With
    --submit it POSTs the record to a ServiceNow instance's Table API.

WHAT IT ASSUMES
    - Python 3.9+ (uses argparse.BooleanOptionalAction).
    - Local (dry-run) mode has no dependencies beyond the standard library.
    - --submit mode requires the third-party `requests` package.
    - ServiceNow instance, credentials, default assignment group, etc. are
      never hardcoded here — they come from CLI flags or environment
      variables (see --help). You must supply them for your own environment.
    - `--assignment-group` / `--requested-by` are sent as-is (display
      values). Most ServiceNow instances resolve reference fields (like
      assignment_group, requested_by) from a unique display value, but if
      your instance does not have that behavior enabled you must pass the
      sys_id instead of a name.
    - Start/end times are accepted as ISO-8601 and converted to UTC before
      being sent to ServiceNow in `YYYY-MM-DD HH:MM:SS` (glide date/time)
      format. This assumes the target instance's date/time field is being
      compared/stored in UTC; adjust --tz-offset-hint in your own workflow
      if your instance uses a different system timezone.
    - The risk/impact -> priority matrix is a simplified, common ITIL
      convention, not a universal standard. Override by editing
      PRIORITY_MATRIX if your organization uses a different mapping.

HOW TO RUN
    # Dry run (no network calls), human-readable output:
    python3 itil_change_record_generator.py \
        --title "Patch prod DB cluster" \
        --description "Apply security patches to the primary DB cluster." \
        --start 2026-09-01T02:00:00 --end 2026-09-01T04:00:00 \
        --change-type normal --risk moderate --impact moderate \
        --assignment-group "Database Engineering" --requested-by "jsmith" \
        --implementation-plan "Apply patch via config mgmt, verify replication." \
        --backout-plan "Roll back package version, restart service." \
        --test-plan "Run smoke tests against read replica after patch." \
        --justification "Vendor-published CVE fix, required by policy."

    # Same, but emit JSON to a file:
    python3 itil_change_record_generator.py ... --json --output-file change.json

    # Actually create the record in ServiceNow:
    export SNOW_INSTANCE=your-instance.service-now.com
    export SNOW_USER=svc_change_api
    export SNOW_PASSWORD=********      # or export SNOW_TOKEN=... with --auth-mode token
    python3 itil_change_record_generator.py ... --submit

    Exit codes: 0 success, 2 validation error, 3 config/credentials error,
    4 network/API error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

PROG_VERSION = "1.0.0"

RISK_CHOICES = ("low", "moderate", "high")
IMPACT_CHOICES = ("low", "moderate", "high")
CHANGE_TYPE_CHOICES = ("standard", "normal", "emergency")
AUTH_MODE_CHOICES = ("basic", "token")

# Simplified, commonly-used ITIL risk/impact -> priority matrix.
# Override to match your organization's CAB-approved matrix if different.
PRIORITY_MATRIX = {
    ("high", "high"): "1 - Critical",
    ("high", "moderate"): "2 - High",
    ("high", "low"): "2 - High",
    ("moderate", "high"): "2 - High",
    ("moderate", "moderate"): "3 - Moderate",
    ("moderate", "low"): "3 - Moderate",
    ("low", "high"): "3 - Moderate",
    ("low", "moderate"): "4 - Low",
    ("low", "low"): "4 - Low",
}


class ValidationError(Exception):
    """Raised for user-input problems (exit code 2)."""


class ConfigError(Exception):
    """Raised for missing/invalid config or credentials (exit code 3)."""


class SubmissionError(Exception):
    """Raised for network/API failures while submitting (exit code 4)."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="itil-change-record-generator",
        description="Generate an ITIL-shaped change record for scheduled maintenance, "
        "optionally submitting it to ServiceNow's Table API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Environment variables:
              SNOW_INSTANCE                   ServiceNow instance hostname (no scheme), e.g. acme.service-now.com
              SNOW_USER / SNOW_PASSWORD       Basic auth credentials (used when --auth-mode=basic)
              SNOW_TOKEN                      Bearer token (used when --auth-mode=token)
              SNOW_DEFAULT_ASSIGNMENT_GROUP   Fallback for --assignment-group
              SNOW_DEFAULT_REQUESTED_BY       Fallback for --requested-by

            Nothing in this script is customer- or environment-specific; all of the
            above must be supplied via flags or environment variables.
            """
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {PROG_VERSION}")

    core = parser.add_argument_group("change record content")
    core.add_argument("--title", required=True, help="Short description / title of the change.")
    core.add_argument("--description", help="Full description of the change (inline text).")
    core.add_argument(
        "--description-file",
        type=Path,
        help="Path to a file containing the full description (alternative to --description).",
    )
    core.add_argument(
        "--change-type",
        choices=CHANGE_TYPE_CHOICES,
        default="normal",
        help="ITIL change type. Default: normal.",
    )
    core.add_argument("--risk", choices=RISK_CHOICES, default="moderate", help="Risk level. Default: moderate.")
    core.add_argument(
        "--impact", choices=IMPACT_CHOICES, default="moderate", help="Impact level. Default: moderate."
    )
    core.add_argument(
        "--category", default="Infrastructure", help="Change category. Default: 'Infrastructure'."
    )
    core.add_argument(
        "--justification",
        help="Business/technical justification. Required for normal and emergency changes.",
    )

    schedule = parser.add_argument_group("maintenance window")
    schedule.add_argument(
        "--start", required=True, help="Maintenance window start, ISO-8601 (e.g. 2026-09-01T02:00:00-05:00)."
    )
    schedule.add_argument(
        "--end", required=True, help="Maintenance window end, ISO-8601 (e.g. 2026-09-01T04:00:00-05:00)."
    )

    ownership = parser.add_argument_group("ownership")
    ownership.add_argument(
        "--assignment-group",
        default=os.environ.get("SNOW_DEFAULT_ASSIGNMENT_GROUP"),
        help="Team/group responsible for the change. Falls back to SNOW_DEFAULT_ASSIGNMENT_GROUP.",
    )
    ownership.add_argument(
        "--requested-by",
        default=os.environ.get("SNOW_DEFAULT_REQUESTED_BY"),
        help="Requester identity (username or sys_id). Falls back to SNOW_DEFAULT_REQUESTED_BY, "
        "then to the local OS user as a last resort.",
    )
    ownership.add_argument(
        "--cab-required",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Whether CAB approval is required. Default: derived from --change-type "
        "(standard=no, normal/emergency=yes).",
    )

    plans = parser.add_argument_group("plans (each required as inline text or a file)")
    plans.add_argument("--implementation-plan", help="Implementation plan (inline text).")
    plans.add_argument("--implementation-plan-file", type=Path, help="Implementation plan (file path).")
    plans.add_argument("--backout-plan", help="Backout/rollback plan (inline text).")
    plans.add_argument("--backout-plan-file", type=Path, help="Backout/rollback plan (file path).")
    plans.add_argument("--test-plan", help="Post-change validation/test plan (inline text).")
    plans.add_argument("--test-plan-file", type=Path, help="Post-change validation/test plan (file path).")

    output = parser.add_argument_group("output")
    output.add_argument(
        "--json", dest="output_format", action="store_const", const="json", help="Emit JSON instead of text."
    )
    output.add_argument(
        "--format",
        dest="output_format",
        choices=("text", "json"),
        default="text",
        help="Output format. Default: text. (--json is shorthand for --format json)",
    )
    output.add_argument(
        "--output-file", type=Path, help="Write output to this file instead of stdout."
    )

    submit = parser.add_argument_group("ServiceNow submission")
    submit.add_argument(
        "--submit",
        action="store_true",
        help="Actually create the change record in ServiceNow via the Table API. "
        "Without this flag, the record is only built and printed locally.",
    )
    submit.add_argument(
        "--dry-run",
        action="store_true",
        help="Build and validate the record (and, with --submit, the request payload) "
        "but never make a network call.",
    )
    submit.add_argument(
        "--instance",
        default=os.environ.get("SNOW_INSTANCE"),
        help="ServiceNow instance hostname, e.g. acme.service-now.com. Falls back to SNOW_INSTANCE.",
    )
    submit.add_argument(
        "--auth-mode",
        choices=AUTH_MODE_CHOICES,
        default="basic",
        help="Authentication mode for submission. Default: basic (SNOW_USER/SNOW_PASSWORD). "
        "'token' uses SNOW_TOKEN as a bearer token.",
    )
    submit.add_argument(
        "--timeout", type=float, default=30.0, help="HTTP timeout in seconds for submission. Default: 30."
    )
    submit.add_argument(
        "--verify-tls",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Verify TLS certificates when submitting. Default: on. Disabling this is insecure "
        "and should only be used against trusted internal test instances.",
    )

    return parser


def resolve_text_field(field_name: str, inline_value: str | None, file_path: Path | None) -> str:
    if inline_value and file_path:
        raise ValidationError(f"--{field_name} and --{field_name}-file are mutually exclusive.")
    if file_path:
        if not file_path.is_file():
            raise ValidationError(f"--{field_name}-file does not exist or is not a file: {file_path}")
        text = file_path.read_text(encoding="utf-8").strip()
    else:
        text = (inline_value or "").strip()
    if not text:
        raise ValidationError(
            f"Missing required content for '{field_name}'. Provide --{field_name} or --{field_name}-file."
        )
    return text


def parse_iso_datetime(label: str, raw: str) -> datetime:
    value = raw.strip()
    # Accept a trailing 'Z' as UTC, which datetime.fromisoformat doesn't handle before 3.11.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValidationError(f"--{label} is not a valid ISO-8601 datetime: {raw!r} ({exc})") from exc
    if dt.tzinfo is None:
        raise ValidationError(
            f"--{label} must include a UTC offset (e.g. 2026-09-01T02:00:00-05:00 or ...Z): got {raw!r}"
        )
    return dt.astimezone(timezone.utc)


def derive_cab_required(change_type: str, override: bool | None) -> bool:
    if override is not None:
        return override
    return change_type != "standard"


def compute_priority(risk: str, impact: str) -> str:
    return PRIORITY_MATRIX[(risk, impact)]


def build_record(args: argparse.Namespace) -> dict:
    errors: list[str] = []

    description = None
    try:
        description = resolve_text_field("description", args.description, args.description_file)
    except ValidationError as exc:
        errors.append(str(exc))

    implementation_plan = backout_plan = test_plan = None
    for field, inline, file_ in (
        ("implementation-plan", args.implementation_plan, args.implementation_plan_file),
        ("backout-plan", args.backout_plan, args.backout_plan_file),
        ("test-plan", args.test_plan, args.test_plan_file),
    ):
        try:
            text = resolve_text_field(field, inline, file_)
            if field == "implementation-plan":
                implementation_plan = text
            elif field == "backout-plan":
                backout_plan = text
            else:
                test_plan = text
        except ValidationError as exc:
            errors.append(str(exc))

    start_dt = end_dt = None
    try:
        start_dt = parse_iso_datetime("start", args.start)
    except ValidationError as exc:
        errors.append(str(exc))
    try:
        end_dt = parse_iso_datetime("end", args.end)
    except ValidationError as exc:
        errors.append(str(exc))
    if start_dt and end_dt and end_dt <= start_dt:
        errors.append(f"--end ({args.end}) must be after --start ({args.start}).")

    if not args.assignment_group:
        errors.append(
            "Missing assignment group. Provide --assignment-group or set SNOW_DEFAULT_ASSIGNMENT_GROUP."
        )

    requested_by = args.requested_by
    if not requested_by:
        # Last-resort fallback, not a hidden default: we tell the user we used it.
        import getpass

        requested_by = getpass.getuser()
        print(
            f"warning: --requested-by not set; using local OS user {requested_by!r}. "
            "Set --requested-by or SNOW_DEFAULT_REQUESTED_BY to override.",
            file=sys.stderr,
        )

    if args.change_type != "standard" and not (args.justification or "").strip():
        errors.append(
            f"--justification is required for change-type={args.change_type!r} "
            "(standard changes are pre-approved and may omit it)."
        )

    if errors:
        raise ValidationError("Invalid input:\n  - " + "\n  - ".join(errors))

    cab_required = derive_cab_required(args.change_type, args.cab_required)
    priority = compute_priority(args.risk, args.impact)
    generated_at = datetime.now(timezone.utc)

    return {
        "record_id": str(uuid.uuid4()),
        "state": "New",
        "type": args.change_type,
        "short_description": args.title,
        "description": description,
        "category": args.category,
        "risk": args.risk,
        "impact": args.impact,
        "priority": priority,
        "cab_required": cab_required,
        "justification": (args.justification or "").strip() or None,
        "start_date": start_dt.isoformat(),
        "end_date": end_dt.isoformat(),
        "assignment_group": args.assignment_group,
        "requested_by": requested_by,
        "implementation_plan": implementation_plan,
        "backout_plan": backout_plan,
        "test_plan": test_plan,
        "generated_at": generated_at.isoformat(),
    }


def render_text(record: dict, submission: dict | None) -> str:
    def wrap(text: str) -> str:
        return textwrap.indent(textwrap.fill(text, width=88), "    ")

    lines = [
        "=" * 88,
        f"CHANGE RECORD (draft id: {record['record_id']})",
        "=" * 88,
        f"Title:            {record['short_description']}",
        f"Type / State:     {record['type']} / {record['state']}",
        f"Category:         {record['category']}",
        f"Risk / Impact:    {record['risk']} / {record['impact']}  ->  Priority: {record['priority']}",
        f"CAB required:     {'yes' if record['cab_required'] else 'no'}",
        f"Assignment group: {record['assignment_group']}",
        f"Requested by:     {record['requested_by']}",
        f"Window (UTC):     {record['start_date']}  ->  {record['end_date']}",
        "",
        "Description:",
        wrap(record["description"]),
    ]
    if record["justification"]:
        lines += ["", "Justification:", wrap(record["justification"])]
    lines += [
        "",
        "Implementation plan:",
        wrap(record["implementation_plan"]),
        "",
        "Backout plan:",
        wrap(record["backout_plan"]),
        "",
        "Test plan:",
        wrap(record["test_plan"]),
        "",
        f"Generated at (UTC): {record['generated_at']}",
    ]
    if submission:
        lines += [
            "-" * 88,
            "ServiceNow submission result:",
            f"  number:  {submission.get('number', 'n/a')}",
            f"  sys_id:  {submission.get('sys_id', 'n/a')}",
        ]
    lines.append("=" * 88)
    return "\n".join(lines)


def build_snow_payload(record: dict) -> dict:
    """Map our internal record to ServiceNow change_request Table API fields."""

    def to_glide(iso_ts: str) -> str:
        return datetime.fromisoformat(iso_ts).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "type": record["type"],
        "short_description": record["short_description"],
        "description": record["description"],
        "category": record["category"],
        "risk": record["risk"],
        "impact": record["impact"],
        "priority": record["priority"],
        "cab_required": record["cab_required"],
        "justification": record["justification"] or "",
        "start_date": to_glide(record["start_date"]),
        "end_date": to_glide(record["end_date"]),
        "assignment_group": record["assignment_group"],
        "requested_by": record["requested_by"],
        "implementation_plan": record["implementation_plan"],
        "backout_plan": record["backout_plan"],
        "test_plan": record["test_plan"],
    }


def resolve_snow_base_url(instance: str) -> str:
    # Accept either a bare hostname or a full URL; normalize to https://<host>.
    parsed = urlparse(instance if "://" in instance else f"https://{instance}")
    if not parsed.netloc:
        raise ConfigError(f"--instance / SNOW_INSTANCE is not a valid hostname or URL: {instance!r}")
    return f"https://{parsed.netloc}"


def submit_to_servicenow(record: dict, args: argparse.Namespace) -> dict:
    try:
        import requests
    except ImportError as exc:
        raise ConfigError(
            "The 'requests' package is required for --submit but is not installed. "
            "Install it with: pip install requests"
        ) from exc

    if not args.instance:
        raise ConfigError("ServiceNow instance not set. Provide --instance or set SNOW_INSTANCE.")
    base_url = resolve_snow_base_url(args.instance)
    url = f"{base_url}/api/now/table/change_request"

    session = requests.Session()
    if args.auth_mode == "basic":
        user = os.environ.get("SNOW_USER")
        password = os.environ.get("SNOW_PASSWORD")
        if not user or not password:
            raise ConfigError(
                "--auth-mode=basic requires SNOW_USER and SNOW_PASSWORD environment variables to be set."
            )
        session.auth = (user, password)
    else:
        token = os.environ.get("SNOW_TOKEN")
        if not token:
            raise ConfigError("--auth-mode=token requires the SNOW_TOKEN environment variable to be set.")
        session.headers["Authorization"] = f"Bearer {token}"

    session.headers["Accept"] = "application/json"
    session.headers["Content-Type"] = "application/json"

    payload = build_snow_payload(record)

    if args.dry_run:
        print("dry-run: skipping network call. Payload that would be sent:", file=sys.stderr)
        print(json.dumps(payload, indent=2), file=sys.stderr)
        return {"number": "DRY-RUN", "sys_id": "DRY-RUN"}

    try:
        response = session.post(url, json=payload, timeout=args.timeout, verify=args.verify_tls)
    except requests.exceptions.SSLError as exc:
        raise SubmissionError(f"TLS verification failed connecting to {url}: {exc}") from exc
    except requests.exceptions.ConnectionError as exc:
        raise SubmissionError(f"Could not connect to {url}: {exc}") from exc
    except requests.exceptions.Timeout as exc:
        raise SubmissionError(f"Request to {url} timed out after {args.timeout}s: {exc}") from exc

    if response.status_code == 401:
        raise ConfigError("ServiceNow rejected the credentials (401 Unauthorized). Check SNOW_USER/SNOW_PASSWORD or SNOW_TOKEN.")
    if response.status_code == 403:
        raise ConfigError(
            "ServiceNow denied access (403 Forbidden). The account may lack the role needed to "
            "create change_request records."
        )
    if not response.ok:
        raise SubmissionError(
            f"ServiceNow API returned {response.status_code} for {url}:\n{response.text[:2000]}"
        )

    try:
        body = response.json()
    except ValueError as exc:
        raise SubmissionError(f"ServiceNow response was not valid JSON: {response.text[:2000]}") from exc

    result = body.get("result", {})
    if not result:
        raise SubmissionError(f"ServiceNow response missing 'result': {body}")
    return {"number": result.get("number", "n/a"), "sys_id": result.get("sys_id", "n/a")}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        record = build_record(args)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    submission_result: dict | None = None
    if args.submit:
        try:
            submission_result = submit_to_servicenow(record, args)
        except ConfigError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return 3
        except SubmissionError as exc:
            print(f"submission error: {exc}", file=sys.stderr)
            return 4
        if submission_result["number"] != "DRY-RUN":
            record["state"] = "Assess"
            record["servicenow_number"] = submission_result["number"]
            record["servicenow_sys_id"] = submission_result["sys_id"]

    if args.output_format == "json":
        payload = dict(record)
        if submission_result and submission_result["number"] != "DRY-RUN":
            payload["submission"] = submission_result
        rendered = json.dumps(payload, indent=2)
    else:
        rendered = render_text(
            record, submission_result if submission_result and submission_result["number"] != "DRY-RUN" else None
        )

    if args.output_file:
        args.output_file.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote change record to {args.output_file}", file=sys.stderr)
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())
