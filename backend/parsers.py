# parsers.py
# =============================================================================
# LOG PARSERS  (MVP Feature 2: "CSV / JSON / Apache log upload")
#
# PURPOSE:
#   A real security tool must accept logs in the formats servers actually
#   produce. This file converts THREE different file formats into ONE common
#   internal shape (our normalized schema), so the detection engine never has
#   to care where the data came from.
#
# THE NORMALIZED SCHEMA (matches the LogEntry table in models.py):
#   event_time    - when it happened            (datetime)
#   source_ip     - who did it                  (str)
#   username      - which account/resource      (str or None)
#   event_type    - login_failed / login_success / connection
#   status        - extra detail                (str or None)
#   port          - port touched                (int or None)
#   country       - login country               (str or None)
#   password_sig  - password fingerprint        (str or None, synthetic data only)
#
# DESIGN NOTE (worth explaining in the report):
#   Apache/Nginx access logs do not contain usernames for failed logins, and
#   they contain no port or country fields. So when we parse them we map the
#   REQUESTED PATH into the `username` field, because for a web server the
#   "thing being attacked" is the URL (e.g. repeated 401s on /admin). This is
#   the same correlation key a real SIEM would use for web brute-force attempts.
# =============================================================================

import csv
import io
import json
import re
from datetime import datetime


# -----------------------------------------------------------------------------
# Helper: turn an empty string into None (so the database stores NULL, not "")
# -----------------------------------------------------------------------------
def _clean(value):
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


# -----------------------------------------------------------------------------
# Helper: convert many possible time formats into a real datetime object
# -----------------------------------------------------------------------------
def _parse_time(value):
    text = str(value).strip()

    # Try the standard ISO format first, e.g. "2026-07-26 09:30:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass

    # Then try a few common alternatives.
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",        # 2026-07-26T09:30:00
        "%Y-%m-%d %H:%M:%S",        # 2026-07-26 09:30:00
        "%d/%b/%Y:%H:%M:%S %z",     # Apache: 26/Jul/2026:09:30:00 +0000
        "%d/%m/%Y %H:%M:%S",        # 26/07/2026 09:30:00
    ):
        try:
            parsed = datetime.strptime(text, fmt)
            # Our database column has no timezone, so drop it if present.
            return parsed.replace(tzinfo=None)
        except ValueError:
            continue

    # Nothing matched - the caller will skip this row.
    raise ValueError(f"Unrecognised timestamp: {text}")


# =============================================================================
# 1. CSV PARSER
# =============================================================================
def parse_csv(text: str):
    """
    Parse a CSV export whose header row uses our schema column names.

    Returns (rows, skipped) where rows is a list of dictionaries.
    """
    reader = csv.DictReader(io.StringIO(text))

    # Sanity check: we need at least these three columns to do anything useful.
    required = {"event_time", "source_ip", "event_type"}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
        raise ValueError(
            "CSV must contain at least these columns: event_time, source_ip, event_type"
        )

    rows, skipped = [], 0
    for row in reader:
        try:
            rows.append({
                "event_time": _parse_time(row["event_time"]),
                "source_ip": row["source_ip"].strip(),
                "username": _clean(row.get("username")),
                "event_type": row["event_type"].strip(),
                "status": _clean(row.get("status")),
                "port": int(row["port"]) if _clean(row.get("port")) else None,
                "country": _clean(row.get("country")),
                "password_sig": _clean(row.get("password_sig")),
            })
        except Exception:
            skipped += 1   # one bad line must never break the whole upload
    return rows, skipped


# =============================================================================
# 2. JSON PARSER
# =============================================================================
def parse_json(text: str):
    """
    Parse a JSON log file. We support the two shapes real tools produce:

      (a) a JSON array:      [ {...}, {...} ]
      (b) JSON Lines / NDJSON: one JSON object per line
    """
    text = text.strip()
    records = []

    # Shape (a): the whole file is one JSON array (or a single object).
    if text.startswith("["):
        records = json.loads(text)
    elif text.startswith("{") and "\n" not in text.strip():
        records = [json.loads(text)]
    else:
        # Shape (b): JSON Lines - parse each non-empty line separately.
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass   # ignore malformed lines

    if not records:
        raise ValueError("No valid JSON records found in the file")

    rows, skipped = [], 0
    for rec in records:
        try:
            # Accept a few common alternative field names, so the parser is
            # tolerant of logs exported from different systems.
            time_value = rec.get("event_time") or rec.get("timestamp") or rec.get("time")
            ip_value = rec.get("source_ip") or rec.get("ip") or rec.get("client_ip")

            rows.append({
                "event_time": _parse_time(time_value),
                "source_ip": str(ip_value).strip(),
                "username": _clean(rec.get("username") or rec.get("user")),
                "event_type": str(rec.get("event_type") or rec.get("event")).strip(),
                "status": _clean(rec.get("status")),
                "port": int(rec["port"]) if _clean(rec.get("port")) else None,
                "country": _clean(rec.get("country")),
                "password_sig": _clean(rec.get("password_sig")),
            })
        except Exception:
            skipped += 1
    return rows, skipped


# =============================================================================
# 3. APACHE / NGINX ACCESS LOG PARSER
# =============================================================================
# A line in Combined Log Format looks like this:
#
#   192.168.1.20 - admin [26/Jul/2026:09:30:00 +0000] "POST /login HTTP/1.1" 401 512 "-" "curl/8.0"
#   |__________|   |___|  |____________________|       |___||_____|          |_|
#      client      user          timestamp             method  path         status
#
# The regex below captures each of those pieces.
# -----------------------------------------------------------------------------
APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'                 # client IP
    r'(?P<ident>\S+)\s+'               # identd (almost always "-")
    r'(?P<user>\S+)\s+'                # HTTP auth user, or "-"
    r'\[(?P<time>[^\]]+)\]\s+'         # [timestamp]
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+'   # "METHOD /path HTTP/1.1"
    r'(?P<status>\d{3})'               # HTTP status code
)


def parse_apache(text: str):
    """
    Parse an Apache/Nginx access log (Common or Combined Log Format).

    HOW WE MAP WEB REQUESTS TO SECURITY EVENTS:
      status 401 / 403  -> "login_failed"    (authentication was rejected)
      status 200 on an auth-looking path -> "login_success"
      everything else   -> "connection"      (ordinary traffic / scanning)
    """
    rows, skipped = [], 0

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        match = APACHE_PATTERN.match(line)
        if not match:
            skipped += 1
            continue

        try:
            status_code = int(match.group("status"))
            path = match.group("path")
            auth_user = match.group("user")

            # Decide what kind of security event this HTTP request represents.
            if status_code in (401, 403):
                event_type = "login_failed"
            elif status_code == 200 and any(
                k in path.lower() for k in ("login", "signin", "auth", "admin")
            ):
                event_type = "login_success"
            else:
                event_type = "connection"

            # See the design note at the top: for web logs the correlation key
            # is the authenticated user if known, otherwise the requested path.
            username = auth_user if auth_user not in ("-", "") else path

            rows.append({
                "event_time": _parse_time(match.group("time")),
                "source_ip": match.group("ip"),
                "username": username,
                "event_type": event_type,
                "status": f"HTTP {status_code}",
                "port": None,      # not present in access logs
                "country": None,   # would require IP geolocation (future work)
                "password_sig": None,
            })
        except Exception:
            skipped += 1

    if not rows:
        raise ValueError("No valid Apache/Nginx log lines were found in the file")
    return rows, skipped


# =============================================================================
# FORMAT DISPATCHER - picks the right parser based on the filename
# =============================================================================
def parse_log_file(filename: str, text: str):
    """
    Choose a parser from the file extension and run it.

    Returns (rows, skipped, format_name).
    """
    name = filename.lower()

    if name.endswith(".csv"):
        rows, skipped = parse_csv(text)
        return rows, skipped, "CSV"

    if name.endswith(".json") or name.endswith(".jsonl") or name.endswith(".ndjson"):
        rows, skipped = parse_json(text)
        return rows, skipped, "JSON"

    if name.endswith(".log") or name.endswith(".txt"):
        rows, skipped = parse_apache(text)
        return rows, skipped, "Apache/Nginx access log"

    raise ValueError(
        "Unsupported file type. Please upload .csv, .json, .jsonl, .log or .txt"
    )