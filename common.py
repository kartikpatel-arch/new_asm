"""
common.py — shared plumbing for discovery.py and asm.py.

Keep this file boring. Anything tool-specific belongs in discovery.py or
asm.py; anything generic (run a command, read config, talk to Postgres)
belongs here. That split is what keeps the two pipeline scripts short.
"""

import json
import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

# Default: config.yaml sitting next to this file, so the scripts work from any
# directory. Set ASM_CONFIG to point somewhere else.
CONFIG_PATH = os.environ.get("ASM_CONFIG", str(Path(__file__).resolve().parent / "config.yaml"))


# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
def load_config(path: str = CONFIG_PATH) -> dict:
    with open(path, "r") as f:
        cfg = yaml.safe_load(f)

    # Fill any missing tuning keys with safe defaults, so a hand-trimmed
    # config.yaml can never crash a scan with KeyError mid-run.
    tuning_defaults = {
        "subfinder_threads": 50, "dnsx_threads": 100, "dnsx_resolvers": "",
        "dnsx_retries": 2, "dnsx_timeout": 2400, "naabu_rate": 300,
        "naabu_top_ports": 1000, "httpx_threads": 25, "ffuf_threads": 10,
        "ffuf_timeout": 10, "nuclei_rate_limit": 50,
        "nuclei_severities": "low,medium,high,critical",
        "nuclei_exclude_tags": "dos,intrusive,fuzz,bruteforce",
        "nuclei_max_targets": 1500, "nuclei_timeout": 10800,
        "exposure_tags": "exposure,token,apikey,config,env,git,backup,logs,debug,swagger,openapi,graphql,springboot,actuator",
        "exposure_severities": "info,low,medium,high,critical",
        "katana_depth": 3, "request_timeout": 10,
    }
    cfg.setdefault("tuning", {})
    for k, v in tuning_defaults.items():
        cfg["tuning"].setdefault(k, v)

    # Expand ~ and make sure the directories we write to actually exist.
    paths = cfg["paths"]
    paths["nuclei_templates"] = os.path.expanduser(paths["nuclei_templates"])
    for key in ("output_dir", "screenshot_dir", "log_dir"):
        Path(paths[key]).mkdir(parents=True, exist_ok=True)

    return cfg


# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
def setup_logging(cfg: dict, name: str) -> logging.Logger:
    log_dir = Path(cfg["paths"]["log_dir"])
    log_dir.mkdir(parents=True, exist_ok=True)
    logfile = log_dir / f"{name}.log"

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    fh = logging.FileHandler(logfile)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


# ----------------------------------------------------------------------------
# Run folders: every invocation of discovery.py / asm.py writes into
# /opt/asm/output/<YYYY-MM-DD>/ so nothing ever overwrites last week's data.
# ----------------------------------------------------------------------------
def run_dir(cfg: dict) -> Path:
    d = Path(cfg["paths"]["output_dir"]) / datetime.now().strftime("%Y-%m-%d")
    d.mkdir(parents=True, exist_ok=True)
    return d


import re as _re
_DATE_DIR = _re.compile(r"^\d{4}-\d{2}-\d{2}$")


def latest_run_dir(cfg: dict) -> Path | None:
    """The newest dated run folder that actually exists. asm.py uses this
    instead of 'today', because if discovery.py started before midnight and
    asm.py after, 'today' would point at an empty folder discovery never
    wrote to. The newest existing folder is always the one discovery just
    filled."""
    base = Path(cfg["paths"]["output_dir"])
    if not base.is_dir():
        return None
    dirs = sorted((p for p in base.iterdir() if p.is_dir() and _DATE_DIR.match(p.name)),
                  key=lambda p: p.name, reverse=True)
    # Prefer the newest folder that actually holds discovery output, so an
    # empty "today" folder (the midnight-split bug) can't shadow the real one.
    for d in dirs:
        if (d / "resolved_hosts.txt").exists() or (d / "subdomains.jsonl").exists():
            return d
    return dirs[0] if dirs else None


def latest_previous_run_dir(cfg: dict, exclude: Path) -> Path | None:
    """Most recent run folder that isn't today's — used for diffing."""
    base = Path(cfg["paths"]["output_dir"])
    candidates = sorted(
        [p for p in base.iterdir() if p.is_dir() and _DATE_DIR.match(p.name) and p != exclude],
        reverse=True,
    )
    return candidates[0] if candidates else None


# ----------------------------------------------------------------------------
# Subprocess wrapper. Every PD/ffuf/gowitness/nmap call goes through this so
# a missing binary or a bad exit code doesn't kill the whole weekly run —
# it logs the failure and the pipeline moves on to the next step.
# ----------------------------------------------------------------------------
def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_cmd(cmd: list[str], logger: logging.Logger, input_text: str | None = None,
            timeout: int = 3600) -> subprocess.CompletedProcess | None:
    binary = cmd[0]
    if not tool_available(binary):
        logger.error("tool not found on PATH, skipping step: %s", binary)
        return None

    logger.info("running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            # Most PD tools exit non-zero on "no results" too, so this is a
            # warning, not a hard stop.
            logger.warning(
                "%s exited %s. stderr: %s",
                binary, result.returncode, result.stderr.strip()[:500],
            )
        return result
    except subprocess.TimeoutExpired:
        logger.error("%s timed out after %ss", binary, timeout)
        return None
    except Exception as e:
        logger.error("%s raised %s: %s", binary, type(e).__name__, e)
        return None


def run_shell(cmd_str: str, logger: logging.Logger, timeout: int = 1800) -> subprocess.CompletedProcess | None:
    """Like run_cmd, but for a pipeline that needs an actual shell
    (e.g. `gcloud ... --format=json | jq -c '...'`). Used for the
    gcloud+jq GCP asset discovery — everything else in the pipeline uses
    run_cmd with a plain argv list, which is safer, so keep this one for
    the cases that genuinely need a pipe."""
    if not (tool_available("gcloud") and tool_available("jq")):
        logger.error("gcloud or jq not found on PATH, skipping: %s", cmd_str)
        return None

    logger.info("running shell: %s", cmd_str)
    try:
        result = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            logger.warning("shell command exited %s. stderr: %s",
                            result.returncode, result.stderr.strip()[:500])
        return result
    except subprocess.TimeoutExpired:
        logger.error("shell command timed out after %ss: %s", timeout, cmd_str)
        return None
    except Exception as e:
        logger.error("shell command raised %s: %s", type(e).__name__, e)
        return None


# ----------------------------------------------------------------------------
# JSONL helpers — every tool's raw output is kept exactly as emitted,
# one JSON object per line, so nothing is ever lossy and you can always
# `jq` your way through an old run.
# ----------------------------------------------------------------------------
def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # tolerate the odd non-JSON log line some tools emit
    return out


def append_jsonl(path: Path, rows: list[dict]) -> None:
    with open(path, "a") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def write_lines(path: Path, lines: list[str]) -> None:
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n" if lines else "")


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    with open(path, "r") as f:
        return [l.strip() for l in f if l.strip()]


# ----------------------------------------------------------------------------
# Postgres
# ----------------------------------------------------------------------------
def get_db_conn(cfg: dict):
    import psycopg2
    pg = cfg["postgres"]
    return psycopg2.connect(
        host=pg["host"], port=pg["port"], dbname=pg["dbname"],
        user=pg["user"], password=pg["password"],
    )


SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id SERIAL PRIMARY KEY,
    run_type TEXT NOT NULL,            -- 'discovery' or 'asm'
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS subdomains (
    id SERIAL PRIMARY KEY,
    run_id INT REFERENCES scan_runs(id),
    domain TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    source TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (subdomain, run_id)
);

CREATE TABLE IF NOT EXISTS dns_records (
    id SERIAL PRIMARY KEY,
    run_id INT REFERENCES scan_runs(id),
    host TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT,              -- 'dnsx' or 'route53'
    UNIQUE (host, record_type, value, run_id)
);

CREATE TABLE IF NOT EXISTS cloud_assets (
    id SERIAL PRIMARY KEY,
    run_id INT REFERENCES scan_runs(id),
    provider TEXT NOT NULL,      -- gcp | aws
    asset_type TEXT NOT NULL,    -- bucket | compute_instance | ...
    account_or_project TEXT,
    name TEXT NOT NULL,
    region TEXT,
    is_public BOOLEAN DEFAULT FALSE,
    details JSONB,
    UNIQUE (provider, asset_type, name, run_id)
);

CREATE TABLE IF NOT EXISTS live_hosts (
    id SERIAL PRIMARY KEY,
    run_id INT REFERENCES scan_runs(id),
    url TEXT NOT NULL,
    host TEXT,
    status_code INT,
    title TEXT,
    tech TEXT,
    cdn TEXT,
    webserver TEXT,
    UNIQUE (url, run_id)
);

CREATE TABLE IF NOT EXISTS open_ports (
    id SERIAL PRIMARY KEY,
    run_id INT REFERENCES scan_runs(id),
    ip TEXT NOT NULL,
    port INT NOT NULL,
    service TEXT,
    UNIQUE (ip, port, run_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    run_id INT REFERENCES scan_runs(id),
    template_id TEXT NOT NULL,
    severity TEXT,
    host TEXT NOT NULL,
    matched_at TEXT,
    description TEXT,
    raw JSONB,
    UNIQUE (template_id, host, matched_at, run_id)
);

CREATE TABLE IF NOT EXISTS dir_fuzz_results (
    id SERIAL PRIMARY KEY,
    run_id INT REFERENCES scan_runs(id),
    url TEXT NOT NULL,
    status_code INT,
    length INT,
    UNIQUE (url, run_id)
);

CREATE TABLE IF NOT EXISTS screenshots (
    id SERIAL PRIMARY KEY,
    run_id INT REFERENCES scan_runs(id),
    url TEXT NOT NULL,
    filepath TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exposures (
    id SERIAL PRIMARY KEY,
    run_id INT REFERENCES scan_runs(id),
    source TEXT NOT NULL,          -- 'nuclei' or 'ffuf-sensitive'
    template_id TEXT NOT NULL,
    severity TEXT,
    host TEXT NOT NULL,
    matched_at TEXT NOT NULL,
    description TEXT,
    evidence_redacted TEXT,        -- never the real secret, see asm.redact()
    UNIQUE (template_id, host, matched_at, run_id)
);

CREATE TABLE IF NOT EXISTS dangling_dns (
    id SERIAL PRIMARY KEY,
    run_id INT REFERENCES scan_runs(id),
    host TEXT NOT NULL,
    record_type TEXT,
    points_to TEXT,
    reason TEXT,
    UNIQUE (host, run_id)
);
"""


def init_db(cfg: dict, logger: logging.Logger) -> None:
    try:
        conn = get_db_conn(cfg)
        with conn, conn.cursor() as cur:
            cur.execute(SCHEMA)
        conn.close()
        logger.info("database schema ensured")
    except Exception as e:
        logger.error("could not init database (continuing, JSONL still saved): %s", e)


def start_run(cfg: dict, logger: logging.Logger, run_type: str) -> int | None:
    try:
        conn = get_db_conn(cfg)
        with conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scan_runs (run_type, started_at) VALUES (%s, now()) RETURNING id",
                (run_type,),
            )
            run_id = cur.fetchone()[0]
        conn.close()
        return run_id
    except Exception as e:
        logger.error("could not record scan_run start: %s", e)
        return None


def finish_run(cfg: dict, logger: logging.Logger, run_id: int | None, status: str = "completed") -> None:
    if run_id is None:
        return
    try:
        conn = get_db_conn(cfg)
        with conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE scan_runs SET finished_at = now(), status = %s WHERE id = %s",
                (status, run_id),
            )
        conn.close()
    except Exception as e:
        logger.error("could not record scan_run finish: %s", e)


def upsert_rows(cfg, logger, table: str, rows: list[dict], conflict_cols: list[str]) -> None:
    """Generic INSERT ... ON CONFLICT DO NOTHING for a list of dict rows.
    All rows in a batch must share the same keys."""
    if not rows:
        return
    try:
        conn = get_db_conn(cfg)
        cols = list(rows[0].keys())
        placeholders = ", ".join(["%s"] * len(cols))
        col_list = ", ".join(cols)
        conflict_list = ", ".join(conflict_cols)
        sql = (
            f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) "
            f"ON CONFLICT ({conflict_list}) DO NOTHING"
        )
        with conn, conn.cursor() as cur:
            for row in rows:
                values = [
                    json.dumps(row[c]) if isinstance(row[c], (dict, list)) else row[c]
                    for c in cols
                ]
                cur.execute(sql, values)
        conn.close()
        logger.info("inserted up to %d rows into %s", len(rows), table)
    except Exception as e:
        logger.error("DB insert into %s failed (JSONL still has the data): %s", table, e)


# ----------------------------------------------------------------------------
# Diffing: "what's new since last week" per table, scoped by a key column.
# ----------------------------------------------------------------------------
def diff_new_values(cfg, logger, table: str, key_col: str, current_run_id: int,
                     previous_run_id: int | None) -> list[str]:
    if current_run_id is None or previous_run_id is None:
        return []
    try:
        conn = get_db_conn(cfg)
        with conn, conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT DISTINCT {key_col} FROM {table} WHERE run_id = %s
                EXCEPT
                SELECT DISTINCT {key_col} FROM {table} WHERE run_id = %s
                """,
                (current_run_id, previous_run_id),
            )
            rows = [r[0] for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        logger.error("diff query on %s failed: %s", table, e)
        return []


# ----------------------------------------------------------------------------
# Notify (ProjectDiscovery `notify` tool)
# ----------------------------------------------------------------------------
def send_notification(cfg: dict, logger: logging.Logger, text: str) -> None:
    if not cfg.get("notify", {}).get("enabled", False):
        return
    provider_config = cfg["notify"]["provider_config"]
    if not Path(provider_config).exists():
        logger.warning("notify provider config missing at %s, skipping notification", provider_config)
        return
    run_cmd(
        ["notify", "-pc", provider_config, "-bulk"],
        logger,
        input_text=text,
        timeout=60,
    )
