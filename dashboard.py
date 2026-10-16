#!/usr/bin/env python3
"""
dashboard.py — turns the daily ASM output folders into data for the dashboard.

  python3 dashboard.py build                  rebuild data for every scan date
  python3 dashboard.py serve [--port 8080]    rebuild, then serve on 127.0.0.1

What it reads:   output/<YYYY-MM-DD>/*.jsonl   (the same raw files asm.py and
                 discovery.py always write; Postgres is NOT needed here)
What it writes:  output/index.html             (copy of dashboard_ui.html)
                 output/data/index.json        (list of scan dates + summary)
                 output/data/<date>.json       (everything for that date)

"New since last scan" flags are worked out here by comparing each date with
the scan date before it, so the browser never has to diff anything.

Standard library only apart from common.py (which needs PyYAML, already in
the venv).
"""

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import common

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".webp")

# Ports that are rarely meant to face the internet. Shown as "risky" in the
# Open ports tab so they can be filtered to quickly. Edit freely.
RISKY_PORTS = {
    21, 22, 23, 25, 69, 111, 135, 139, 445, 512, 513, 514, 873, 1433, 1521,
    2049, 2375, 2376, 3306, 3389, 5432, 5601, 5900, 5984, 6379, 7001, 8080,
    9200, 9300, 11211, 15672, 27017,
}


# ----------------------------------------------------------------------------
# small helpers
# ----------------------------------------------------------------------------
def sev(value) -> str:
    v = str(value or "unknown").lower()
    return v if v in SEVERITIES else "unknown"


def hostname_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def dedupe(rows: list[dict], keyfn) -> list[dict]:
    """asm.py appends to the same day's files on a re-run, so the same row can
    appear twice. Keep the last copy of each."""
    seen = {}
    for r in rows:
        seen[keyfn(r)] = r
    return list(seen.values())


def trim(text, n=600) -> str:
    text = str(text or "")
    return text if len(text) <= n else text[: n - 1] + "…"


def first_ip_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return [str(value)] if value else []


def screenshot_url_from_stem(stem: str) -> str:
    """gowitness names files like https---example.com.png; turn it back into a URL."""
    return re.sub(r"^(https?)---", r"\1://", stem)


# ----------------------------------------------------------------------------
# build one day
# ----------------------------------------------------------------------------
def build_day(cfg: dict, day_dir: Path, out_root: Path) -> dict:
    scan_date = datetime.strptime(day_dir.name, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    rj = lambda name: common.read_jsonl(day_dir / name)

    # ---- DNS (also used to enrich ports and subdomains) ----
    dns_raw = dedupe(rj("dns_records.jsonl"),
                     lambda r: (r.get("host"), r.get("record_type"), r.get("value")))
    dns = [{"host": r.get("host", ""), "record_type": r.get("record_type", ""),
            "value": r.get("value", ""), "source": r.get("source", "")} for r in dns_raw]

    ip_to_hosts: dict[str, set] = {}
    host_to_ips: dict[str, set] = {}
    host_to_cname: dict[str, set] = {}
    for r in dns:
        if r["record_type"] in ("A", "AAAA"):
            ip_to_hosts.setdefault(r["value"], set()).add(r["host"])
            host_to_ips.setdefault(r["host"], set()).add(r["value"])
        elif r["record_type"] == "CNAME":
            host_to_cname.setdefault(r["host"], set()).add(r["value"])

    # ---- web assets ----
    web = []
    for r in dedupe(rj("web_assets.jsonl"), lambda r: r.get("url")):
        url = r.get("url")
        if not url:
            continue
        status = r.get("status_code")
        ip = (first_ip_list(r.get("a")) or first_ip_list(r.get("host_ip")) or [""])[0]
        web.append({
            "url": url,
            "host": hostname_of(url),
            "ip": ip,
            "status": status if isinstance(status, int) else "",
            "status_class": f"{status // 100}xx" if isinstance(status, int) else "",
            "title": trim(r.get("title"), 200),
            "tech": [str(t) for t in (r.get("tech") or r.get("technologies") or [])],
            "webserver": r.get("webserver", "") or "",
            "cdn": r.get("cdn_name") or ("yes" if r.get("cdn") else "none"),
            "length": r.get("content_length", ""),
        })
    live_hosts = {w["host"] for w in web}

    # ---- open ports ----
    ports = []
    for r in dedupe(rj("open_ports.jsonl"), lambda r: (r.get("ip"), r.get("port"))):
        ip, port = r.get("ip"), r.get("port")
        if not ip or not isinstance(port, int):
            continue
        ports.append({
            "ip": ip, "port": port, "service": r.get("service") or "",
            "hosts": ", ".join(sorted(ip_to_hosts.get(ip, []))[:3]),
            "risky": port in RISKY_PORTS,
        })

    # ---- TLS ----
    tls = []
    for r in dedupe(rj("tls_info.jsonl"), lambda r: (r.get("host"), r.get("port"))):
        if r.get("probe_status") is False or not r.get("tls_version"):
            continue
        days_left, expires = "", r.get("not_after") or ""
        try:
            dt = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            days_left = (dt - scan_date).days
        except ValueError:
            pass
        issues = []
        if r.get("expired") or (isinstance(days_left, int) and days_left < 0):
            issues.append("expired")
        elif isinstance(days_left, int) and days_left <= 30:
            issues.append("expires within 30 days")
        if r.get("self_signed"):
            issues.append("self-signed")
        if r.get("mismatched"):
            issues.append("hostname mismatch")
        tls.append({
            "host": r.get("host", ""), "port": r.get("port", ""),
            "tls_version": r.get("tls_version", ""), "issuer": r.get("issuer_cn", "") or "",
            "subject": r.get("subject_cn", "") or "", "expires": str(expires)[:10],
            "days_left": days_left, "issues": issues,
        })

    # ---- nuclei findings (vulnerabilities + takeover fingerprints) ----
    findings, takeover = [], []
    for r in dedupe(rj("findings.jsonl"),
                    lambda r: (r.get("template-id"), r.get("host"), r.get("matched-at"))):
        info = r.get("info") or {}
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = tags.split(",")
        tags = [t.strip() for t in tags if t.strip()]
        tid = r.get("template-id", "")
        kind = "takeover" if ("takeover" in tags or "takeover" in tid) else "vulnerability"
        row = {
            "severity": sev(info.get("severity")), "name": info.get("name") or tid,
            "template_id": tid, "host": r.get("host", ""),
            "matched_at": r.get("matched-at") or r.get("host", ""),
            "kind": kind, "tags": ", ".join(tags),
            "description": trim(info.get("description")),
            "evidence": "; ".join(str(x) for x in (r.get("extracted-results") or [])),
        }
        findings.append(row)
        if kind == "takeover":
            takeover.append({"kind": "takeover fingerprint", "severity": row["severity"],
                             "host": row["host"], "detail": row["name"]})

    # ---- exposures (already redacted by asm.py) ----
    exposures = []
    for r in dedupe(rj("exposures.jsonl"),
                    lambda r: (r.get("template_id"), r.get("host"), r.get("matched_at"))):
        exposures.append({
            "severity": sev(r.get("severity")), "description": r.get("description", ""),
            "template_id": r.get("template_id", ""), "source": r.get("source", ""),
            "host": r.get("host", ""), "matched_at": r.get("matched_at", ""),
            "evidence_redacted": r.get("evidence_redacted") or "",
        })

    # ---- directory fuzzing ----
    fuzz = []
    for r in dedupe(rj("dir_fuzz.jsonl"), lambda r: r.get("url")):
        if not r.get("url"):
            continue
        fuzz.append({"url": r["url"], "host": hostname_of(r["url"]),
                     "status": r.get("status_code", ""), "length": r.get("length", "")})

    # ---- dangling DNS (+ takeover fingerprints above) ----
    reasons = {"cname_target_does_not_resolve": "target does not resolve"}
    for r in dedupe(rj("dangling_dns.jsonl"), lambda r: (r.get("host"), r.get("points_to"))):
        takeover.append({
            "kind": "dangling CNAME", "severity": "medium", "host": r.get("host", ""),
            "detail": f"{r.get('record_type', 'CNAME')} to {r.get('points_to', '')} "
                      f"({reasons.get(r.get('reason'), r.get('reason', ''))})",
        })

    # ---- subdomains ----
    sub_sources: dict[str, set] = {}
    sub_domain: dict[str, str] = {}
    for r in rj("subdomains.jsonl"):
        s = r.get("subdomain")
        if s:
            sub_sources.setdefault(s, set()).add(r.get("source", ""))
            sub_domain[s] = r.get("domain", "")
    subdomains = [{
        "subdomain": s, "domain": sub_domain.get(s, ""),
        "source": ", ".join(sorted(x for x in srcs if x)),
        "ips": ", ".join(sorted(host_to_ips.get(s, []))),
        "cname": ", ".join(sorted(host_to_cname.get(s, []))),
        "live": s in live_hosts,
    } for s, srcs in sorted(sub_sources.items())]

    # ---- cloud assets ----
    cloud = []
    for r in dedupe(rj("cloud_assets.jsonl"),
                    lambda r: (r.get("provider"), r.get("asset_type"), r.get("name"))):
        d = r.get("details") or {}
        bits = []
        for key in ("ips", "ip", "endpoint", "url"):
            v = d.get(key)
            bits += [str(x) for x in v] if isinstance(v, list) else ([str(v)] if v else [])
        if d.get("reasons"):
            bits.append("public via " + ", ".join(d["reasons"]))
        cloud.append({
            "provider": r.get("provider", ""), "asset_type": r.get("asset_type", ""),
            "project": r.get("account_or_project") or "", "name": r.get("name", ""),
            "region": r.get("region") or "", "public": bool(r.get("is_public")),
            "detail": ", ".join(bits),
        })

    # ---- screenshots (scan the folder: it is the source of truth) ----
    shots = []
    shot_dir = Path(cfg["paths"]["screenshot_dir"]) / day_dir.name
    web_by_url = {w["url"].rstrip("/"): w for w in web}
    root_resolved = out_root.resolve()
    if shot_dir.is_dir():
        for img in sorted(shot_dir.iterdir()):
            if img.suffix.lower() not in IMAGE_EXTS:
                continue
            resolved = img.resolve()
            if root_resolved not in resolved.parents:
                continue  # outside the served folder, the browser couldn't load it anyway
            url = screenshot_url_from_stem(img.stem)
            match = web_by_url.get(url.rstrip("/"), {})
            shots.append({
                "url": url, "file": Path(os.path.relpath(resolved, root_resolved)).as_posix(),
                "status": match.get("status", ""), "title": match.get("title", ""),
            })

    return {
        "findings": findings, "exposures": exposures, "takeover": takeover,
        "ports": ports, "tls": tls, "fuzz": fuzz, "web": web,
        "subdomains": subdomains, "dns": dns, "cloud": cloud, "screenshots": shots,
    }


# ----------------------------------------------------------------------------
# "new since last scan" keys, one per table
# ----------------------------------------------------------------------------
KEYS = {
    "findings":    lambda r: (r["template_id"], r["host"], r["matched_at"]),
    "exposures":   lambda r: (r["template_id"], r["host"], r["matched_at"]),
    "takeover":    lambda r: (r["kind"], r["host"], r["detail"]),
    "ports":       lambda r: (r["ip"], r["port"]),
    "tls":         lambda r: (r["host"], r["port"]),
    "fuzz":        lambda r: r["url"],
    "web":         lambda r: r["url"],
    "subdomains":  lambda r: r["subdomain"],
    "dns":         lambda r: (r["host"], r["record_type"], r["value"]),
    "cloud":       lambda r: (r["provider"], r["asset_type"], r["name"]),
    "screenshots": lambda r: r["url"],
}


def build_all(cfg: dict) -> None:
    out_root = Path(cfg["paths"]["output_dir"])
    data_dir = out_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    days = sorted(p for p in out_root.iterdir() if p.is_dir() and DATE_RE.match(p.name))
    if not days:
        print(f"No scan folders (YYYY-MM-DD) found in {out_root}. Run discovery.py and asm.py first.")
        sys.exit(1)

    index_rows, prev_keys, prev_date = [], None, None
    for day in days:
        tables = build_day(cfg, day, out_root)
        has_baseline = prev_keys is not None

        new_counts, cur_keys = {}, {}
        for name, rows in tables.items():
            keys = {KEYS[name](r) for r in rows}
            cur_keys[name] = keys
            for r in rows:
                r["new"] = bool(has_baseline and KEYS[name](r) not in prev_keys[name])
            new_counts[name] = sum(1 for r in rows if r["new"])

        counts = {name: len(rows) for name, rows in tables.items()}
        counts["high_plus"] = sum(
            1 for r in tables["findings"] + tables["exposures"]
            if r["severity"] in ("critical", "high"))

        payload = {
            "date": day.name, "previous_date": prev_date, "has_baseline": has_baseline,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "counts": counts, "new_counts": new_counts, "tables": tables,
        }
        (data_dir / f"{day.name}.json").write_text(json.dumps(payload, separators=(",", ":")))
        index_rows.append({"date": day.name, "high_plus": counts["high_plus"],
                           "new": sum(new_counts.values())})
        prev_keys, prev_date = cur_keys, day.name
        print(f"built {day.name}: {sum(counts[k] for k in tables)} rows, "
              f"{sum(new_counts.values())} new")

    index_rows.sort(key=lambda d: d["date"], reverse=True)
    (data_dir / "index.json").write_text(json.dumps({"dates": index_rows}, separators=(",", ":")))

    template = Path(__file__).resolve().parent / "dashboard_ui.html"
    if template.exists():
        shutil.copyfile(template, out_root / "index.html")
    else:
        print(f"WARNING: {template} not found, so no index.html was written.")
    print(f"done. Open index.html through the server: python3 dashboard.py serve")


# ----------------------------------------------------------------------------
# serve
# ----------------------------------------------------------------------------
class QuietHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, fmt, *args):
        pass


def serve(cfg: dict, host: str, port: int) -> None:
    out_root = Path(cfg["paths"]["output_dir"])
    handler = partial(QuietHandler, directory=str(out_root))
    with ThreadingHTTPServer((host, port), handler) as httpd:
        print(f"\nDashboard: http://{host}:{port}/")
        if host in ("127.0.0.1", "localhost"):
            print("Listening on this VM only. From your laptop, open a tunnel:")
            print(f"  gcloud compute ssh gbl-security-workflow -- -L {port}:localhost:{port}")
            print(f"then browse to http://localhost:{port}/")
        else:
            print("WARNING: this page has no login. Only bind a non-local address "
                  "behind a VPN or firewall rule you control.")
        print("Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="ASM dashboard builder / server")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("build", help="rebuild dashboard data for every scan date")
    sp = sub.add_parser("serve", help="rebuild, then serve the dashboard")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    cfg = common.load_config()
    build_all(cfg)
    if args.cmd == "serve":
        serve(cfg, args.host, args.port)


if __name__ == "__main__":
    main()
