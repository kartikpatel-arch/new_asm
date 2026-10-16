#!/usr/bin/env python3
"""
asm.py — Stage 2 of the ASM pipeline: scan everything discovery.py found.

Reads the hand-off files written by discovery.py in today's run folder
(resolved_hosts.txt, live_urls.txt, ips.txt, dns_records.jsonl) and runs:
  naabu (+ nmap)   -> open ports / service detection
  tlsx             -> TLS/cert info
  httpx            -> tech stack, titles, status codes (deeper than discovery's pass)
  katana           -> crawling for endpoints
  ffuf             -> directory/file fuzzing
  nuclei           -> vulnerability scanning
  dnsx + nuclei     -> dangling DNS / subdomain takeover
  gowitness        -> screenshots of every web asset

Then: persist to Postgres + JSONL, diff against last week, notify.

Must be run AFTER discovery.py on the same day (cronjob.sh guarantees this).
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import common


def load_handoff(cfg, logger, out_dir: Path):
    resolved_hosts = common.read_lines(out_dir / "resolved_hosts.txt")
    live_urls = common.read_lines(out_dir / "live_urls.txt")
    ips = common.read_lines(out_dir / "ips.txt")
    dns_records = common.read_jsonl(out_dir / "dns_records.jsonl")

    if not resolved_hosts:
        logger.warning("no resolved_hosts.txt found — did discovery.py run today? "
                        "Falling back to an empty set; this run will find nothing.")
    return resolved_hosts, live_urls, ips, dns_records


# ----------------------------------------------------------------------------
# Port scanning: naabu for discovery, nmap for service/version detail on
# whatever naabu finds open. (naabu can shell out to nmap itself via
# -nmap-cli, but running it as a separate explicit step keeps naabu's JSON
# output clean and makes failures easier to debug.)
# ----------------------------------------------------------------------------
def scan_ports(cfg, logger, out_dir: Path, ips: list[str]) -> list[dict]:
    if not ips:
        return []
    input_path = out_dir / "naabu_input.txt"
    common.write_lines(input_path, ips)

    top_ports = cfg["tuning"]["naabu_top_ports"]
    cmd = [
        "naabu", "-list", str(input_path), "-json", "-silent",
        "-rate", str(cfg["tuning"]["naabu_rate"]),
    ]
    cmd += ["-top-ports", str(top_ports)] if top_ports != "full" else ["-p", "-"]

    result = common.run_cmd(cmd, logger, timeout=1800)
    open_ports = []
    if result and result.stdout:
        (out_dir / "naabu_raw.jsonl").write_text(result.stdout)
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
                open_ports.append({"ip": obj.get("ip") or obj.get("host"), "port": obj.get("port"), "service": None})
            except json.JSONDecodeError:
                continue
    logger.info("naabu found %d open ports", len(open_ports))

    # nmap service/version detection on exactly what naabu found, grouped by IP
    by_ip: dict[str, list[int]] = {}
    for p in open_ports:
        by_ip.setdefault(p["ip"], []).append(p["port"])

    service_map = {}
    for ip, ports in by_ip.items():
        port_str = ",".join(str(p) for p in sorted(set(ports)))
        xml_out = out_dir / f"nmap_{ip.replace(':', '_')}.xml"
        common.run_cmd(
            ["nmap", "-sV", "-Pn", "-p", port_str, "-oX", str(xml_out), ip],
            logger, timeout=600,
        )
        service_map.update(parse_nmap_xml(xml_out, ip))

    for p in open_ports:
        p["service"] = service_map.get((p["ip"], p["port"]))

    return open_ports


def parse_nmap_xml(xml_path: Path, ip: str) -> dict:
    out = {}
    if not xml_path.exists():
        return out
    try:
        tree = ET.parse(xml_path)
        for port_el in tree.iter("port"):
            portid = int(port_el.get("portid"))
            service_el = port_el.find("service")
            if service_el is not None:
                name = service_el.get("name", "")
                product = service_el.get("product", "")
                version = service_el.get("version", "")
                out[(ip, portid)] = " ".join(filter(None, [name, product, version])).strip()
    except ET.ParseError as e:
        pass
    return out


# ----------------------------------------------------------------------------
# TLS info
# ----------------------------------------------------------------------------
def scan_tls(cfg, logger, out_dir: Path, hosts: list[str]) -> list[dict]:
    if not hosts:
        return []
    input_path = out_dir / "tlsx_input.txt"
    common.write_lines(input_path, hosts)

    result = common.run_cmd(
        ["tlsx", "-l", str(input_path), "-json", "-silent", "-cert-expiry", "-tls-version", "-san"],
        logger, timeout=600,
    )
    rows = []
    if result and result.stdout:
        (out_dir / "tlsx_raw.jsonl").write_text(result.stdout)
        for line in result.stdout.splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    logger.info("tlsx collected TLS info for %d hosts", len(rows))
    return rows


# ----------------------------------------------------------------------------
# Deep httpx pass: tech stack, title, status, webserver, CDN
# ----------------------------------------------------------------------------
def probe_deep(cfg, logger, out_dir: Path, urls: list[str]) -> list[dict]:
    if not urls:
        return []
    input_path = out_dir / "httpx_deep_input.txt"
    common.write_lines(input_path, urls)

    result = common.run_cmd(
        [
            "httpx", "-l", str(input_path), "-silent", "-json",
            "-title", "-tech-detect", "-status-code", "-web-server", "-cdn",
            "-follow-redirects", "-timeout", str(cfg["tuning"]["request_timeout"]),
            "-t", str(cfg["tuning"]["httpx_threads"]),
        ],
        logger, timeout=1200,
    )
    rows = []
    if result and result.stdout:
        (out_dir / "httpx_deep_raw.jsonl").write_text(result.stdout)
        for line in result.stdout.splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    logger.info("httpx (deep) probed %d web assets", len(rows))
    return rows


# ----------------------------------------------------------------------------
# Crawling
# ----------------------------------------------------------------------------
def crawl_with_katana(cfg, logger, out_dir: Path, urls: list[str]) -> list[str]:
    if not urls:
        return []
    input_path = out_dir / "katana_input.txt"
    common.write_lines(input_path, urls)

    result = common.run_cmd(
        [
            "katana", "-list", str(input_path), "-json", "-silent",
            "-depth", str(cfg["tuning"]["katana_depth"]),
        ],
        logger, timeout=1800,
    )
    crawled = []
    if result and result.stdout:
        (out_dir / "katana_raw.jsonl").write_text(result.stdout)
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
                u = (obj.get("request") or {}).get("endpoint") or obj.get("url")
                if u:
                    crawled.append(u)
            except json.JSONDecodeError:
                continue
    logger.info("katana crawled %d unique URLs", len(set(crawled)))
    return sorted(set(crawled))


# ----------------------------------------------------------------------------
# Directory / file fuzzing (ffuf — the one directory fuzzer in scope)
# ----------------------------------------------------------------------------
def fuzz_directories(cfg, logger, out_dir: Path, urls: list[str]) -> list[dict]:
    wordlist = cfg["paths"]["wordlist"]
    if not Path(wordlist).exists():
        logger.warning("wordlist missing at %s, skipping ffuf (see MANUAL_SETUP.md)", wordlist)
        return []

    rows = []
    fuzz_dir = out_dir / "ffuf"
    fuzz_dir.mkdir(exist_ok=True)

    for url in urls:
        safe_name = url.replace("://", "_").replace("/", "_")[:150]
        json_out = fuzz_dir / f"{safe_name}.json"
        target = url.rstrip("/") + "/FUZZ"
        common.run_cmd(
            [
                "ffuf", "-u", target, "-w", wordlist, "-of", "json", "-o", str(json_out),
                "-mc", "200,204,301,302,307,401,403",
                "-t", str(cfg["tuning"]["ffuf_threads"]),
                "-timeout", str(cfg["tuning"]["ffuf_timeout"]),
                "-silent",
            ],
            logger, timeout=900,
        )
        if json_out.exists():
            try:
                data = json.loads(json_out.read_text())
                for r in data.get("results", []):
                    rows.append({
                        "url": r.get("url"),
                        "status_code": r.get("status"),
                        "length": r.get("length"),
                    })
            except json.JSONDecodeError:
                logger.warning("could not parse ffuf output for %s", url)

    logger.info("ffuf found %d interesting paths across %d hosts", len(rows), len(urls))
    return rows


# ----------------------------------------------------------------------------
# Vulnerability scanning
# ----------------------------------------------------------------------------
def scan_with_nuclei(cfg, logger, out_dir: Path, urls: list[str]) -> list[dict]:
    if not urls:
        return []
    input_path = out_dir / "nuclei_input.txt"
    common.write_lines(input_path, urls)
    output_path = out_dir / "nuclei_raw.jsonl"

    # De-dupe and cap: live_urls + every crawled URL can be thousands of
    # targets, which is why nuclei never finished inside the time limit.
    # Nuclei scans a host's templates per URL, so unique hosts matter more
    # than unique paths — keep it bounded.
    seen_host, capped = set(), []
    max_targets = cfg["tuning"].get("nuclei_max_targets", 1500)
    for u in urls:
        capped.append(u)
        if len(capped) >= max_targets:
            logger.warning("nuclei target list capped at %d (had %d); raise "
                            "tuning.nuclei_max_targets if you want them all", max_targets, len(urls))
            break
    common.write_lines(input_path, capped)

    timeout = cfg["tuning"].get("nuclei_timeout", 10800)   # 3h default
    common.run_cmd(
        [
            "nuclei", "-l", str(input_path), "-jsonl", "-o", str(output_path),
            "-severity", cfg["tuning"]["nuclei_severities"],
            "-rate-limit", str(cfg["tuning"]["nuclei_rate_limit"]),
            "-silent", "-stats", "-si", "300",   # periodic progress into the log
            "-etags", cfg["tuning"].get("nuclei_exclude_tags", "dos,intrusive,fuzz,bruteforce"),
            "-templates", cfg["paths"]["nuclei_templates"],
        ],
        logger, timeout=timeout,
    )
    # Read whatever nuclei wrote, even if it was killed on timeout: -o is
    # written incrementally, so a partial file still has real findings.
    rows = [scrub_nuclei_row(r) for r in common.read_jsonl(output_path)]
    if output_path.exists():
        output_path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    logger.info("nuclei produced %d findings", len(rows))
    return rows


# ----------------------------------------------------------------------------
# Exposure pass: leaked secrets + exposed API specs (Swagger/OpenAPI/GraphQL).
# Kept separate from the main findings so info-level noise doesn't flood the
# weekly diff, and so we can redact secrets before anything is stored.
# ----------------------------------------------------------------------------
def redact(value) -> str:
    """Never store a real secret. Keep 4 leading chars + length so a human can
    still tell which key it was, and go re-check the live URL themselves."""
    s = str(value)
    return f"{s[:4]}...[redacted, {len(s)} chars]" if len(s) > 4 else "[redacted]"


def scrub_nuclei_row(f: dict) -> dict:
    """Redact leaked values and drop request/response bodies from a nuclei
    result, so neither the JSONL files nor Postgres ever hold a real secret."""
    f = dict(f)
    if f.get("extracted-results"):
        f["extracted-results"] = [redact(x) for x in f["extracted-results"]]
    for k in ("request", "response", "curl-command"):
        f.pop(k, None)
    return f


def fuzz_sensitive_paths(cfg, logger, out_dir: Path, urls: list[str]) -> list[dict]:
    """ffuf with the sensitive-file / API-spec wordlist. -ac (auto-calibrate)
    drops soft-404 and SPA catch-all pages, which otherwise answer 200 to
    everything and bury the real hits."""
    wordlist = cfg["paths"].get("sensitive_wordlist", "")
    if not Path(wordlist).exists():
        logger.warning("sensitive wordlist missing at %s, skipping (see MANUAL_SETUP.md)", wordlist)
        return []

    rows = []
    fuzz_dir = out_dir / "ffuf_sensitive"
    fuzz_dir.mkdir(exist_ok=True)

    for url in urls:
        safe_name = url.replace("://", "_").replace("/", "_")[:150]
        json_out = fuzz_dir / f"{safe_name}.json"
        common.run_cmd(
            [
                "ffuf", "-u", url.rstrip("/") + "/FUZZ", "-w", wordlist,
                "-of", "json", "-o", str(json_out),
                "-mc", "200,204", "-ac",
                "-t", str(cfg["tuning"]["ffuf_threads"]),
                "-timeout", str(cfg["tuning"]["ffuf_timeout"]),
                "-silent",
            ],
            logger, timeout=900,
        )
        if json_out.exists():
            try:
                for r in json.loads(json_out.read_text()).get("results", []):
                    rows.append({
                        "source": "ffuf-sensitive", "template_id": "sensitive-path-exposed",
                        "severity": "medium", "host": url, "matched_at": r.get("url", ""),
                        "description": f"Sensitive path returned {r.get('status')} ({r.get('length')} bytes)",
                        "evidence_redacted": None,
                    })
            except json.JSONDecodeError:
                logger.warning("could not parse sensitive ffuf output for %s", url)

    logger.info("sensitive-path ffuf found %d hits across %d hosts", len(rows), len(urls))
    return rows


def scan_exposures(cfg, logger, out_dir: Path, urls: list[str], crawled_urls: list[str]) -> list[dict]:
    """Focused nuclei run: exposure/token/config/swagger/openapi/graphql tags,
    info severity included. Also scans JavaScript files katana found, since
    hardcoded keys in frontend bundles are one of the most common leaks."""
    js_urls = sorted({u for u in crawled_urls if u.split("?")[0].lower().endswith(".js")})
    targets = sorted(set(urls) | set(js_urls))
    if not targets:
        return []

    input_path = out_dir / "exposures_input.txt"
    common.write_lines(input_path, targets)
    raw_path = out_dir / "nuclei_exposures_raw.jsonl"   # deleted after redaction below

    common.run_cmd(
        [
            "nuclei", "-l", str(input_path), "-jsonl", "-o", str(raw_path),
            "-tags", cfg["tuning"].get("exposure_tags",
                "exposure,token,apikey,config,env,git,backup,logs,debug,swagger,openapi,graphql,springboot,actuator"),
            "-severity", cfg["tuning"].get("exposure_severities", "info,low,medium,high,critical"),
            "-rate-limit", str(cfg["tuning"]["nuclei_rate_limit"]),
            "-silent",
            "-etags", cfg["tuning"].get("nuclei_exclude_tags", "dos,intrusive,fuzz,bruteforce"),
            "-templates", cfg["paths"]["nuclei_templates"],
        ],
        logger, timeout=5400,
    )

    rows = []
    for f in common.read_jsonl(raw_path):
        info = f.get("info", {}) or {}
        extracted = f.get("extracted-results") or []
        rows.append({
            "source": "nuclei",
            "template_id": f.get("template-id", "unknown"),
            "severity": info.get("severity"),
            "host": f.get("host", ""),
            "matched_at": f.get("matched-at", ""),
            "description": info.get("name", ""),
            "evidence_redacted": "; ".join(redact(x) for x in extracted) or None,
        })

    # The raw file can contain the actual leaked values. Don't keep it.
    try:
        raw_path.unlink()
    except FileNotFoundError:
        pass

    logger.info("exposure scan: %d hits (%d JS files scanned)", len(rows), len(js_urls))
    return rows


def check_subdomain_takeover(cfg, logger, out_dir: Path, hosts: list[str]) -> list[dict]:
    """Dedicated nuclei pass with just the takeover-tagged templates, which is
    more reliable than guessing fingerprints ourselves."""
    if not hosts:
        return []
    input_path = out_dir / "takeover_input.txt"
    common.write_lines(input_path, hosts)
    output_path = out_dir / "takeover_raw.jsonl"

    common.run_cmd(
        [
            "nuclei", "-l", str(input_path), "-jsonl", "-o", str(output_path),
            "-tags", "takeover", "-silent",
            "-etags", cfg["tuning"].get("nuclei_exclude_tags", "dos,intrusive,fuzz,bruteforce"),
            "-templates", cfg["paths"]["nuclei_templates"],
        ],
        logger, timeout=1200,
    )
    rows = common.read_jsonl(output_path)
    logger.info("takeover scan produced %d hits", len(rows))
    return rows


def find_dangling_dns(cfg, logger, out_dir: Path, dns_records: list[dict]) -> list[dict]:
    """Heuristic companion to the nuclei takeover templates: a CNAME that
    points somewhere that no longer resolves at all is worth a look even if
    no fingerprint matched."""
    cnames = [r for r in dns_records if r["record_type"] == "CNAME"]
    if not cnames:
        return []

    targets = sorted({r["value"] for r in cnames})
    input_path = out_dir / "dangling_check_input.txt"
    common.write_lines(input_path, targets)

    # Use the same resolver/retry/timeout settings as discovery's dnsx call,
    # so this doesn't time out on the slow default resolver and silently
    # report zero dangling records.
    cmd = ["dnsx", "-l", str(input_path), "-resp", "-json", "-silent", "-a",
           "-retry", str(cfg["tuning"].get("dnsx_retries", 2))]
    resolvers = cfg["tuning"].get("dnsx_resolvers", "")
    if resolvers:
        cmd += ["-r", resolvers]
    result = common.run_cmd(cmd, logger, timeout=cfg["tuning"].get("dnsx_timeout", 2400))
    resolves = set()
    if result and result.stdout:
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
                if obj.get("a"):
                    resolves.add(obj.get("host"))
            except json.JSONDecodeError:
                continue

    dangling = []
    for r in cnames:
        if r["value"] not in resolves:
            dangling.append({
                "host": r["host"], "record_type": "CNAME",
                "points_to": r["value"], "reason": "cname_target_does_not_resolve",
            })
    logger.info("found %d potentially dangling CNAME records", len(dangling))
    return dangling


# ----------------------------------------------------------------------------
# Screenshots
# ----------------------------------------------------------------------------
def take_screenshots(cfg, logger, out_dir: Path, urls: list[str]) -> list[dict]:
    if not urls:
        return []
    screenshot_dir = Path(cfg["paths"]["screenshot_dir"]) / out_dir.name
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    input_path = out_dir / "gowitness_input.txt"
    common.write_lines(input_path, urls)

    # gowitness v3 (cobra, subcommands). If you're on v2, swap for:
    # ["gowitness", "file", "-f", str(input_path), "-P", str(screenshot_dir)]
    common.run_cmd(
        [
            "gowitness", "scan", "file", "-f", str(input_path),
            "--screenshot-path", str(screenshot_dir),
        ],
        logger, timeout=1800,
    )

    rows = []
    # gowitness v3 saves .jpeg by default, v2 saves .png: accept both
    for img in sorted(p for p in screenshot_dir.iterdir()
                      if p.suffix.lower() in (".png", ".jpg", ".jpeg", ".webp")):
        rows.append({"url": img.stem, "filepath": str(img)})
    logger.info("gowitness produced %d screenshots", len(rows))
    return rows


# ----------------------------------------------------------------------------
# Diff + notify
# ----------------------------------------------------------------------------
def get_previous_asm_run_id(cfg, logger, current_run_id):
    try:
        conn = common.get_db_conn(cfg)
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM scan_runs
                WHERE run_type = 'asm' AND status = 'completed' AND id != %s
                ORDER BY started_at DESC LIMIT 1
                """,
                (current_run_id,),
            )
            row = cur.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        logger.error("could not fetch previous asm run: %s", e)
        return None


def build_diff_report(cfg, logger, out_dir, current_run_id, previous_run_id, company):
    if previous_run_id is None:
        return f"[{company} ASM] First completed run — nothing to diff against yet."

    new_hosts = common.diff_new_values(cfg, logger, "live_hosts", "url", current_run_id, previous_run_id)
    new_findings = common.diff_new_values(cfg, logger, "findings", "template_id || ':' || host",
                                           current_run_id, previous_run_id)
    new_ports = common.diff_new_values(cfg, logger, "open_ports", "ip || ':' || port",
                                        current_run_id, previous_run_id)

    new_exposures = common.diff_new_values(cfg, logger, "exposures", "template_id || ' @ ' || matched_at",
                                            current_run_id, previous_run_id)

    lines = [f"[{company} ASM] Weekly diff — run {current_run_id} vs {previous_run_id}"]
    lines.append(f"New live web assets: {len(new_hosts)}")
    lines.extend(f"  + {h}" for h in new_hosts[:25])
    lines.append(f"New open ports: {len(new_ports)}")
    lines.extend(f"  + {p}" for p in new_ports[:25])
    lines.append(f"New findings: {len(new_findings)}")
    lines.extend(f"  + {fnd}" for fnd in new_findings[:25])
    lines.append(f"New exposures (secrets / API specs): {len(new_exposures)}")
    lines.extend(f"  + {e}" for e in new_exposures[:25])

    report = "\n".join(lines)
    (out_dir / "diff_report.txt").write_text(report)
    return report


def main():
    cfg = common.load_config()
    logger = common.setup_logging(cfg, "asm")
    # Use the newest discovery folder, not today's date: a run that starts
    # before midnight (discovery) and finishes after (asm) would otherwise
    # split across two folders and asm would scan an empty one.
    out_dir = common.latest_run_dir(cfg)
    if out_dir is None:
        out_dir = common.run_dir(cfg)
        logger.warning("no existing run folder found; discovery.py may not have run")
    logger.info("=== asm run starting, using discovery data in: %s ===", out_dir)

    common.init_db(cfg, logger)
    run_id = common.start_run(cfg, logger, "asm")

    logger.info("asm using discovery folder: %s", out_dir.name)
    # Warn (don't stop) if the discovery data looks stale — e.g. asm.py is
    # being re-run days later without a fresh discovery.
    try:
        from datetime import datetime as _dt
        age = (_dt.utcnow().date() - _dt.strptime(out_dir.name, "%Y-%m-%d").date()).days
        if age >= 2:
            logger.warning("discovery data in %s is %d days old; consider re-running discovery.py",
                            out_dir.name, age)
    except ValueError:
        pass

    resolved_hosts, live_urls, ips, dns_records = load_handoff(cfg, logger, out_dir)

    open_ports = scan_ports(cfg, logger, out_dir, ips)
    tls_rows = scan_tls(cfg, logger, out_dir, resolved_hosts)
    web_assets = probe_deep(cfg, logger, out_dir, live_urls)
    crawled_urls = crawl_with_katana(cfg, logger, out_dir, live_urls)
    ffuf_rows = fuzz_directories(cfg, logger, out_dir, live_urls)
    nuclei_rows = scan_with_nuclei(cfg, logger, out_dir, live_urls + crawled_urls)
    exposure_rows = scan_exposures(cfg, logger, out_dir, live_urls, crawled_urls) \
        + fuzz_sensitive_paths(cfg, logger, out_dir, live_urls)
    takeover_rows = check_subdomain_takeover(cfg, logger, out_dir, resolved_hosts)
    dangling_rows = find_dangling_dns(cfg, logger, out_dir, dns_records)
    screenshot_rows = take_screenshots(cfg, logger, out_dir, live_urls)

    all_findings = nuclei_rows + takeover_rows

    # ---- raw JSONL, always ----
    common.append_jsonl(out_dir / "open_ports.jsonl", open_ports)
    common.append_jsonl(out_dir / "tls_info.jsonl", tls_rows)
    common.append_jsonl(out_dir / "web_assets.jsonl", web_assets)
    common.write_lines(out_dir / "crawled_urls.txt", crawled_urls)
    common.append_jsonl(out_dir / "dir_fuzz.jsonl", ffuf_rows)
    common.append_jsonl(out_dir / "findings.jsonl", all_findings)
    common.append_jsonl(out_dir / "exposures.jsonl", exposure_rows)   # redacted, safe to keep
    common.append_jsonl(out_dir / "dangling_dns.jsonl", dangling_rows)
    common.append_jsonl(out_dir / "screenshots.jsonl", screenshot_rows)

    # ---- Postgres ----
    if run_id:
        common.upsert_rows(cfg, logger, "open_ports",
            [{"run_id": run_id, "ip": p["ip"], "port": p["port"], "service": p["service"]}
             for p in open_ports if p.get("ip") and p.get("port")],
            ["ip", "port", "run_id"])

        common.upsert_rows(cfg, logger, "live_hosts",
            [{"run_id": run_id, "url": w.get("url", ""), "host": w.get("host"),
              "status_code": w.get("status_code"), "title": w.get("title"),
              "tech": ",".join(w.get("tech", []) or []), "cdn": w.get("cdn_name"),
              "webserver": w.get("webserver")} for w in web_assets if w.get("url")],
            ["url", "run_id"])

        common.upsert_rows(cfg, logger, "findings",
            [{"run_id": run_id, "template_id": f.get("template-id", "unknown"),
              "severity": (f.get("info", {}) or {}).get("severity"),
              "host": f.get("host", ""), "matched_at": f.get("matched-at", ""),
              "description": (f.get("info", {}) or {}).get("name", ""),
              "raw": f} for f in all_findings if f.get("host")],
            ["template_id", "host", "matched_at", "run_id"])

        common.upsert_rows(cfg, logger, "exposures",
            [{"run_id": run_id, **{k: e[k] for k in (
                "source", "template_id", "severity", "host", "matched_at",
                "description", "evidence_redacted")}}
             for e in exposure_rows if e.get("host") and e.get("matched_at")],
            ["template_id", "host", "matched_at", "run_id"])

        common.upsert_rows(cfg, logger, "dir_fuzz_results",
            [{"run_id": run_id, "url": r["url"], "status_code": r["status_code"], "length": r["length"]}
             for r in ffuf_rows if r.get("url")],
            ["url", "run_id"])

        common.upsert_rows(cfg, logger, "screenshots",
            [{"run_id": run_id, "url": s["url"], "filepath": s["filepath"]} for s in screenshot_rows],
            ["id"])  # screenshots have no natural unique key besides id; always inserted

        common.upsert_rows(cfg, logger, "dangling_dns",
            [{"run_id": run_id, "host": d["host"], "record_type": d["record_type"],
              "points_to": d["points_to"], "reason": d["reason"]} for d in dangling_rows],
            ["host", "run_id"])

    common.finish_run(cfg, logger, run_id, "completed")

    # ---- weekly diff + notify ----
    previous_run_id = get_previous_asm_run_id(cfg, logger, run_id)
    report = build_diff_report(cfg, logger, out_dir, run_id, previous_run_id, cfg["company"])
    logger.info("diff report:\n%s", report)
    common.send_notification(cfg, logger, report)

    logger.info("=== asm run finished ===")


if __name__ == "__main__":
    main()
