#!/usr/bin/env python3
"""
discovery.py — Stage 1 of the ASM pipeline: find everything.

Scope: subdomain enumeration, DNS resolution, CDN detection, GCP asset
inventory (gcloud + jq), AWS asset inventory (boto3: S3 + Route53 only, per
scope), public GCS/S3 bucket exposure.

Output of this stage feeds asm.py (Stage 2), which does the actual
port scanning / fuzzing / vuln scanning / screenshots.

Run manually:   python3 discovery.py
Run via cron:   see cronjob.sh (always run `pdtm -ua` and
                 `nuclei -update-templates` before this, cronjob.sh does it)
"""

import json
import os
import shlex
import sys
from pathlib import Path

import boto3

import common


def discover_subdomains(cfg, logger, out_dir: Path) -> list[dict]:
    """subfinder (+ chaos if available) across every configured root domain."""
    rows = []
    raw_path = out_dir / "subfinder_raw.jsonl"

    for domain in cfg["domains"]:
        result = common.run_cmd(
            [
                "subfinder", "-d", domain, "-silent", "-json",
                "-t", str(cfg["tuning"]["subfinder_threads"]),
            ],
            logger, timeout=900,
        )
        if result and result.stdout:
            with open(raw_path, "a") as f:
                f.write(result.stdout)
            for line in result.stdout.splitlines():
                try:
                    obj = json.loads(line)
                    rows.append({"domain": domain, "subdomain": obj.get("host"), "source": "subfinder"})
                except json.JSONDecodeError:
                    continue

        if cfg.get("chaos", {}).get("enabled") and os.environ.get("CHAOS_KEY"):
            result = common.run_cmd(["chaos", "-d", domain, "-silent", "-json"], logger, timeout=600)
            if result and result.stdout:
                with open(raw_path, "a") as f:
                    f.write(result.stdout)
                for line in result.stdout.splitlines():
                    try:
                        obj = json.loads(line)
                        sub = obj.get("subdomain") or obj.get("host")
                        if sub:
                            rows.append({"domain": domain, "subdomain": sub, "source": "chaos"})
                    except json.JSONDecodeError:
                        continue
        elif cfg.get("chaos", {}).get("enabled"):
            logger.info("CHAOS_KEY not set, skipping chaos for %s", domain)

    logger.info("subfinder/chaos found %d raw subdomain records", len(rows))
    return rows


def permute_with_alterx(cfg, logger, out_dir: Path, known_subs: list[str]) -> list[str]:
    """alterx generates likely-but-unseen hostnames from the ones we already found
    (e.g. dev-api.gameberrylabs.com from api.gameberrylabs.com). dnsx below decides
    which of these actually exist."""
    if not known_subs:
        return []
    input_path = out_dir / "alterx_input.txt"
    output_path = out_dir / "alterx_candidates.txt"
    common.write_lines(input_path, known_subs)

    result = common.run_cmd(
        ["alterx", "-l", str(input_path), "-o", str(output_path)],
        logger, timeout=300,
    )
    candidates = common.read_lines(output_path)
    logger.info("alterx generated %d candidate hostnames", len(candidates))
    return candidates


def resolve_with_dnsx(cfg, logger, out_dir: Path, hosts: list[str]) -> list[dict]:
    """Resolve every hostname and capture A/AAAA/CNAME records. This both
    tells us what's actually alive and gives us data for the dangling-DNS check."""
    if not hosts:
        return []
    input_path = out_dir / "dnsx_input.txt"
    common.write_lines(input_path, sorted(set(hosts)))

    cmd = [
        "dnsx", "-l", str(input_path), "-a", "-aaaa", "-cname", "-resp",
        "-json", "-silent", "-t", str(cfg["tuning"]["dnsx_threads"]),
        "-retry", str(cfg["tuning"].get("dnsx_retries", 2)),
    ]
    # Optional explicit resolvers. Set tuning.dnsx_resolvers to a comma-
    # separated list (e.g. "1.1.1.1,8.8.8.8") to force fast public resolvers;
    # the VM's default resolver was slow enough (~350ms/lookup) to time the
    # whole run out, so this matters on locked-down networks.
    resolvers = cfg["tuning"].get("dnsx_resolvers", "")
    if resolvers:
        cmd += ["-r", resolvers]
    # dnsx must have time to finish every host. A slow resolver over hundreds
    # of hosts easily exceeds 15 min, which killed it mid-run before.
    result = common.run_cmd(cmd, logger, timeout=cfg["tuning"].get("dnsx_timeout", 2400))
    records = []
    if result and result.stdout:
        (out_dir / "dnsx_raw.jsonl").write_text(result.stdout)
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = obj.get("host") or obj.get("input")
            if not host:
                continue
            # dnsx output shape varies by version. Older builds put records in
            # flat arrays (a/aaaa/cname); newer ones nest them under "all" or
            # emit a per-type "resolver"/"status" object. Pull from whichever
            # keys are present so resolution never silently yields 0 rows.
            for rtype, key in (("A", "a"), ("AAAA", "aaaa"), ("CNAME", "cname")):
                for value in (obj.get(key) or []):
                    records.append({"host": host, "record_type": rtype,
                                    "value": str(value), "source": "dnsx"})
            # fallback: some versions emit {"all": ["1.2.3.4", "cname.target"]}
            if not any(obj.get(k) for k in ("a", "aaaa", "cname")):
                for value in (obj.get("all") or []):
                    v = str(value)
                    # crude but safe: dotted-quad or colon => IP, else treat as CNAME
                    rtype = "A" if v.replace(".", "").isdigit() else ("AAAA" if ":" in v else "CNAME")
                    records.append({"host": host, "record_type": rtype, "value": v, "source": "dnsx"})
    logger.info("dnsx resolved %d DNS records from %d hosts", len(records), len(hosts))
    if hosts and not records:
        logger.error("dnsx produced ZERO records for %d hosts — likely a resolver problem or an "
                      "unrecognized output format. Check 'dnsx_raw.jsonl' and consider setting "
                      "dnsx_resolvers in config.yaml.", len(hosts))
    return records


def check_cdn(cfg, logger, out_dir: Path, hosts: list[str]) -> dict:
    """cdncheck flags hosts sitting behind a CDN/WAF — useful context for
    both asm.py (don't bother port-scanning Cloudflare's IP) and for triage."""
    if not hosts:
        return {}
    input_path = out_dir / "cdncheck_input.txt"
    common.write_lines(input_path, sorted(set(hosts)))

    result = common.run_cmd(
        ["cdncheck", "-l", str(input_path), "-resp", "-json", "-silent"],
        logger, timeout=300,
    )
    cdn_map = {}
    if result and result.stdout:
        (out_dir / "cdncheck_raw.jsonl").write_text(result.stdout)
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
                cdn_map[obj.get("input")] = obj.get("cdn_name") or obj.get("waf_name")
            except json.JSONDecodeError:
                continue
    return cdn_map


def probe_alive_hosts(cfg, logger, out_dir: Path, hosts: list[str]) -> list[dict]:
    """A quick httpx pass just to find which resolved hosts actually serve HTTP(S).
    asm.py runs a second, heavier httpx pass with tech-detect etc. on this list."""
    if not hosts:
        return []
    input_path = out_dir / "httpx_discovery_input.txt"
    common.write_lines(input_path, sorted(set(hosts)))

    result = common.run_cmd(
        [
            "httpx", "-l", str(input_path), "-silent", "-json",
            "-status-code", "-ip", "-timeout", str(cfg["tuning"]["request_timeout"]),
            "-t", str(cfg["tuning"]["httpx_threads"]),
        ],
        logger, timeout=900,
    )
    live = []
    if result and result.stdout:
        (out_dir / "httpx_discovery_raw.jsonl").write_text(result.stdout)
        for line in result.stdout.splitlines():
            try:
                live.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    logger.info("httpx found %d live web hosts", len(live))
    return live


def _get_gcp_projects(cfg, logger) -> list[str]:
    projects = cfg["gcp"]["projects"]
    if projects:
        return projects
    result = common.run_cmd(
        ["gcloud", "projects", "list", "--format=value(projectId)", "--quiet"], logger,
    )
    return result.stdout.split() if result and result.stdout else []


def _run_gcloud_jq(cfg, logger, out_dir: Path, label: str, project: str,
                    gcloud_args: list[str], jq_filter: str) -> list[dict]:
    """One gcloud list command piped through one jq filter, for one project.
    Each matching jq_filter must emit one compact JSON object per line
    (`jq -c '.[] | select(...) | {...}'`) — that's what gets parsed below."""
    # --quiet: never prompt interactively (e.g. "enable this API? y/N") — in
    # an unattended cron run there's no one to answer, so fail fast and let
    # the pipeline log it and move on instead of hanging.
    gcloud_cmd = ("gcloud " + " ".join(shlex.quote(a) for a in gcloud_args)
                  + f" --project {shlex.quote(project)} --format=json --quiet")
    full_cmd = f"{gcloud_cmd} | jq -c '{jq_filter}'"

    result = common.run_shell(full_cmd, logger, timeout=300)
    rows = []
    if result and result.stdout:
        raw_path = out_dir / f"gcp_{label}_raw.jsonl"
        with open(raw_path, "a") as f:
            f.write(result.stdout)
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("could not parse %s output line for project %s", label, project)
    return rows


def discover_gcp_assets(cfg, logger, out_dir: Path) -> list[dict]:
    """GCP asset inventory via gcloud + jq (cloudlist had config issues in
    this environment, so we talk to gcloud directly instead). Covers the
    externally-reachable asset types:
      - Compute Engine instances with an external/NAT IP
      - Load-balancer forwarding rules with EXTERNAL scheme
      - Cloud SQL instances with a public IP enabled
      - GKE clusters with a public (non-private) control-plane endpoint
      - Cloud Run services (always internet-reachable by URL unless
        ingress is locked down, which is itself worth knowing)

    Add more resource types later by following the same three-line pattern:
    gcloud list command -> jq filter -> dict with provider/asset_type/name/...
    """
    if not common.tool_available("gcloud"):
        logger.error("gcloud not found on PATH, skipping GCP asset discovery")
        return []
    if not common.tool_available("jq"):
        logger.error("jq not found on PATH, skipping GCP asset discovery")
        return []

    projects = _get_gcp_projects(cfg, logger)
    if not projects:
        logger.warning("no GCP projects to scan (empty gcp.projects and `gcloud projects list` returned nothing)")
        return []

    assets = []

    for project in projects:
        # 1. Compute Engine instances with an external IP
        for r in _run_gcloud_jq(
            cfg, logger, out_dir, "compute_instances", project,
            ["compute", "instances", "list"],
            '.[] | select([.networkInterfaces[]?.accessConfigs[]?.natIP | select(. != null)] | length > 0) | '
            '{name: .name, zone: (.zone | split("/") | last), '
            'ips: [.networkInterfaces[]?.accessConfigs[]?.natIP | select(. != null)]}',
        ):
            assets.append({
                "provider": "gcp", "asset_type": "compute_instance",
                "account_or_project": project, "name": r.get("name"),
                "region": r.get("zone"), "is_public": True,
                "details": {"ips": r.get("ips", [])},
            })

        # 2. External load-balancer forwarding rules
        for r in _run_gcloud_jq(
            cfg, logger, out_dir, "forwarding_rules", project,
            ["compute", "forwarding-rules", "list"],
            '.[] | select(.loadBalancingScheme == "EXTERNAL") | '
            '{name: .name, ip: .IPAddress, region: (.region // "global")}',
        ):
            assets.append({
                "provider": "gcp", "asset_type": "load_balancer",
                "account_or_project": project, "name": r.get("name"),
                "region": r.get("region"), "is_public": True,
                "details": {"ip": r.get("ip")},
            })

        # 3. Cloud SQL instances reachable on a public IP
        for r in _run_gcloud_jq(
            cfg, logger, out_dir, "cloudsql", project,
            ["sql", "instances", "list"],
            '.[] | select(.settings.ipConfiguration.ipv4Enabled == true) | '
            '{name: .name, region: .region, '
            'ip: ([.ipAddresses[]? | select(.type == "PRIMARY") | .ipAddress][0])}',
        ):
            assets.append({
                "provider": "gcp", "asset_type": "cloud_sql",
                "account_or_project": project, "name": r.get("name"),
                "region": r.get("region"), "is_public": True,
                "details": {"ip": r.get("ip")},
            })

        # 4. GKE clusters with a public control-plane endpoint
        for r in _run_gcloud_jq(
            cfg, logger, out_dir, "gke_clusters", project,
            ["container", "clusters", "list"],
            '.[] | select(.privateClusterConfig.enablePrivateEndpoint != true) | '
            '{name: .name, location: .location, endpoint: .endpoint}',
        ):
            assets.append({
                "provider": "gcp", "asset_type": "gke_cluster",
                "account_or_project": project, "name": r.get("name"),
                "region": r.get("location"), "is_public": True,
                "details": {"endpoint": r.get("endpoint")},
            })

        # 5. Cloud Run services
        for r in _run_gcloud_jq(
            cfg, logger, out_dir, "cloud_run", project,
            ["run", "services", "list", "--platform=managed"],
            '.[] | {name: .metadata.name, url: .status.url, '
            'region: .metadata.labels["cloud.googleapis.com/location"]}',
        ):
            assets.append({
                "provider": "gcp", "asset_type": "cloud_run",
                "account_or_project": project, "name": r.get("name"),
                "region": r.get("region"), "is_public": True,
                "details": {"url": r.get("url")},
            })

    logger.info("gcloud+jq discovered %d GCP assets across %d projects", len(assets), len(projects))
    return assets


def extract_ips_and_hosts(cloud_assets: list[dict]) -> tuple[list[str], list[str]]:
    """Pull raw IPs and hostnames out of the GCP asset details so they feed
    straight into naabu/httpx alongside whatever DNS enumeration found —
    a compute instance or load balancer with an external IP is in scope for
    port scanning even if no DNS record points at it yet."""
    ips, hosts = set(), set()
    for a in cloud_assets:
        details = a.get("details", {}) or {}
        for ip in details.get("ips", []) or []:
            if ip:
                ips.add(ip)
        for key in ("ip", "endpoint"):
            val = details.get(key)
            if val:
                ips.add(val)
        url = details.get("url")
        if url:
            hosts.add(url.replace("https://", "").replace("http://", "").rstrip("/"))
    return sorted(ips), sorted(hosts)


def check_gcs_public_buckets(cfg, logger, out_dir: Path) -> list[dict]:
    """List every GCS bucket in each configured project and flag public ones
    (allUsers / allAuthenticatedUsers in IAM, or public access prevention off)."""
    findings = []
    projects = _get_gcp_projects(cfg, logger)

    for project in projects:
        result = common.run_cmd(
            ["gcloud", "storage", "buckets", "list", "--project", project,
             "--format=value(name)", "--quiet"],
            logger,
        )
        buckets = result.stdout.split() if result and result.stdout else []
        for bucket in buckets:
            iam_result = common.run_cmd(["gsutil", "iam", "get", f"gs://{bucket}"], logger)
            is_public = False
            if iam_result and iam_result.stdout:
                try:
                    policy = json.loads(iam_result.stdout)
                    for binding in policy.get("bindings", []):
                        members = binding.get("members", [])
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            is_public = True
                except json.JSONDecodeError:
                    pass
            findings.append({
                "provider": "gcp", "asset_type": "gcs_bucket", "account_or_project": project,
                "name": bucket, "region": None, "is_public": is_public,
                "details": {"iam_checked": iam_result is not None},
            })

    logger.info("checked %d GCS buckets, %d public",
                len(findings), sum(1 for f in findings if f["is_public"]))
    return findings


def check_s3_public_buckets(cfg, logger, out_dir: Path) -> list[dict]:
    """List every S3 bucket in the AWS account and flag ones that are
    publicly accessible via policy, ACL, or lack of a public-access block."""
    findings = []
    try:
        session = boto3.Session(profile_name=cfg["aws"].get("profile") or None)
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        logger.error("could not list S3 buckets (check AWS creds): %s", e)
        return findings

    for b in buckets:
        name = b["Name"]
        is_public = False
        reason = []
        try:
            status = s3.get_bucket_policy_status(Bucket=name)
            if status["PolicyStatus"]["IsPublic"]:
                is_public = True
                reason.append("bucket_policy")
        except Exception:
            pass
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    is_public = True
                    reason.append("acl")
        except Exception:
            pass
        try:
            region = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        except Exception:
            region = None

        findings.append({
            "provider": "aws", "asset_type": "s3_bucket", "account_or_project": "default",
            "name": name, "region": region, "is_public": is_public,
            "details": {"reasons": reason},
        })

    logger.info("checked %d S3 buckets, %d public",
                len(findings), sum(1 for f in findings if f["is_public"]))
    return findings


def dump_route53(cfg, logger, out_dir: Path) -> list[dict]:
    """Pull every hosted zone and record set. This both surfaces subdomains
    that subfinder/chaos might miss and gives asm.py raw material for the
    dangling-DNS / subdomain-takeover check."""
    records = []
    try:
        session = boto3.Session(profile_name=cfg["aws"].get("profile") or None)
        route53 = session.client("route53")
        zones = route53.list_hosted_zones().get("HostedZones", [])
    except Exception as e:
        logger.error("could not list Route53 zones (check AWS creds): %s", e)
        return records

    for zone in zones:
        zone_id = zone["Id"]
        paginator = route53.get_paginator("list_resource_record_sets")
        for page in paginator.paginate(HostedZoneId=zone_id):
            for rs in page.get("ResourceRecordSets", []):
                rtype = rs["Type"]
                name = rs["Name"].rstrip(".")
                if "AliasTarget" in rs:
                    records.append({"host": name, "record_type": rtype,
                                     "value": rs["AliasTarget"]["DNSName"].rstrip("."), "source": "route53"})
                else:
                    for rr in rs.get("ResourceRecords", []):
                        records.append({"host": name, "record_type": rtype,
                                         "value": rr["Value"], "source": "route53"})

    logger.info("route53 returned %d records across %d zones", len(records), len(zones))
    return records


def main():
    cfg = common.load_config()
    logger = common.setup_logging(cfg, "discovery")
    out_dir = common.run_dir(cfg)
    logger.info("=== discovery run starting, output dir: %s ===", out_dir)

    common.init_db(cfg, logger)
    run_id = common.start_run(cfg, logger, "discovery")

    # 1. Subdomains
    sub_rows = discover_subdomains(cfg, logger, out_dir)
    known_subs = sorted({r["subdomain"] for r in sub_rows if r["subdomain"]})

    # 2. Permutations of what we found
    candidates = permute_with_alterx(cfg, logger, out_dir, known_subs)
    all_hostnames = sorted(set(known_subs) | set(candidates))

    # 3. Resolve everything
    dns_rows = resolve_with_dnsx(cfg, logger, out_dir, all_hostnames)
    resolved_hosts = sorted({r["host"] for r in dns_rows})

    # 4. Cloud asset inventory (GCP, via gcloud + jq) — done before the
    #    liveness probe so Cloud Run URLs etc. get included in it too.
    cloud_rows = discover_gcp_assets(cfg, logger, out_dir)
    gcp_ips, gcp_hosts = extract_ips_and_hosts(cloud_rows)
    resolved_hosts = sorted(set(resolved_hosts) | set(gcp_hosts))

    # 5. CDN/WAF context
    cdn_map = check_cdn(cfg, logger, out_dir, resolved_hosts)

    # 6. Which resolved hosts actually speak HTTP(S)
    live_hosts = probe_alive_hosts(cfg, logger, out_dir, resolved_hosts)

    # 7. Public bucket checks (explicitly in scope, separate from the gcloud asset list above)
    gcs_public = check_gcs_public_buckets(cfg, logger, out_dir)
    if cfg["aws"].get("s3_enabled", True):
        s3_public = check_s3_public_buckets(cfg, logger, out_dir)
    else:
        logger.info("S3 check disabled (aws.s3_enabled: false), skipping")
        s3_public = []

    # 8. Route53 zone dump
    if cfg["aws"].get("route53_enabled", True):
        route53_rows = dump_route53(cfg, logger, out_dir)
    else:
        logger.info("Route53 dump disabled (aws.route53_enabled: false), skipping")
        route53_rows = []
    dns_rows.extend(route53_rows)

    # ---- persist raw JSONL (always, regardless of DB health) ----
    common.append_jsonl(out_dir / "subdomains.jsonl", sub_rows)
    common.append_jsonl(out_dir / "dns_records.jsonl", dns_rows)
    common.append_jsonl(out_dir / "live_hosts_discovery.jsonl", live_hosts)
    common.append_jsonl(out_dir / "cloud_assets.jsonl", cloud_rows + gcs_public + s3_public)

    # ---- persist to Postgres ----
    if run_id:
        common.upsert_rows(cfg, logger, "subdomains",
            [{"run_id": run_id, "domain": r["domain"], "subdomain": r["subdomain"], "source": r["source"]}
             for r in sub_rows if r["subdomain"]],
            ["subdomain", "run_id"])

        common.upsert_rows(cfg, logger, "dns_records",
            [{"run_id": run_id, "host": r["host"], "record_type": r["record_type"],
              "value": r["value"], "source": r["source"]} for r in dns_rows],
            ["host", "record_type", "value", "run_id"])

        common.upsert_rows(cfg, logger, "cloud_assets",
            [{"run_id": run_id, "provider": r.get("provider", "unknown"),
              "asset_type": r.get("asset_type", "unknown"),
              "account_or_project": r.get("account_or_project"),
              "name": r.get("name", json.dumps(r)[:200]),
              "region": r.get("region"), "is_public": r.get("is_public", False),
              "details": r.get("details", r)} for r in (cloud_rows + gcs_public + s3_public)],
            ["provider", "asset_type", "name", "run_id"])

    # ---- handoff files for asm.py ----
    # resolved_hosts already has GCP hostnames (e.g. Cloud Run URLs) folded
    # in above; ips.txt gets GCP IPs (compute instances, load balancers,
    # Cloud SQL) added too, so they get port-scanned even if no DNS record
    # points at them yet.
    common.write_lines(out_dir / "resolved_hosts.txt", resolved_hosts)
    common.write_lines(out_dir / "live_urls.txt",
                        sorted({h["url"] for h in live_hosts if h.get("url")}))
    dns_ips = {r["value"] for r in dns_rows if r["record_type"] in ("A", "AAAA")}
    # Safety net: if DNS parsing yielded few/no IPs but httpx still found live
    # hosts, pull IPs straight from the httpx results so naabu isn't starved.
    httpx_ips = set()
    for h in live_hosts:
        for ip in (h.get("a") or []):
            httpx_ips.add(str(ip))
    all_ips = dns_ips | httpx_ips | set(gcp_ips)
    common.write_lines(out_dir / "ips.txt", sorted(all_ips))
    if len(all_ips) < max(5, len(live_hosts) // 4):
        logger.warning("only %d IPs for %d live hosts — port scan may be incomplete. "
                        "Check dnsx output and consider setting tuning.dnsx_resolvers.",
                        len(all_ips), len(live_hosts))

    with open(out_dir / "cdn_map.json", "w") as f:
        json.dump(cdn_map, f, indent=2)

    common.finish_run(cfg, logger, run_id, "completed")
    logger.info("=== discovery run finished ===")
    logger.info("hand-off to asm.py: %s", out_dir)


if __name__ == "__main__":
    main()
