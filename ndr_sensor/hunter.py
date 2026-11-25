import os
import re
import json
import csv
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field


class HuntMatch(BaseModel):
    timestamp: str
    source: str
    event_type: str
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    target_or_query: str
    category: Optional[str] = None
    severity: str = "low"
    details: Dict[str, Any] = Field(default_factory=dict)


class HuntReport(BaseModel):
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    query_filter: Optional[str] = None
    ip_filter: Optional[str] = None
    sources_searched: List[str] = Field(default_factory=list)
    total_scanned_lines: int = 0
    total_matches: int = 0
    top_queries: Dict[str, int] = Field(default_factory=dict)
    top_sources: Dict[str, int] = Field(default_factory=dict)
    top_devices: Dict[str, int] = Field(default_factory=dict)
    matches: List[HuntMatch] = Field(default_factory=list)

    def save_json(self, target_path: str) -> None:
        path = Path(target_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def save_csv(self, target_path: str) -> None:
        path = Path(target_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "timestamp",
            "source",
            "event_type",
            "src_ip",
            "src_port",
            "dest_ip",
            "dest_port",
            "proto",
            "target_or_query",
            "category",
            "severity",
            "details",
        ]
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for m in self.matches:
                row = {
                    "timestamp": m.timestamp,
                    "source": m.source,
                    "event_type": m.event_type,
                    "src_ip": m.src_ip or "",
                    "src_port": m.src_port or "",
                    "dest_ip": m.dest_ip or "",
                    "dest_port": m.dest_port or "",
                    "proto": m.proto or "",
                    "target_or_query": m.target_or_query,
                    "category": m.category or "",
                    "severity": m.severity,
                    "details": json.dumps(m.details),
                }
                writer.writerow(row)

    def save_markdown(self, target_path: str) -> None:
        path = Path(target_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# NDR Investigation & Log Hunt Report",
            "",
            f"- **Generated At:** {self.generated_at}",
            f"- **Target IP Filter:** `{self.ip_filter or 'All'}`",
            f"- **Keyword/Query Filter:** `{self.query_filter or 'All'}`",
            f"- **Scanned Lines:** {self.total_scanned_lines:,}",
            f"- **Total Matches:** {self.total_matches:,}",
            "",
            "## Summary of Findings",
            "",
        ]

        if self.top_queries:
            lines.extend([
                "### Top Targets & Queries",
                "",
                "| Target / Query | Hits |",
                "| :--- | :--- |",
            ])
            for target, count in list(self.top_queries.items())[:15]:
                escaped_target = target.replace("|", "\\|")
                lines.append(f"| `{escaped_target}` | {count} |")
            lines.append("")

        if self.top_devices:
            lines.extend([
                "### Top Associated Devices",
                "",
                "| IP Address | Event Count |",
                "| :--- | :--- |",
            ])
            for ip, count in list(self.top_devices.items())[:10]:
                lines.append(f"| `{ip}` | {count} |")
            lines.append("")

        if self.top_sources:
            lines.extend([
                "### Matches by Log Source",
                "",
                "| Source | Matches |",
                "| :--- | :--- |",
            ])
            for src, count in self.top_sources.items():
                lines.append(f"| `{src}` | {count} |")
            lines.append("")

        lines.extend([
            "## Event Log Timeline",
            "",
            "| Timestamp | Source | Type | Source IP | Destination | Target / Query / Signature | Severity |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])

        for m in self.matches[:250]:
            src_str = f"{m.src_ip}:{m.src_port}" if m.src_port else (m.src_ip or "-")
            dest_str = f"{m.dest_ip}:{m.dest_port}" if m.dest_port else (m.dest_ip or "-")
            escaped_val = m.target_or_query.replace("|", "\\|")
            lines.append(
                f"| {m.timestamp} | {m.source} | {m.event_type} | `{src_str}` | `{dest_str}` | `{escaped_val}` | {m.severity.upper()} |"
            )

        if len(self.matches) > 250:
            lines.append(f"\n*Showing first 250 of {len(self.matches)} total events.*")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


class LogHunter:
    """Investigative log searcher across Zeek and Suricata telemetry."""

    def __init__(
        self,
        suricata_path: Optional[str] = None,
        zeek_dir: Optional[str] = None
    ):
        self.suricata_path = Path(suricata_path) if suricata_path else Path("/var/log/suricata/eve.json")
        self.zeek_dir = Path(zeek_dir) if zeek_dir else Path("/var/log/zeek/current")

    def _normalize_timestamp(self, ts_val: Any) -> str:
        if isinstance(ts_val, (int, float)):
            try:
                return datetime.fromtimestamp(ts_val, tz=timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                pass
        if isinstance(ts_val, str):
            if "T" in ts_val or "-" in ts_val:
                return ts_val.strip()
            try:
                epoch = float(ts_val)
                return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                pass
        return datetime.now(timezone.utc).isoformat()

    def _matches_ip(self, target_ip: Optional[str], src: Optional[str], dest: Optional[str]) -> bool:
        if not target_ip:
            return True
        target = target_ip.strip().lower()
        if src and target == src.strip().lower():
            return True
        if dest and target == dest.strip().lower():
            return True
        return False

    def _matches_query(
        self,
        query: Optional[str],
        candidate_strings: List[Optional[str]],
        case_sensitive: bool = False,
        use_regex: bool = False
    ) -> bool:
        if not query:
            return True

        valid_candidates = [s for s in candidate_strings if s is not None]
        if not valid_candidates:
            return False

        if use_regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                pattern = re.compile(query, flags)
                return any(pattern.search(str(c)) for c in valid_candidates)
            except re.error:
                pass

        if not case_sensitive:
            needle = query.lower()
            return any(needle in str(c).lower() for c in valid_candidates)
        return any(query in str(c) for c in valid_candidates)

    def _parse_zeek_line(self, line: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                return None
        return None

    def _parse_suricata_line(self, line: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line or not (line.startswith("{") and line.endswith("}")):
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def hunt(
        self,
        query: Optional[str] = None,
        ip: Optional[str] = None,
        sources: Optional[List[str]] = None,
        limit: int = 500,
        case_sensitive: bool = False,
        use_regex: bool = False
    ) -> HuntReport:
        if sources is None or not sources or "all" in sources:
            active_sources = {"dns", "http", "ssl", "alert", "conn", "notice"}
        else:
            active_sources = {s.lower().strip() for s in sources}

        report = HuntReport(
            query_filter=query,
            ip_filter=ip,
        )

        all_matches: List[HuntMatch] = []
        total_scanned = 0
        sources_searched: Set[str] = set()

        query_counter: Counter = Counter()
        source_counter: Counter = Counter()
        device_counter: Counter = Counter()

        # 1. Search Zeek Logs
        if self.zeek_dir.exists() and self.zeek_dir.is_dir():
            zeek_files_map = {
                "dns": "dns.log",
                "http": "http.log",
                "ssl": "ssl.log",
                "notice": "notice.log",
                "conn": "conn.log",
            }

            for stype, fname in zeek_files_map.items():
                if stype not in active_sources:
                    continue

                log_path = self.zeek_dir / fname
                if not log_path.exists():
                    continue

                sources_searched.add(f"zeek:{fname}")
                try:
                    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            total_scanned += 1
                            record = self._parse_zeek_line(line)
                            if not record:
                                continue

                            src_ip = record.get("id.orig_h") or record.get("orig_h")
                            dest_ip = record.get("id.resp_h") or record.get("resp_h")

                            if not self._matches_ip(ip, src_ip, dest_ip):
                                continue

                            match = self._evaluate_zeek_record(
                                stype, record, query, case_sensitive, use_regex
                            )
                            if match:
                                all_matches.append(match)
                                query_counter[match.target_or_query] += 1
                                source_counter[match.source] += 1
                                if match.src_ip:
                                    device_counter[match.src_ip] += 1
                                if limit > 0 and len(all_matches) >= limit:
                                    break
                except Exception:
                    pass

                if limit > 0 and len(all_matches) >= limit:
                    break

        # 2. Search Suricata Logs
        if (limit <= 0 or len(all_matches) < limit) and self.suricata_path.exists():
            sources_searched.add(f"suricata:{self.suricata_path.name}")
            try:
                with open(self.suricata_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        total_scanned += 1
                        record = self._parse_suricata_line(line)
                        if not record:
                            continue

                        src_ip = record.get("src_ip")
                        dest_ip = record.get("dest_ip")

                        if not self._matches_ip(ip, src_ip, dest_ip):
                            continue

                        match = self._evaluate_suricata_record(
                            record, active_sources, query, case_sensitive, use_regex
                        )
                        if match:
                            all_matches.append(match)
                            query_counter[match.target_or_query] += 1
                            source_counter[match.source] += 1
                            if match.src_ip:
                                device_counter[match.src_ip] += 1
                            if limit > 0 and len(all_matches) >= limit:
                                break
            except Exception:
                pass

        all_matches.sort(key=lambda m: m.timestamp)

        report.sources_searched = sorted(list(sources_searched))
        report.total_scanned_lines = total_scanned
        report.total_matches = len(all_matches)
        report.top_queries = dict(query_counter.most_common(20))
        report.top_sources = dict(source_counter)
        report.top_devices = dict(device_counter.most_common(10))
        report.matches = all_matches

        return report

    def _evaluate_zeek_record(
        self,
        stype: str,
        rec: Dict[str, Any],
        query: Optional[str],
        case_sensitive: bool,
        use_regex: bool
    ) -> Optional[HuntMatch]:
        ts = self._normalize_timestamp(rec.get("ts"))
        src_ip = rec.get("id.orig_h") or rec.get("orig_h")
        dest_ip = rec.get("id.resp_h") or rec.get("resp_h")
        src_port = rec.get("id.orig_p") or rec.get("orig_p")
        dest_port = rec.get("id.resp_p") or rec.get("resp_p")
        proto = str(rec.get("proto", "tcp")).lower()

        target = ""
        category = ""
        severity = "low"
        candidates = []

        if stype == "dns":
            target = str(rec.get("query") or "")
            qtype = str(rec.get("qtype_name") or "DNS")
            answers = rec.get("answers", [])
            answers_str = ", ".join(answers) if isinstance(answers, list) else str(answers)
            category = f"DNS Query ({qtype})"
            candidates = [target, answers_str]
        elif stype == "http":
            host = str(rec.get("host") or "")
            uri = str(rec.get("uri") or "/")
            method = str(rec.get("method") or "GET")
            target = f"{method} {host}{uri}"
            category = "HTTP Request"
            candidates = [host, uri, target, str(rec.get("user_agent") or "")]
        elif stype == "ssl":
            target = str(rec.get("server_name") or rec.get("subject") or "")
            category = "TLS Handshake"
            candidates = [target, str(rec.get("issuer") or "")]
        elif stype == "notice":
            note = str(rec.get("note") or "")
            msg = str(rec.get("msg") or "")
            sub = str(rec.get("sub") or "")
            target = f"{note}: {msg}"
            category = "Zeek Notice"
            severity = "high" if any(w in (target + sub).lower() for w in ["attack", "scan", "violation"]) else "medium"
            candidates = [note, msg, sub, target]
        elif stype == "conn":
            service = str(rec.get("service") or proto)
            target = f"{dest_ip}:{dest_port} ({service})"
            category = "Connection"
            candidates = [target, service]

        if not target:
            target = f"{dest_ip}:{dest_port}" if dest_ip else "unknown"

        if not self._matches_query(query, candidates, case_sensitive, use_regex):
            return None

        return HuntMatch(
            timestamp=ts,
            source=f"zeek-{stype}",
            event_type=stype,
            src_ip=src_ip,
            src_port=src_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            proto=proto,
            target_or_query=target,
            category=category,
            severity=severity,
            details=rec,
        )

    def _evaluate_suricata_record(
        self,
        rec: Dict[str, Any],
        active_sources: Set[str],
        query: Optional[str],
        case_sensitive: bool,
        use_regex: bool
    ) -> Optional[HuntMatch]:
        raw_type = str(rec.get("event_type", "")).lower()
        if not raw_type:
            return None

        mapped_type = raw_type
        if raw_type == "tls":
            mapped_type = "ssl"
        elif raw_type == "flow":
            mapped_type = "conn"

        if mapped_type not in active_sources:
            return None

        ts = self._normalize_timestamp(rec.get("timestamp"))
        src_ip = rec.get("src_ip")
        dest_ip = rec.get("dest_ip")
        src_port = rec.get("src_port")
        dest_port = rec.get("dest_port")
        proto = str(rec.get("proto", "tcp")).lower()

        target = ""
        category = ""
        severity = "low"
        candidates = []

        if raw_type == "alert":
            alert = rec.get("alert", {})
            sig = str(alert.get("signature", "Suricata Alert"))
            target = sig
            raw_sev = alert.get("severity", 3)
            severity = "critical" if raw_sev == 1 else "high" if raw_sev == 2 else "medium"
            category = str(alert.get("category", "Security Alert"))
            candidates = [sig, category, str(alert.get("signature_id", ""))]
        elif raw_type == "dns":
            dns_data = rec.get("dns", {})
            rrname = str(dns_data.get("rrname") or "")
            rrtype = str(dns_data.get("rrtype") or "DNS")
            target = rrname
            category = f"DNS Query ({rrtype})"
            candidates = [rrname, str(dns_data.get("rdata") or "")]
        elif raw_type == "http":
            http_data = rec.get("http", {})
            host = str(http_data.get("hostname") or "")
            url = str(http_data.get("url") or "/")
            method = str(http_data.get("http_method") or "GET")
            target = f"{method} {host}{url}"
            category = "HTTP Request"
            candidates = [host, url, target, str(http_data.get("http_user_agent") or "")]
        elif raw_type in ("tls", "ssl"):
            tls_data = rec.get("tls", {})
            sni = str(tls_data.get("sni") or tls_data.get("subject") or "")
            target = sni
            category = "TLS Handshake"
            candidates = [sni, str(tls_data.get("issuerdn") or "")]
        elif raw_type in ("flow", "conn"):
            target = f"{dest_ip}:{dest_port}"
            category = "Network Flow"
            candidates = [target]

        if not target:
            target = f"{dest_ip}:{dest_port}" if dest_ip else "unknown"

        if not self._matches_query(query, candidates, case_sensitive, use_regex):
            return None

        return HuntMatch(
            timestamp=ts,
            source=f"suricata-{raw_type}",
            event_type=mapped_type,
            src_ip=src_ip,
            src_port=src_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            proto=proto,
            target_or_query=target,
            category=category,
            severity=severity,
            details=rec,
        )
