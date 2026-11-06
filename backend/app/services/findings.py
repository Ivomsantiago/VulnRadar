"""Operational records are derived from scan evidence, never global CVE counts."""

import hashlib
import json
from sqlalchemy import select
from ..db import Activity, Finding, FindingObservation, InventoryComponent, Scan, Vulnerability, now, utc_datetime
from .evidence import evidence
from .intelligence import upsert, severity_name
from .history import record_state
from .packages import package_identity

CLOSED = {"resolved", "not_applicable", "false_positive", "accepted", "mitigated"}
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def fingerprint(parts):
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


def engine_result(scan, kind):
    return scan.result.get(kind, scan.result if scan.kind == kind else {})


def can_compare(previous, current, kind):
    old, new = engine_result(previous, kind), engine_result(current, kind)
    if previous.status != "completed" or current.status != "completed" or old.get("warnings") or new.get("warnings"):
        return False
    if not old.get("engine") or old.get("engine") != new.get("engine"):
        return False
    if old.get("engine_version") != new.get("engine_version"):
        return False
    if kind == "oci":
        return bool(new.get("image")) and old.get("image") == new.get("image") and old.get("coverage") == new.get("coverage") == "complete"
    # Scope equality is necessary: missing manifests or skipped files must not look fixed.
    if kind == "sca":
        return (
            bool(new.get("inventory"))
            and {d.get("file") for d in old.get("inventory", [])} == {d.get("file") for d in new.get("inventory", [])}
            and all(d.get("query_status") == "complete" for d in new.get("inventory", []))
        )
    return bool(new.get("scope")) and old.get("scope") == new.get("scope") and bool(new.get("rules_digest")) and old.get("rules_digest") == new.get("rules_digest")


def index_scan(session, scan, legacy=False):
    if scan.indexed:
        return
    occurrences = {}
    counts = {"reopened": 0, "new": 0, "persistent": 0, "resolved": 0, "comparable": False}
    for component in scan.result.get("inventory", []):
        session.add(
            InventoryComponent(
                project_id=scan.project_id,
                scan_id=scan.id,
                ecosystem=component["ecosystem"],
                package=component["package"],
                version=component["version"],
                file=component.get("file", ""),
                direct=component.get("direct"),
                query_status=component.get("query_status", "unknown"),
            )
        )
    for kind in [scan.kind] if scan.kind != "combined" else ["sca", "sast"]:
        data = engine_result(scan, kind)
        observed = set()
        for raw in data.get("findings", []):
            if kind in {"sca", "oci"}:
                dependency = raw["dependency"]
                source = raw.get("source", "osv")
                vulnerability = upsert(session, source, raw["advisory"], context="scan")
                fixed = sorted(
                    {
                        version
                        for package in evidence(source, raw["advisory"])["packages"]
                        if package_identity(dependency["ecosystem"], package["package"]) == package_identity(dependency["ecosystem"], dependency["package"]) and package["ecosystem"] == dependency["ecosystem"]
                        for version in package["fixed"]
                    }
                )
                values = dict(
                    vulnerability_id=vulnerability.id,
                    package=dependency["package"],
                    ecosystem=dependency["ecosystem"],
                    version=dependency["version"],
                    file=dependency.get("file", ""),
                    line=None,
                    rule_id=None,
                    severity=vulnerability.severity,
                    fixed_versions=fixed,
                )
                key = fingerprint([kind, vulnerability.id, dependency["ecosystem"], dependency["package"], dependency["version"], values["file"]])
            else:
                extra = raw.get("extra", {})
                values = dict(
                    vulnerability_id=None,
                    package=None,
                    ecosystem=None,
                    version=None,
                    file=raw.get("path", ""),
                    line=raw.get("start", {}).get("line"),
                    rule_id=raw["check_id"],
                    severity={"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(extra.get("severity"), "UNKNOWN"),
                    fixed_versions=[],
                )
                identity = raw.get("code_digest")
                if identity:
                    occurrence_key = (values["rule_id"], values["file"], identity)
                    ordinal = occurrences.get(occurrence_key, 0)
                    occurrences[occurrence_key] = ordinal + 1
                    key = fingerprint([kind, *occurrence_key, ordinal])
                else:
                    key = fingerprint([kind, values["rule_id"], values["file"], values["line"]])
            finding = session.scalar(select(Finding).where(Finding.project_id == scan.project_id, Finding.kind == kind, Finding.fingerprint == key))
            if finding is None and kind == "sast" and raw.get("code_digest"):
                # Upgrade legacy identities only with matching rule, path and redacted matched line.
                def matched_line(payload):
                    line = payload.get("start", {}).get("line")
                    return next((text.partition(": ")[2] for text in payload.get("extra", {}).get("lines", "").splitlines() if text.startswith(f"{line}: ")), None)

                current_line = matched_line(raw)
                candidates = session.scalars(
                    select(Finding).where(Finding.project_id == scan.project_id, Finding.kind == kind, Finding.rule_id == values["rule_id"], Finding.file == values["file"])
                )
                matches = [candidate for candidate in candidates if candidate.id not in observed and current_line and matched_line(candidate.evidence) == current_line]
                if len(matches) == 1:
                    finding = matches[0]
                    finding.fingerprint = key
            if finding is None and kind in {"sca", "oci"}:
                finding = session.scalar(
                    select(Finding).where(
                        Finding.project_id == scan.project_id,
                        Finding.kind == kind,
                        Finding.vulnerability_id == values["vulnerability_id"],
                        Finding.package == values["package"],
                        Finding.version == values["version"],
                        Finding.file == values["file"],
                    )
                )
            if finding is None:
                finding = Finding(
                    project_id=scan.project_id,
                    scan_id=scan.id,
                    kind=kind,
                    fingerprint=key,
                    evidence=raw,
                    first_seen=scan.created_at,
                    last_seen=scan.completed_at or scan.created_at,
                    **values,
                )
                session.add(finding)
                session.flush()
                record_state(session, finding, "baseline" if legacy else "created")
                counts["new"] += 1
                if not legacy:
                    session.add(
                        Activity(
                            kind="alert",
                            subject=f"finding:{finding.id}",
                            data={"reason": "Novo achado de análise", "project_id": scan.project_id, "finding_id": finding.id, "severity": finding.severity},
                        )
                    )
            else:
                finding.scan_id = scan.id
                finding.last_seen = scan.completed_at or now()
                finding.evidence = raw
                for name, value in values.items():
                    setattr(finding, name, value)
                if finding.status in {"resolved", "mitigated"} or (
                    finding.status == "accepted" and finding.risk_expires_at and utc_datetime(finding.risk_expires_at) <= now()
                ):
                    session.add(Activity(kind="finding.reopened", subject=f"finding:{finding.id}", data={"previous_status": finding.status, "scan_id": scan.id}))
                    finding.status = "new"
                    counts["reopened"] += 1
                    record_state(session, finding, "reopened")
                else:
                    record_state(session, finding, "observed")
                counts["persistent"] += 1
            if finding.id not in observed:
                session.add(FindingObservation(scan_id=scan.id, finding_id=finding.id, evidence=raw))
                observed.add(finding.id)
        previous = session.scalar(
            select(Scan)
            .where(Scan.project_id == scan.project_id, Scan.id < scan.id, Scan.kind.in_([kind, "combined"]), Scan.status.in_(["completed", "partial"]))
            .order_by(Scan.id.desc())
            .limit(1)
        )
        comparable = previous is not None and can_compare(previous, scan, kind)
        counts["comparable"] = counts["comparable"] or comparable
        if comparable:
            previous_ids = select(FindingObservation.finding_id).where(FindingObservation.scan_id == previous.id)
            for old in session.scalars(select(Finding).where(Finding.id.in_(previous_ids), Finding.kind == kind)):
                if old.id not in observed and old.status not in CLOSED:
                    old.status = "resolved"
                    record_state(session, old, "resolved")
                    counts["resolved"] += 1
                    session.add(
                        Activity(kind="finding.resolved", subject=f"finding:{old.id}", data={"scan_id": scan.id, "reason": "Ausente em análise completa de escopo comparável"})
                    )
    scan.result = {**scan.result, "comparison": counts}
    scan.indexed = True
    session.flush()


def backfill(session):
    for item in session.scalars(select(Vulnerability).where(Vulnerability.severity.in_(["MODERATE", "IMPORTANT", "NEGLIGIBLE"]))):
        item.severity = severity_name(item.severity)
    for scan in session.scalars(select(Scan).where(Scan.indexed.is_(False), Scan.status.in_(["completed", "partial"])).order_by(Scan.id)):
        index_scan(session, scan, legacy=True)
    session.commit()
