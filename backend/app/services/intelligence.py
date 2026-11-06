"""Connectors preserve original source evidence and explicit aliases."""

import asyncio
import random
import time
import copy
from datetime import datetime, timedelta, timezone
import httpx
from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError
from sqlalchemy import select, delete, update
from ..config import settings
from ..db import Activity, Advisory, Alias, Source, Vulnerability, AffectedPackage, Finding, SyncRun, utc_datetime
from .evidence import evidence

URLS = {
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "github": "https://api.github.com/advisories",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://api.first.org/data/v1/epss",
    "osv": "https://api.osv.dev/v1/query",
}

KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"


def github_timestamp(value):
    return utc_datetime(datetime.fromisoformat(value) if isinstance(value, str) else value).strftime("%Y-%m-%dT%H:%M:%SZ")


def github_next_page(response, seen):
    """Global advisories paginate with an opaque `after` cursor, not page=N."""
    from urllib.parse import urlsplit, parse_qs
    link = response.links.get("next")
    if not link:
        return None
    parsed = urlsplit(link["url"])
    if parsed.hostname not in (None, "api.github.com") or parsed.path not in ("", "/advisories"):
        raise ValueError("Link de paginação GitHub fora do endpoint autorizado")
    query = parse_qs(parsed.query)
    if query.get("after") and len(query["after"][0]) <= 4096:
        cursor = {"after": query["after"][0]}
    elif query.get("page") and query["page"][0].isdigit():
        cursor = {"page": int(query["page"][0])}
    else:
        raise ValueError("GitHub retornou paginação sem cursor reconhecido")
    key = tuple(cursor.items())
    if key in seen:
        raise ValueError("GitHub retornou cursor repetido; consulta incompleta")
    seen.add(key)
    return cursor


async def request(client, method, url, **kwargs):
    for attempt in range(4):
        response = await client.request(method, url, **kwargs)
        if response.status_code != 429 and response.status_code < 500:
            response.raise_for_status()
            return response
        if attempt == 3:
            response.raise_for_status()
        retry = response.headers.get("Retry-After", "")
        delay = min(float(retry), 60) if retry.isdigit() else 2**attempt + random.random()
        await asyncio.sleep(delay)
    raise RuntimeError("Retries exhausted")


async def fetch_kev(client):
    try:
        response = await request(client, "GET", URLS["kev"])
    except httpx.HTTPError:
        # Official CISA-maintained mirror; keep TLS verification on both routes.
        response = await request(client, "GET", KEV_MIRROR)
    return response.json()


def severity_name(value):
    normalized = str(value or "UNKNOWN").upper()
    normalized = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH", "NEGLIGIBLE": "LOW"}.get(normalized, normalized)
    return normalized if normalized in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "UNKNOWN"


def refresh_assessment(session, vulnerability):
    """Keep a source-owned severity/CVSS pair; unrated mirrors cannot hide known criticals."""
    ratings = []
    for advisory in session.scalars(select(Advisory).where(Advisory.vulnerability_id == vulnerability.id, Advisory.source.in_(["nvd", "github", "osv", "trivy", "grype"]))):
        if advisory.payload.get("withdrawn") or advisory.payload.get("withdrawn_at"):
            continue
        rating = normalize(advisory.source, advisory.payload)
        ratings.append((advisory.source, rating))
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    if ratings:
        source, chosen = max(ratings, key=lambda item: (rank.get(item[1]["severity"], 0), item[1].get("cvss") if item[1].get("cvss") is not None else -1))
        vulnerability.severity, vulnerability.cvss = chosen["severity"], chosen.get("cvss")
        return source
    vulnerability.severity, vulnerability.cvss = "UNKNOWN", None
    return None


def repair_unrated_assessments(session):
    # Repair the old cached combination UNKNOWN + a known numerical CVSS. Raw
    # advisories and analyst decisions remain unchanged; evidence supplies the rating.
    for vulnerability in session.scalars(select(Vulnerability).where(Vulnerability.severity == "UNKNOWN", Vulnerability.cvss.is_not(None))):
        previous = {"severity": vulnerability.severity, "cvss": vulnerability.cvss}
        source = refresh_assessment(session, vulnerability)
        if vulnerability.severity != previous["severity"]:
            session.add(Activity(kind="vulnerability.reconciled", subject=vulnerability.id, data={"source": source, "previous": previous, "current": {"severity": vulnerability.severity, "cvss": vulnerability.cvss}, "reason": "Classificação conhecida preservada a partir da evidência original"}))
    session.commit()


def normalize(source, raw):
    if source in {"osv", "trivy", "grype"}:
        scores = raw.get("severity", [])
        score, derived_severity = None, "UNKNOWN"
        for metric in sorted(scores, key=lambda value: {"CVSS_V4": 4, "CVSS_V3": 3, "CVSS_V2": 2}.get(value.get("type"), 0), reverse=True):
            parser = {"CVSS_V4": CVSS4, "CVSS_V3": CVSS3, "CVSS_V2": CVSS2}.get(metric.get("type"))
            if parser is None:
                continue
            try:
                parsed = parser(metric.get("score", ""))
                score, derived_severity = parsed.scores()[0], parsed.severities()[0].upper()
                break
            except (CVSSError, ValueError, TypeError):
                continue
        return dict(
            id=raw["id"],
            aliases=raw.get("aliases", []),
            title=raw.get("summary", raw["id"]),
            description=raw.get("details", ""),
            published=raw.get("published"),
            modified=raw.get("modified"),
            severity=severity_name(raw.get("database_specific", {}).get("severity"))
            if severity_name(raw.get("database_specific", {}).get("severity")) != "UNKNOWN"
            else severity_name(derived_severity),
            cvss=score,
            affected=raw.get("affected", []),
            references=raw.get("references", []),
            scores=scores,
        )
    if source == "github":
        cvss = raw.get("cvss") or {}
        return dict(
            id=raw["ghsa_id"],
            aliases=[i["value"] for i in raw.get("identifiers", [])],
            title=raw.get("summary", raw["ghsa_id"]),
            description=raw.get("description", ""),
            severity=severity_name(raw.get("severity")),
            cvss=cvss.get("score"),
            published=raw.get("published_at"),
            modified=raw.get("updated_at"),
            affected=raw.get("vulnerabilities", []),
            references=raw.get("references", []),
        )
    cve = raw.get("cve", raw)
    descriptions = cve.get("descriptions", [])
    text = next((x["value"] for x in descriptions if x.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    metric = next((metrics[k][0].get("cvssData", {}) for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2") if metrics.get(k)), {})
    score = metric.get("baseScore")
    severity = metric.get("baseSeverity") or (
        "CRITICAL" if score and score >= 9 else "HIGH" if score and score >= 7 else "MEDIUM" if score and score >= 4 else "LOW" if score is not None else "UNKNOWN"
    )
    return dict(
        id=cve["id"],
        aliases=[],
        title=text[:200] or cve["id"],
        description=text,
        published=cve.get("published"),
        modified=cve.get("lastModified"),
        severity=severity_name(severity),
        cvss=score,
        affected=cve.get("configurations", []),
        references=cve.get("references", []),
    )


def upsert(session, source, raw, context="collection"):
    item = normalize(source, raw)
    identifiers = sorted(set([item["id"], *item["aliases"]]))
    matches = list(session.scalars(select(Alias).where(Alias.id.in_(identifiers))))
    matches_ids = sorted({a.vulnerability_id for a in matches})
    canonical = matches_ids[0] if matches_ids else next((a for a in identifiers if a.startswith("CVE-")), item["id"])
    vulnerability = session.get(Vulnerability, canonical)
    new = vulnerability is None
    if new:
        vulnerability = Vulnerability(
            id=canonical, title=item["title"], description=item["description"], severity=item["severity"], cvss=item["cvss"], published=item["published"], modified=item["modified"]
        )
        session.add(vulnerability)
        session.flush()
    # An explicit bridging alias can join previously independent records.
    for old_id in matches_ids:
        if old_id == canonical:
            continue
        old = session.get(Vulnerability, old_id)
        for alias in session.scalars(select(Alias).where(Alias.vulnerability_id == old_id)):
            alias.vulnerability_id = canonical
        for advisory in session.scalars(select(Advisory).where(Advisory.vulnerability_id == old_id)):
            advisory.vulnerability_id = canonical
        vulnerability.kev = vulnerability.kev or old.kev
        vulnerability.epss = vulnerability.epss if vulnerability.epss is not None else old.epss
        session.execute(update(Finding).where(Finding.vulnerability_id == old_id).values(vulnerability_id=canonical))
        session.flush()
        session.delete(old)
    for identifier in identifiers:
        if session.get(Alias, identifier) is None:
            session.add(Alias(id=identifier, vulnerability_id=canonical))
    key = f"{source}:{item['id']}"
    advisory = session.get(Advisory, key)
    previous = advisory.payload if advisory else None
    changed = advisory is None or advisory.payload != raw
    if advisory is None:
        session.add(Advisory(id=key, source=source, vulnerability_id=canonical, payload=raw))
    else:
        advisory.payload = raw
    if changed:
        event_type = "advisory_update"
        reason = "Advisory atualizado pela fonte"
        if new:
            event_type = "local_discovery" if context != "collection" else "first_collection"
            reason = "Advisory identificado em análise/consulta local" if context != "collection" else "Advisory coletado pela primeira vez"
            if context == "collection" and item.get("published"):
                try:
                    published_at = utc_datetime(datetime.fromisoformat(item["published"]))
                    if datetime.now(timezone.utc) - timedelta(hours=24) <= published_at <= datetime.now(timezone.utc):
                        event_type, reason = "publication", "Nova publicação informada pela fonte"
                except (ValueError, TypeError):
                    pass
        if previous:
            old_fixes = {v for package in evidence(source, previous)["packages"] for v in package["fixed"]}
            new_fixes = {v for package in evidence(source, raw)["packages"] for v in package["fixed"]}
            if new_fixes - old_fixes:
                session.add(
                    Activity(
                        kind="alert", subject=canonical, data={"reason": "Nova versão corrigida informada pela fonte", "source": source, "versions": sorted(new_fixes - old_fixes)}
                    )
                )
        session.flush()
        session.execute(delete(AffectedPackage).where(AffectedPackage.advisory_id == key))
        if source == "nvd":
            from .products import index_products
            index_products(session, key, raw)
        for package in evidence(source, raw)["packages"]:
            session.add(AffectedPackage(advisory_id=key, ecosystem=package["ecosystem"], package=package["package"], constraints=package))
        vulnerability.updated_at = datetime.now(timezone.utc)
        vulnerability.title = item["title"]
        vulnerability.description = item["description"]
        vulnerability.modified = item["modified"]
        vulnerability.severity = item["severity"]
        if item["cvss"] is not None:
            vulnerability.cvss = item["cvss"]
        session.add(
            Activity(
                kind="vulnerability.updated" if not new else "vulnerability.new",
                subject=canonical,
                data={
                    "source": source,
                    "event_type": event_type,
                    "reason": reason,
                    "published": item.get("published"),
                    "previous": {key: normalize(source, previous).get(key) for key in ("severity", "cvss", "modified")} if previous else None,
                    "current": {key: item.get(key) for key in ("severity", "cvss", "modified")},
                },
            )
        )
        if new and context == "collection" and (vulnerability.severity in {"CRITICAL", "HIGH"}):
            session.add(Activity(kind="alert", subject=canonical, data={"reason": reason + " (alta/crítica)", "source": source, "event_type": event_type}))
    vulnerability.severity = severity_name(vulnerability.severity)
    if changed or (vulnerability.severity == "UNKNOWN" and vulnerability.cvss is not None):
        session.flush()
        refresh_assessment(session, vulnerability)
    # KEV can create the canonical record before a dated NVD/GitHub advisory.
    if vulnerability.published is None and item.get("published"):
        vulnerability.published = item["published"]
    session.flush()
    return vulnerability


_OSV_CACHE = {}
_OSV_DETAIL_CACHE = {}


async def query_osv_batch(keys):
    """OSV batch matches IDs; hydrate complete advisories once per unique ID.

    Missing/failed/paginated entries are omitted so callers retry with the fully
    paginated single-package query instead of claiming complete coverage.
    """
    from urllib.parse import quote
    results, pending = {}, []
    for key in keys:
        cached = _OSV_CACHE.get(key)
        if cached and time.monotonic() - cached[0] < 300:
            results[key] = copy.deepcopy(cached[1])
        else:
            pending.append(key)
    semaphore = asyncio.Semaphore(4)
    async with httpx.AsyncClient(timeout=30) as client:
        for start in range(0, len(pending), 100):
            group = pending[start:start + 100]
            queries = [{"package": {"ecosystem": eco, "name": package}, "version": version} for eco, package, version in group]
            body = (await request(client, "POST", "https://api.osv.dev/v1/querybatch", json={"queries": queries})).json()
            rows = body.get("results")
            if not isinstance(rows, list) or len(rows) != len(group):
                raise ValueError("OSV batch incompleto")
            details = {}

            async def hydrate(identifier):
                async with semaphore:
                    cached = _OSV_DETAIL_CACHE.get(identifier)
                    if cached and time.monotonic() - cached[0] < 300:
                        details[identifier] = copy.deepcopy(cached[1])
                        return
                    try:
                        raw = (await request(client, "GET", "https://api.osv.dev/v1/vulns/" + quote(identifier, safe=""))).json()
                        if raw.get("id") != identifier:
                            return
                        details[identifier] = raw
                        if len(_OSV_DETAIL_CACHE) >= 1024:
                            _OSV_DETAIL_CACHE.pop(next(iter(_OSV_DETAIL_CACHE)))
                        _OSV_DETAIL_CACHE[identifier] = (time.monotonic(), copy.deepcopy(raw))
                    except (httpx.HTTPError, ValueError, KeyError, TypeError):
                        return
            identifiers = {vuln["id"] for row in rows if not row.get("next_page_token") for vuln in row.get("vulns", [])}
            identifiers = list(identifiers)
            for index in range(0, len(identifiers), 40):
                await asyncio.gather(*(hydrate(value) for value in identifiers[index:index + 40]))
            for key, row in zip(group, rows):
                ids = [vuln["id"] for vuln in row.get("vulns", [])]
                if row.get("next_page_token") or not all(identifier in details for identifier in ids):
                    continue
                values = [details[identifier] for identifier in ids]
                results[key] = copy.deepcopy(values)
                if len(_OSV_CACHE) >= 256:
                    _OSV_CACHE.pop(next(iter(_OSV_CACHE)))
                _OSV_CACHE[key] = (time.monotonic(), copy.deepcopy(values))
    return results


async def query_osv(ecosystem, package, version):
    key = (ecosystem, package, version)
    cached = _OSV_CACHE.get(key)
    if cached and time.monotonic() - cached[0] < 300:
        return copy.deepcopy(cached[1])
    async with httpx.AsyncClient(timeout=30) as client:
        payload = {"package": {"ecosystem": ecosystem, "name": package}}
        if version:
            payload["version"] = version
        rows, token = [], None
        seen_tokens = set()
        while True:
            if token:
                payload["page_token"] = token
            response = await request(client, "POST", URLS["osv"], json=payload)
            body = response.json()
            rows.extend(body.get("vulns", []))
            token = body.get("next_page_token")
            if not token:
                if len(_OSV_CACHE) >= 256:
                    _OSV_CACHE.pop(next(iter(_OSV_CACHE)))
                _OSV_CACHE[key] = (time.monotonic(), copy.deepcopy(rows))
                return rows
            if token in seen_tokens:
                raise ValueError("OSV retornou paginação repetida; consulta incompleta")
            seen_tokens.add(token)
            if len(rows) > 10000:
                raise ValueError("Consulta OSV excede o limite de resultados; refine com uma versão")


async def sync_source(session, source):
    state = session.get(Source, source)
    if state is None:
        state = Source(id=source)
        session.add(state)
    previous_status = state.status
    state.status = "running"
    state.last_run = datetime.now(timezone.utc).isoformat()
    session.commit()
    count, new_count, updated_count, pages = 0, 0, 0, 0
    committed = (0, 0, 0, 0)
    started = time.monotonic()
    run = SyncRun(source=source)
    session.add(run)
    session.commit()
    run_id = run.id
    checkpoint = datetime.now(timezone.utc).isoformat()
    try:
        async with httpx.AsyncClient(timeout=45, headers={"User-Agent": "VulnRadar/0.1"}) as client:
            if source in {"nvd", "github"}:
                start = state.checkpoint or (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
                if source == "nvd":
                    # NVD limits modification windows; paginate one bounded window
                    # per sync so long-offline installations can catch up safely.
                    window_end = utc_datetime(datetime.fromisoformat(start)) + timedelta(days=119)
                    checkpoint = min(datetime.fromisoformat(checkpoint), window_end).isoformat()
                page = 0
                github_cursor, seen_github_cursors = {}, set()
                while True:
                    if source == "nvd":
                        params = {"lastModStartDate": start, "lastModEndDate": checkpoint, "startIndex": page * 2000, "resultsPerPage": 2000}
                        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
                    else:
                        params = {"modified": f">={github_timestamp(start)}", "per_page": 100, **github_cursor}
                        headers = {"Authorization": f"Bearer {settings.github_token}"} if settings.github_token else {}
                    response = await request(client, "GET", URLS[source], params=params, headers=headers)
                    body = response.json()
                    rows = body.get("vulnerabilities", []) if source == "nvd" else body
                    for row in rows:
                        identifier = normalize(source, row)["id"]
                        existing = session.get(Advisory, f"{source}:{identifier}")
                        if existing is None:
                            new_count += 1
                        elif existing.payload != row:
                            updated_count += 1
                        upsert(session, source, row)
                        count += 1
                    pages += 1
                    run.processed_count, run.new_count, run.updated_count, run.pages = count, new_count, updated_count, pages
                    session.commit()  # Retain successful pages if a later request fails.
                    committed = (count, new_count, updated_count, pages)
                    page += 1
                    if source == "github":
                        github_cursor = github_next_page(response, seen_github_cursors)
                    if (source == "nvd" and page * 2000 >= body.get("totalResults", 0)) or (source == "github" and github_cursor is None):
                        break
                    await asyncio.sleep(0.2 if source == "github" or settings.nvd_api_key else 6)
            elif source == "kev":
                rows = (await fetch_kev(client))["vulnerabilities"]
                pages = 1
                for row in rows:
                    identifier = row["cveID"]
                    alias = session.get(Alias, identifier)
                    vulnerability = session.get(Vulnerability, alias.vulnerability_id if alias else identifier)
                    if vulnerability is None:
                        vulnerability = Vulnerability(id=identifier, title=row["vulnerabilityName"], description=row.get("shortDescription", ""), severity="UNKNOWN")
                        session.add(vulnerability)
                        session.flush()
                        session.add(Alias(id=identifier, vulnerability_id=identifier))
                    if not vulnerability.kev:
                        session.add(Activity(kind="alert", subject=vulnerability.id, data={"reason": "Inclusão no CISA KEV"}))
                        session.add(Activity(kind="exploitation.updated", subject=vulnerability.id, data={"source": "kev", "from": False, "to": True, "date_added": row.get("dateAdded")}))
                    vulnerability.kev = True
                    key = f"kev:{identifier}"
                    advisory = session.get(Advisory, key)
                    if advisory:
                        if advisory.payload != row:
                            updated_count += 1
                        advisory.payload = row
                    else:
                        new_count += 1
                        session.add(Advisory(id=key, vulnerability_id=vulnerability.id, source="kev", payload=row))
                    count += 1
            elif source == "epss":
                ids = list(session.scalars(select(Alias.id).where(Alias.id.like("CVE-%"))))
                for index in range(0, len(ids), 100):
                    rows = (await request(client, "GET", URLS[source], params={"cve": ",".join(ids[index : index + 100])})).json()["data"]
                    pages += 1
                    for row in rows:
                        alias = session.get(Alias, row["cve"])
                        vulnerability = session.get(Vulnerability, alias.vulnerability_id)
                        if vulnerability.epss != float(row["epss"]):
                            updated_count += 1
                            session.add(Activity(kind="epss", subject=vulnerability.id, data=row))
                        vulnerability.epss = float(row["epss"])
                        count += 1
            else:
                raise ValueError("Fonte sem coleta global; OSV é consultado por pacote e versão")
        if source == "nvd":
            from ..db import ProductWatch
            from .products import check_product_watch
            for watch in session.scalars(select(ProductWatch)):
                check_product_watch(session, watch)
        state.status, state.error, state.checkpoint, state.count = "success", None, checkpoint, count
        session.add(Activity(kind="sync", subject=source, data={"status": "success", "count": count}))
        session.commit()
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        session.rollback()
        count, new_count, updated_count, pages = committed
        state = session.get(Source, source)
        state.status = "partial" if count else "failed"
        # Keep upstream bodies, authorization headers and credentials out of persisted errors.
        state.error = f"{type(exc).__name__}: falha na fonte; dados anteriores preservados"
        state.count = count
        if previous_status not in {"failed", "partial"}:
            session.add(
                Activity(
                    kind="alert", subject=f"source:{source}", data={"reason": "Falha de sincronização; dados anteriores preservados", "source": source, "status": state.status}
                )
            )
        session.add(Activity(kind="sync", subject=source, data={"status": "failed", "count": count}))
        session.commit()
    run = session.get(SyncRun, run_id)
    run.status = state.status
    run.completed_at = datetime.now(timezone.utc)
    run.duration_ms = round((time.monotonic() - started) * 1000)
    run.processed_count, run.new_count, run.updated_count, run.pages = count, new_count, updated_count, pages
    run.error = state.error
    session.commit()
    return state
