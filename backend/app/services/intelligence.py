"""Connectors preserve original source evidence and explicit aliases."""

import asyncio
import random
from datetime import datetime, timedelta, timezone
import httpx
from sqlalchemy import select, delete
from ..config import settings
from ..db import Activity, Advisory, Alias, Source, Vulnerability, AffectedPackage
from .evidence import evidence

URLS = {
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "github": "https://api.github.com/advisories",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://api.first.org/data/v1/epss",
    "osv": "https://api.osv.dev/v1/query",
}

KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"


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


def normalize(source, raw):
    if source == "osv":
        scores = raw.get("severity", [])
        return dict(
            id=raw["id"],
            aliases=raw.get("aliases", []),
            title=raw.get("summary", raw["id"]),
            description=raw.get("details", ""),
            published=raw.get("published"),
            modified=raw.get("modified"),
            severity=raw.get("database_specific", {}).get("severity", "UNKNOWN").upper(),
            cvss=None,
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
            severity=raw.get("severity", "UNKNOWN").upper(),
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
        severity=severity,
        cvss=score,
        affected=cve.get("configurations", []),
        references=cve.get("references", []),
    )


def upsert(session, source, raw):
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
        session.flush()
        session.delete(old)
    for identifier in identifiers:
        if session.get(Alias, identifier) is None:
            session.add(Alias(id=identifier, vulnerability_id=canonical))
    key = f"{source}:{item['id']}"
    advisory = session.get(Advisory, key)
    changed = advisory is None or advisory.payload != raw
    if advisory is None:
        session.add(Advisory(id=key, source=source, vulnerability_id=canonical, payload=raw))
    else:
        advisory.payload = raw
    if changed:
        session.flush()
        session.execute(delete(AffectedPackage).where(AffectedPackage.advisory_id == key))
        for package in evidence(source, raw)["packages"]:
            session.add(AffectedPackage(advisory_id=key, ecosystem=package["ecosystem"], package=package["package"], constraints=package))
        vulnerability.updated_at = datetime.now(timezone.utc)
        vulnerability.title = item["title"]
        vulnerability.description = item["description"]
        vulnerability.modified = item["modified"]
        vulnerability.severity = item["severity"]
        if item["cvss"] is not None:
            vulnerability.cvss = item["cvss"]
        session.add(Activity(kind="vulnerability.updated" if not new else "vulnerability.new", subject=canonical, data={"source": source}))
        if new and (vulnerability.severity in {"CRITICAL", "HIGH"}):
            session.add(Activity(kind="alert", subject=canonical, data={"reason": "Nova vulnerabilidade alta ou crítica", "source": source}))
    session.flush()
    return vulnerability


async def query_osv(ecosystem, package, version):
    async with httpx.AsyncClient(timeout=30) as client:
        response = await request(client, "POST", URLS["osv"], json={"package": {"ecosystem": ecosystem, "name": package}, "version": version})
        return response.json().get("vulns", [])


async def sync_source(session, source):
    state = session.get(Source, source)
    if state is None:
        state = Source(id=source)
        session.add(state)
    state.status = "running"
    state.last_run = datetime.now(timezone.utc).isoformat()
    session.commit()
    count = 0
    checkpoint = datetime.now(timezone.utc).isoformat()
    try:
        async with httpx.AsyncClient(timeout=45, headers={"User-Agent": "VulnRadar/0.1"}) as client:
            if source in {"nvd", "github"}:
                start = state.checkpoint or (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
                page = 0
                while True:
                    if source == "nvd":
                        params = {"lastModStartDate": start, "lastModEndDate": checkpoint, "startIndex": page * 2000, "resultsPerPage": 2000}
                        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
                    else:
                        params = {"modified": f">={start}", "per_page": 100, "page": page + 1}
                        headers = {"Authorization": f"Bearer {settings.github_token}"} if settings.github_token else {}
                    response = await request(client, "GET", URLS[source], params=params, headers=headers)
                    body = response.json()
                    rows = body.get("vulnerabilities", []) if source == "nvd" else body
                    for row in rows:
                        upsert(session, source, row)
                        count += 1
                    session.commit()  # Retain successful pages if a later request fails.
                    page += 1
                    if (source == "nvd" and page * 2000 >= body.get("totalResults", 0)) or (source == "github" and 'rel="next"' not in response.headers.get("Link", "")):
                        break
                    await asyncio.sleep(0.2 if source == "github" or settings.nvd_api_key else 6)
            elif source == "kev":
                rows = (await fetch_kev(client))["vulnerabilities"]
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
                    vulnerability.kev = True
                    key = f"kev:{identifier}"
                    advisory = session.get(Advisory, key)
                    if advisory:
                        advisory.payload = row
                    else:
                        session.add(Advisory(id=key, vulnerability_id=vulnerability.id, source="kev", payload=row))
                    count += 1
            elif source == "epss":
                ids = list(session.scalars(select(Alias.id).where(Alias.id.like("CVE-%"))))
                for index in range(0, len(ids), 100):
                    rows = (await request(client, "GET", URLS[source], params={"cve": ",".join(ids[index : index + 100])})).json()["data"]
                    for row in rows:
                        alias = session.get(Alias, row["cve"])
                        vulnerability = session.get(Vulnerability, alias.vulnerability_id)
                        vulnerability.epss = float(row["epss"])
                        session.add(Activity(kind="epss", subject=vulnerability.id, data=row))
                        count += 1
            else:
                raise ValueError("Fonte sem coleta global; OSV é consultado por pacote e versão")
        state.status, state.error, state.checkpoint, state.count = "success", None, checkpoint, count
        session.add(Activity(kind="sync", subject=source, data={"status": "success", "count": count}))
        session.commit()
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        session.rollback()
        state = session.get(Source, source)
        state.status = "failed"
        # Keep upstream bodies, authorization headers and credentials out of persisted errors.
        state.error = f"{type(exc).__name__}: falha na fonte; dados anteriores preservados"
        state.count = count
        session.add(Activity(kind="sync", subject=source, data={"status": "failed", "count": count}))
        session.commit()
    return state
