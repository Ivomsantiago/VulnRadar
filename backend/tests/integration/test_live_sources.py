"""Optional live checks: explicitly opt in; never substitute mocks here."""

import os
import httpx
import pytest
from app.services.intelligence import URLS, request, query_osv, fetch_kev

pytestmark = [pytest.mark.integration, pytest.mark.skipif(os.environ.get("VULNRADAR_LIVE_TESTS") != "1", reason="Integrações reais opcionais: VULNRADAR_LIVE_TESTS=1")]


@pytest.mark.parametrize("source", ["nvd", "github", "kev", "epss"])
async def test_live_official_source(source):
    params = {"nvd": {"cveId": "CVE-2021-44228"}, "github": {"per_page": 1}, "kev": {}, "epss": {"cve": "CVE-2021-44228"}}[source]
    async with httpx.AsyncClient(timeout=45, headers={"User-Agent": "VulnRadar-integration-test/0.1"}) as client:
        if source == "kev":
            data = await fetch_kev(client)
            assert data["vulnerabilities"]
            return
        response = await request(client, "GET", URLS[source], params=params)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list)) and data


async def test_live_osv_version_lookup():
    rows = await query_osv("npm", "lodash", "4.17.20")
    assert rows and all("id" in row for row in rows)


async def test_live_osv_batch_hydrates_full_advisories():
    from app.services.intelligence import query_osv_batch

    keys = [("npm", "lodash", "4.17.20"), ("PyPI", "django", "1.11.0")]
    result = await query_osv_batch(keys)
    assert all(result[key] and all(row.get("affected") for row in result[key]) for key in keys)


async def test_live_nvd_cpe_index_uses_official_product_data(session):
    from app.services.intelligence import upsert
    from app.services.products import product_rows

    async with httpx.AsyncClient(timeout=45) as client:
        response = await request(client, "GET", URLS["nvd"], params={"cveId": "CVE-2021-44228"})
        upsert(session, "nvd", response.json()["vulnerabilities"][0])
        session.commit()
    rows = list(product_rows(session, vendor="apache", product="log4j", version="2.14.1"))
    assert rows and any(row["version_match"] == "affected" for row in rows)


@pytest.mark.parametrize("source", ["nvd", "github"])
async def test_live_month_publication_filter(source):
    from datetime import datetime, timedelta
    from app.db import now, utc_datetime
    from app.services.intelligence import normalize

    end = now().replace(microsecond=0)
    start = end - timedelta(days=30)
    params = (
        {"pubStartDate": start.isoformat(), "pubEndDate": end.isoformat(), "resultsPerPage": 1}
        if source == "nvd"
        else {"published": f"{start.strftime('%Y-%m-%dT%H:%M:%SZ')}..{end.strftime('%Y-%m-%dT%H:%M:%SZ')}", "per_page": 1}
    )
    async with httpx.AsyncClient(timeout=45) as client:
        response = await request(client, "GET", URLS[source], params=params)
        rows = response.json().get("vulnerabilities", []) if source == "nvd" else response.json()
        assert rows
        assert all(start <= utc_datetime(datetime.fromisoformat(normalize(source, row)["published"])) <= end for row in rows)
        if source == "github":
            from app.services.intelligence import github_next_page

            cursor = github_next_page(response, set())
            assert cursor and "after" in cursor
            next_response = await request(client, "GET", URLS[source], params={**params, **cursor})
            assert next_response.json()[0]["ghsa_id"] != rows[0]["ghsa_id"]
