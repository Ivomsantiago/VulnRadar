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
