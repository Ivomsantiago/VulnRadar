import json
from datetime import timedelta
import pytest
from sqlalchemy import select, func
from app.db import Activity, Finding, FindingState, Project, Scan, now
from app.security import read_file
from app.services.findings import index_scan
from app.services.history import ensure_baseline, expire_risks
from app.services.intelligence import upsert, query_osv_batch
from app.services.oci import normalize_report, validate_image
from app.services.scanner import parse_dependencies
from test_operations_v2 import HEADERS, make_scan


def nvd_fixture(conditional=False):
    return {
        "cve": {
            "id": "CVE-2099-PRODUCT-TEST",
            "lastModified": "2026-01-01T00:00:00Z",
            "descriptions": [{"lang": "en", "value": "Explicit test-only product"}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "AND" if conditional else "OR",
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:runtime:*:*:*:*:*:*:*:*", "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}
                            ],
                        }
                    ]
                }
            ],
        }
    }


def test_cpe_filters_version_boundaries_unknown_conditions_and_monitoring(client, session):
    upsert(session, "nvd", nvd_fixture())
    session.commit()
    query = {"vendor": "vendor", "product": "runtime", "version": "1.5"}
    rows = client.get("/api/products", params=query).json()
    assert rows["total"] == 1 and rows["items"][0]["version_match"] == "affected"
    assert client.get("/api/vulnerabilities", params=query).json()["total"] == 1
    assert client.get("/api/products", params={**query, "version": "2.0"}).json()["total"] == 0
    assert client.get("/api/products", params={**query, "version": "custom-build"}).json()["items"][0]["version_match"] == "unknown"
    watch = client.post("/api/product-watches", json=query, headers=HEADERS).json()
    for _ in range(2):
        result = client.post(f"/api/product-watches/{watch['id']}/check", headers=HEADERS)
        assert result.status_code == 200 and len(result.json()["items"]) == 1
    assert session.scalar(select(func.count()).select_from(Activity).where(Activity.kind == "alert", Activity.subject.like("product-watch:%"))) == 1
    upsert(session, "nvd", nvd_fixture(conditional=True))
    session.commit()
    assert client.get("/api/products", params=query).json()["items"][0]["version_match"] == "unknown"
    assert client.delete(f"/api/product-watches/{watch['id']}", headers=HEADERS).status_code == 204


def test_history_captures_states_instead_of_rewriting_past_and_exports_pdf(client, session):
    scan = make_scan(session)
    index_scan(session, scan)
    session.commit()
    finding = session.scalar(select(Finding))
    created = session.scalar(select(FindingState))
    created.occurred_at = now() - timedelta(days=2)
    session.commit()
    assert (
        client.patch(
            f"/api/findings/{finding.id}/triage",
            json={"status": "resolved", "reason": "Validated remediation", "owner": "AppSec", "remediation_plan": "Atualização Café"},
            headers=HEADERS,
        ).status_code
        == 200
    )
    rows = client.get("/api/reports/exposure?days=4").json()["items"]
    assert rows[0]["open"] is None and rows[1]["open"] == 1 and rows[-1]["open"] == 0
    assert rows[-1]["resolved"] == 1 and rows[1]["resolved"] == 0
    # Repeated resolution does not invent another correction in the time series.
    client.patch(f"/api/findings/{finding.id}/triage", json={"status": "resolved", "reason": "Owner updated", "owner": "Updated owner"}, headers=HEADERS)
    assert client.get("/api/reports/exposure?days=4").json()["items"][-1]["resolved"] == 1
    assert client.get("/api/reports/findings?change=resolved").json()["total"] == 1
    response = client.get("/api/reports/findings?format=pdf&status=resolved")
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-1.4") and response.content.endswith(b"%%EOF\n")
    assert b"Updated owner" in response.content and b"Caf\xe9" in response.content
    assert b"Updated owner" not in client.get("/api/reports/findings?format=pdf&status=planned").content
    assert client.get("/api/reports/exposure?format=pdf").content.startswith(b"%PDF")
    assert "date,open,closed" in client.get("/api/reports/exposure?format=csv").text


def test_empty_baseline_is_known_from_registration_and_risk_expires_without_new_scan(client, session):
    ensure_baseline(session)
    rows = client.get("/api/reports/exposure?days=2").json()["items"]
    assert rows[0]["open"] is None and rows[-1]["open"] is None
    project = Project(name="Clean scan fixture", path="/clean")
    session.add(project)
    session.flush()
    session.add(Scan(project_id=project.id, kind="sast", indexed=True, status="completed", result={}, created_at=now(), completed_at=now()))
    session.commit()
    assert client.get("/api/reports/exposure?days=2").json()["items"][-1]["open"] == 0
    scan = make_scan(session)
    index_scan(session, scan)
    finding = session.scalar(select(Finding))
    finding.status = "accepted"
    finding.risk_expires_at = now() - timedelta(hours=1)
    session.commit()
    expire_risks(session)
    assert finding.status == "new"
    assert session.scalar(select(FindingState).where(FindingState.action == "reopened"))


def trivy_fixture(vulnerable=True):
    return {
        "Metadata": {"RepoDigests": ["fixture@sha256:test"]},
        "Results": [
            {
                "Type": "alpine",
                "Target": "alpine",
                "Packages": [{"Name": "libssl", "Version": "1.0"}],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2099-OCI-TEST",
                        "PkgName": "libssl",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Severity": "HIGH",
                        "References": ["https://example.org/advisory"],
                    }
                ]
                if vulnerable
                else [],
            }
        ],
    }


def test_oci_is_separate_engine_persists_source_and_never_resolves_on_partial_scan(session):
    project = Project(name="OCI fixture", path="/fixture")
    session.add(project)
    session.flush()

    def scan(vulnerable, partial=False):
        result = normalize_report("trivy", trivy_fixture(vulnerable), "alpine:3.22")
        if partial:
            result["warnings"] = ["Incomplete test coverage"]
        value = Scan(project_id=project.id, kind="oci", status="partial" if partial else "completed", result=result)
        session.add(value)
        session.flush()
        index_scan(session, value)
        session.commit()
        return value

    scan(True)
    finding = session.scalar(select(Finding))
    assert finding.kind == "oci" and finding.fixed_versions == ["1.1"] and finding.evidence["source"] == "trivy"
    scan(False, partial=True)
    assert finding.status == "new"
    scan(True)
    last = scan(False)
    assert finding.status == "resolved" and last.result["comparison"]["resolved"] == 1
    last = scan(True)
    assert finding.status == "new" and last.result["comparison"]["reopened"] == 1


def test_retired_oci_and_registry_validation(client, session, monkeypatch):
    project = Project(name="OCI project", path="/fixture")
    session.add(project)
    session.commit()
    response = client.post(f"/api/projects/{project.id}/oci", json={"image": "alpine:3.22.0", "engine": "trivy"}, headers=HEADERS)
    assert response.status_code == 410
    for image in ("http://169.254.169.254/", "localhost:5000/image", "file:/private", "docker.io/library/image;cat", "../image", "$(command)"):
        with pytest.raises(ValueError):
            validate_image(image)
    assert validate_image("ghcr.io/org/image@sha256:" + "a" * 64)


def test_grype_database_status_object_and_fixes_are_preserved():
    raw = {
        "source": {"type": "image", "target": {"imageID": "sha256:fixture"}},
        "descriptor": {"db": {"status": {"valid": True, "built": "2026-01-01"}}},
        "matches": [
            {"vulnerability": {"id": "CVE-2099-GRYPE-TEST", "severity": "High", "fix": {"versions": ["1.1"]}}, "artifact": {"name": "lib", "version": "1.0", "type": "apk"}}
        ],
    }
    result = normalize_report("grype", raw, "alpine:3.22")
    assert result["coverage"] == "complete" and result["source_updated"] == "2026-01-01"
    raw["descriptor"]["db"]["status"]["valid"] = False
    assert normalize_report("grype", raw, "alpine:3.22")["coverage"] == "partial"


async def test_osv_batch_hydrates_unique_advisories_and_omits_paginated_entries(monkeypatch):
    import httpx
    from app.services import intelligence

    intelligence._OSV_CACHE.clear()
    intelligence._OSV_DETAIL_CACHE.clear()
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path.endswith("querybatch"):
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": "TEST-BATCH"}]}, {"vulns": [{"id": "TEST-BATCH"}]}, {"vulns": [{"id": "TEST-OTHER"}], "next_page_token": "more"}]}
            )
        return httpx.Response(200, json={"id": "TEST-BATCH", "summary": "Full advisory", "affected": []})

    original = httpx.AsyncClient
    monkeypatch.setattr(intelligence.httpx, "AsyncClient", lambda **_: original(transport=httpx.MockTransport(handler)))
    keys = [("npm", package, "1.0.0") for package in ("a", "b", "c")]
    result = await query_osv_batch(keys)
    assert result[keys[0]][0]["summary"] == "Full advisory" and keys[2] not in result
    assert calls.count("/v1/vulns/TEST-BATCH") == 1
    result[keys[0]][0]["summary"] = "Changed"
    assert (await intelligence.query_osv(*keys[1]))[0]["summary"] == "Full advisory"
    intelligence._OSV_CACHE.clear()
    intelligence._OSV_DETAIL_CACHE.clear()


@pytest.mark.parametrize(
    "name,text,package,version,direct",
    [
        ("pnpm-lock.yaml", "lockfileVersion: '5.4'\ndependencies:\n  '@scope/lib': 1.2.3\npackages:\n  /@scope/lib/1.2.3_peer@2.0.0: {}\n", "@scope/lib", "1.2.3", True),
        ("yarn.lock", '# yarn lockfile v1\n"alias@npm:real-lib@^1.0":\n  version "1.2.3"\n', "real-lib", "1.2.3", None),
        ("uv.lock", 'version = 1\n[[package]]\nname="Some_Package"\nversion="1.2.3"\n', "some-package", "1.2.3", None),
        (
            "project.assets.json",
            '{"libraries":{"Lib/1.2.3":{"type":"package"},"Local/1.0":{"type":"project"}},"project":{"frameworks":{"net8.0":{"dependencies":{"Lib":{}}}}}}',
            "lib",
            "1.2.3",
            True,
        ),
        ("Gemfile.lock", "GEM\n  specs:\n    nokogiri (1.16.2-x86_64-linux)\n      racc (~> 1.4)\n\nDEPENDENCIES\n  nokogiri\n", "nokogiri", "1.16.2", True),
        (
            "pom.xml",
            "<project><properties><lib.version>1.2.3</lib.version></properties><dependencyManagement><dependencies><dependency><groupId>org</groupId><artifactId>lib</artifactId><version>${lib.version}</version></dependency></dependencies></dependencyManagement><dependencies><dependency><groupId>org</groupId><artifactId>lib</artifactId></dependency></dependencies></project>",
            "org:lib",
            "1.2.3",
            True,
        ),
    ],
)
def test_extended_parser_coordinates(tmp_path, name, text, package, version, direct):
    path = tmp_path / name
    path.write_text(text)
    items, _ = parse_dependencies(path)
    assert len(items) == 1 and (items[0]["package"], items[0]["version"], items[0]["direct"]) == (package, version, direct)


def test_unknown_versions_and_local_go_replace_are_not_vulnerability_matches(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps({"packages": {"node_modules/lib": {"version": "latest"}}}))
    items, warnings = parse_dependencies(path)
    assert not items and warnings
    path = tmp_path / "go.mod"
    path.write_text("module test\nrequire example.org/lib v1.2.3\nreplace example.org/lib => ../local\n")
    items, warnings = parse_dependencies(path)
    assert not items and warnings


def test_reader_rejects_symlinked_ancestor_even_when_leaf_is_regular(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "private.txt").write_text("private")
    try:
        (root / "changed").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Sistema não autoriza criação de symlinks")
    with pytest.raises((OSError, ValueError)):
        read_file(root, root / "changed" / "private.txt")


def test_yarn_direct_selectors_include_aliases_without_marking_other_versions_direct(tmp_path):
    path = tmp_path / "yarn.lock"
    path.write_text('"alias@npm:real-lib@^1.0":\n  version "1.2.3"\n"real-lib@^2.0":\n  version "2.0.0"\n')
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"alias": "npm:real-lib@^1.0"}}))
    items, _ = parse_dependencies(path)
    assert items[0]["direct"] is True and items[1]["direct"] is False


def test_nuget_fix_matches_ecosystem_case_equivalence(session):
    from test_intelligence import osv

    raw = osv()
    raw["affected"] = [{"package": {"ecosystem": "NuGet", "name": "Some.Library"}, "ranges": [{"events": [{"fixed": "2.0.0"}]}]}]
    scan = make_scan(session, raw=raw)
    scan.result["findings"][0]["dependency"].update(ecosystem="NuGet", package="some.library")
    index_scan(session, scan)
    assert session.scalar(select(Finding)).fixed_versions == ["2.0.0"]


async def test_sca_batch_failure_falls_back_and_keeps_individual_failures_partial(tmp_path, monkeypatch):
    from app.config import settings
    from app.services import scanner

    monkeypatch.setattr(settings, "osv_batch", True)
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/ok": {"version": "1.0.0"}, "node_modules/fail": {"version": "1.0.0"}}}))

    async def batch(_):
        raise ValueError("Test-only batch failure")

    async def query(eco, package, version):
        if package == "fail":
            raise ValueError("Test-only lookup failure")
        return []

    monkeypatch.setattr(scanner, "query_osv_batch", batch)
    monkeypatch.setattr(scanner, "query_osv", query)
    result = await scanner.sca(tmp_path)
    assert result["coverage"] == "partial"
    assert {row["package"]: row["query_status"] for row in result["inventory"]} == {"ok": "complete", "fail": "failed"}


async def test_nvd_long_offline_checkpoint_uses_accepted_window(session, monkeypatch):
    from datetime import datetime
    import httpx
    from app.db import Source, utc_datetime
    from app.services import intelligence

    start = now() - timedelta(days=300)
    session.add(Source(id="nvd", checkpoint=start.isoformat(), status="success"))
    session.commit()

    async def request(client, method, url, **kwargs):
        params = kwargs["params"]
        end = datetime.fromisoformat(params["lastModEndDate"])
        beginning = datetime.fromisoformat(params["lastModStartDate"])
        assert (end - beginning).days == 119
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})

    monkeypatch.setattr(intelligence, "request", request)
    result = await intelligence.sync_source(session, "nvd")
    assert result.status == "success"
    assert utc_datetime(datetime.fromisoformat(result.checkpoint)) == start + timedelta(days=119)


def test_publication_collection_local_discovery_and_update_are_distinct(session):
    from test_intelligence import osv

    old = {**osv("OLD", ["CVE-2099-OLD"]), "published": "2020-01-01T00:00:00Z"}
    upsert(session, "osv", old)
    upsert(session, "osv", {**old, "summary": "Updated source evidence"})
    upsert(session, "osv", osv("LOCAL", ["CVE-2099-LOCAL"]), context="scan")
    upsert(session, "osv", {**osv("RECENT", ["CVE-2099-RECENT"]), "published": now().isoformat()})
    session.commit()
    events = list(session.scalars(select(Activity).where(Activity.kind.in_(["vulnerability.new", "vulnerability.updated"])).order_by(Activity.id)))
    assert [event.data["event_type"] for event in events] == ["first_collection", "advisory_update", "local_discovery", "publication"]


def test_today_history_does_not_mark_a_future_deadline_overdue(client, session, monkeypatch):
    from app import reports

    midday = now().replace(hour=12, minute=0, second=0, microsecond=0)
    scan = make_scan(session)
    index_scan(session, scan)
    event = session.scalar(select(FindingState))
    event.occurred_at = midday - timedelta(hours=1)
    event.data = {**event.data, "status": "planned", "due_at": (midday + timedelta(hours=1)).isoformat()}
    session.commit()
    monkeypatch.setattr(reports, "now", lambda: midday)
    point = client.get("/api/reports/exposure?days=1").json()["items"][0]
    assert point["open"] == 1 and point["overdue"] == 0
