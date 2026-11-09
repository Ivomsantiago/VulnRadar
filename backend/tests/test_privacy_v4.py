import gzip
import httpx
import pytest
from app.config import settings
from app.privacy import require_package_egress, scanner_environment
from app.services import intelligence


def test_scanner_does_not_inherit_server_secrets_or_home(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNRADAR_NVD_API_KEY", "TEST-PRIVATE-NVD-KEY")
    monkeypatch.setenv("GITHUB_TOKEN", "TEST-PRIVATE-GITHUB-KEY")
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "TEST-PRIVATE-SEMGREP-TOKEN")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "TEST-PRIVATE-AWS-KEY")
    env = scanner_environment(tmp_path, "/isolated/semgrep")
    assert all(value not in env.values() for value in ["TEST-PRIVATE-NVD-KEY", "TEST-PRIVATE-GITHUB-KEY", "TEST-PRIVATE-SEMGREP-TOKEN", "TEST-PRIVATE-AWS-KEY"])
    assert env["HOME"] == str(tmp_path)


async def test_privacy_policy_blocks_even_cached_package_egress(monkeypatch):
    monkeypatch.setattr(settings, "osv_queries_enabled", False)
    with pytest.raises(ValueError, match="privacidade"):
        require_package_egress()
    with pytest.raises(ValueError, match="privacidade"):
        await intelligence.query_osv("npm", "internal-package", "1.0.0")
    with pytest.raises(ValueError, match="privacidade"):
        await intelligence.query_osv_batch([("npm", "internal-package", "1.0.0")])


async def test_upstream_body_limit_and_compressed_responses(monkeypatch):
    monkeypatch.setattr(settings, "max_upstream_bytes", 100)
    compressed = gzip.compress(b'{"ok":true}')
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, content=compressed, headers={"Content-Encoding": "gzip"}))) as client:
        result = await intelligence.request(client, "GET", "https://source.example.test")
        assert result.json() == {"ok": True}
    compressed = gzip.compress(b"x" * 101)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, content=compressed, headers={"Content-Encoding": "gzip"}))) as client:
        with pytest.raises(ValueError, match="limite"):
            await intelligence.request(client, "GET", "https://source.example.test")


async def test_supervisor_restarts_after_failure_but_propagates_cancellation(monkeypatch):
    import asyncio
    from app import workers
    calls = []

    async def runner():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("test-only")
        raise asyncio.CancelledError

    async def wait(_):
        pass

    monkeypatch.setattr(workers.asyncio, "sleep", wait)
    with pytest.raises(asyncio.CancelledError):
        await workers.supervise("test", runner)
    assert len(calls) == 2


async def test_team_does_not_launch_local_sast_without_explicit_server_policy(tmp_path, monkeypatch):
    from app.services.scanner import sast
    monkeypatch.setattr(settings, "access_mode", "team")
    monkeypatch.setattr(settings, "allow_local_sast_in_team", False)
    with pytest.raises(ValueError, match="bloqueado"):
        await sast(tmp_path)
