import json
import pytest
from fastapi import HTTPException
from app.config import settings
from app.security import authorized_path, safe_files
from app.services.scanner import parse_dependencies, sca


def test_symlink_escape(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "private"
    outside.mkdir()
    (outside / "secret.txt").write_text("fixture")
    try:
        (root / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Sistema sem permissão para criar symlinks")
    monkeypatch.setattr(settings, "allowed_roots", [str(root)])
    assert authorized_path(str(root)) == root
    with pytest.raises(HTTPException):
        authorized_path(str(root / "link"))
    assert list(safe_files(root)) == []


def test_requirements_unresolved(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("requests==2.0.0\nflask>=1.0\n# comment\n")
    items, warnings = parse_dependencies(path)
    assert items[0]["package"] == "requests" and items[0]["version"] == "2.0.0"
    assert len(warnings) == 1


def test_package_lock_scoped(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_text(
        json.dumps(
            {
                "packages": {
                    "": {"dependencies": {"@scope/name": "1.0.0"}},
                    "node_modules/@scope/name": {"version": "1.0.0"},
                    "node_modules/@scope/name/node_modules/transitive": {"version": "2.0.0"},
                }
            }
        )
    )
    items, warnings = parse_dependencies(path)
    assert items[0]["package"] == "@scope/name" and items[0]["direct"]
    assert items[1]["package"] == "transitive" and not items[1]["direct"]
    assert not warnings


@pytest.mark.parametrize(
    "name,text,ecosystem",
    [
        ("Cargo.lock", '[[package]]\nname="crate"\nversion="1.0.0"', "crates.io"),
        ("poetry.lock", '[[package]]\nname="lib"\nversion="1.0.0"', "PyPI"),
        ("composer.lock", '{"packages":[{"name":"vendor/lib","version":"v1.0.0"}]}', "Packagist"),
        ("go.mod", "module test\nrequire example.org/lib v1.0.0", "Go"),
        ("gradle.lockfile", "org.test:lib:1.0.0=runtimeClasspath", "Maven"),
        ("packages.lock.json", '{"dependencies":{"net8.0":{"Lib":{"resolved":"1.0.0","type":"Direct"}}}}', "NuGet"),
    ],
)
def test_formats(tmp_path, name, text, ecosystem):
    path = tmp_path / name
    path.write_text(text)
    items, _ = parse_dependencies(path)
    assert len(items) == 1 and items[0]["ecosystem"] == ecosystem


async def test_sca_failed_queries_not_clean(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.0.0")

    async def fail(*args):
        raise RuntimeError("unavailable")

    monkeypatch.setattr("app.services.scanner.query_osv", fail)
    result = await sca(tmp_path)
    assert result["coverage"] == "partial"
    assert result["inventory"][0]["query_status"] == "failed" and result["warnings"]


@pytest.mark.parametrize(
    "name,text",
    [
        ("yarn.lock", '# yarn lockfile v1\n"@scope/lib@^1.0.0":\n  version "1.2.3"\n'),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  '@scope/lib@1.2.3': {}\nsnapshots:\n  '@scope/lib@1.2.3': {}\n"),
    ],
)
def test_yarn_and_pnpm(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    items, notes = parse_dependencies(path)
    assert items[0]["package"] == "@scope/lib" and items[0]["version"] == "1.2.3"
    assert not notes


async def test_sca_positive_fixture(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/fixture": {"version": "1.0.0"}}}))

    async def query(*args):
        return [{"id": "fixture-only", "affected": []}]

    monkeypatch.setattr("app.services.scanner.query_osv", query)
    result = await sca(tmp_path)
    assert result["coverage"] == "complete"
    assert result["findings"][0]["advisory"]["id"] == "fixture-only"
