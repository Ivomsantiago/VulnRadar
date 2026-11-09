import pytest
from app.services.intelligence import upsert


@pytest.mark.parametrize("mutation", [{"id": "a" * 161}, {"aliases": ["bad\nidentifier"]}, {"database_specific": {"severity": "HIGH"}, "aliases": ["a"] * 101}])
def test_invalid_source_identity_is_rejected_before_persistence(session, mutation):
    from sqlalchemy import select, func
    from app.db import Vulnerability
    raw = {"id": "OSV-source-fixture", **mutation}
    with pytest.raises(ValueError):
        upsert(session, "osv", raw)
    assert session.scalar(select(func.count()).select_from(Vulnerability)) == 0


def test_cvss_outside_domain_does_not_enter_index(session):
    with pytest.raises(ValueError):
        upsert(session, "github", {"ghsa_id": "GHSA-test-source", "cvss": {"score": 900}, "summary": "Invalid upstream score"})
