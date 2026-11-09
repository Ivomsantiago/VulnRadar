import pytest
from app.config import Settings


def test_configuration_failure_does_not_echo_secret_inputs():
    with pytest.raises(ValueError) as result:
        Settings(_env_file=None, access_mode="team", smtp_password="PRIVATE-CONFIG-SECRET")
    assert "PRIVATE-CONFIG-SECRET" not in str(result.value)
