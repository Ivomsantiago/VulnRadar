"""Purpose-limited controls shared by scanners and external package connectors."""
import os
from pathlib import Path
from .config import settings


def require_package_egress() -> None:
    if not settings.osv_queries_enabled:
        raise ValueError("Consultas externas de pacotes desabilitadas pela política de privacidade")


def scanner_environment(home: Path, executable: str) -> dict[str, str]:
    allowed = {key: value for key, value in os.environ.items() if key.upper() in {"SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "TEMP", "TMP", "TMPDIR"}}
    allowed.update({"PATH": str(Path(executable).parent) + os.pathsep + os.defpath,
                    "HOME": str(home), "USERPROFILE": str(home), "XDG_CONFIG_HOME": str(home), "XDG_CACHE_HOME": str(home),
                    "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"})
    return allowed
