"""Directory discovery never executes repository code or follows symlinks."""

import shutil
import tempfile
from fastapi import HTTPException
from pathlib import Path
from ..config import settings
from ..security import authorized_path, safe_files
from .scanner import SUPPORTED

LANGUAGES = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".cs": ".NET",
    ".php": "PHP",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
}


def inspect_project(path):
    root = authorized_path(path)
    languages, lockfiles, frameworks = set(), [], set()
    for file in safe_files(root):
        if file.suffix in LANGUAGES:
            languages.add(LANGUAGES[file.suffix])
        if file.name in SUPPORTED or file.name.endswith(".cdx.json"):
            lockfiles.append(str(file.relative_to(root)))
        if file.name in {"next.config.js", "next.config.ts", "next.config.mjs"}:
            frameworks.add("Next.js")
        if file.name == "manage.py":
            frameworks.add("Possível Django (arquivo manage.py)")
    rules = list(settings.semgrep_rules.glob("*.y*ml")) if settings.semgrep_rules.is_dir() else []
    return {
        "path": str(root),
        "languages": sorted(languages),
        "lockfiles": sorted(lockfiles),
        "frameworks": sorted(frameworks),
        "checks": [
            {"label": "Caminho autorizado", "status": "ready"},
            {
                "label": "Manifestos suportados",
                "status": "ready" if lockfiles else "missing",
                "message": "Adicione um lockfile com versões resolvidas para analisar dependências" if not lockfiles else f"{len(lockfiles)} arquivos encontrados",
            },
            {
                "label": "Semgrep",
                "status": "ready" if shutil.which("semgrep") else "missing",
                "message": "Instale o mecanismo SAST seguindo a seção de instalação do README; SCA pode ser executado separadamente",
            },
            {"label": "Regras SAST locais", "status": "ready" if rules else "missing"},
            {"label": "Espaço temporário", "status": "ready" if shutil.disk_usage(tempfile.gettempdir()).free > settings.max_scan_bytes else "missing"},
        ],
    }


def browse(path=None):
    if not path:
        return {
            "path": None,
            "parent": None,
            "directories": [{"name": Path(root).name or root, "path": str(Path(root).resolve())} for root in settings.allowed_roots if Path(root).is_dir()],
            "roots_configured": bool(settings.allowed_roots),
        }
    directory = authorized_path(path)
    children = []
    for entry in sorted(directory.iterdir(), key=lambda item: item.name.lower()):
        if entry.name.startswith(".") or entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
            continue
        try:
            if entry.is_dir():
                safe = authorized_path(str(entry))
                children.append({"name": entry.name, "path": str(safe)})
        except (OSError, ValueError, HTTPException):
            continue
        if len(children) >= 200:
            break
    try:
        parent = str(authorized_path(str(directory.parent))) if directory.parent != directory else None
    except Exception:
        parent = None
    return {"path": str(directory), "parent": parent, "directories": children, "roots_configured": True}
