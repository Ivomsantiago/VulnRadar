from pathlib import Path
from fastapi import HTTPException
from .config import settings


def authorized_path(value: str) -> Path:
    path = Path(value).resolve(strict=True)
    roots = [Path(root).resolve(strict=True) for root in settings.allowed_roots if Path(root).is_dir()]
    if not path.is_dir() or not any(path.is_relative_to(root) for root in roots):
        raise HTTPException(403, "Diretório fora das raízes autorizadas")
    return path


def safe_files(root: Path):
    count = 0
    total_bytes = 0
    excluded = {".git", "node_modules", ".venv", "venv", "dist", "build", "vendor"}
    import os

    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in excluded and not (Path(directory) / d).is_symlink() and not getattr(Path(directory) / d, "is_junction", lambda: False)()]
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink() or getattr(path, "is_junction", lambda: False)() or not path.resolve().is_relative_to(root):
                continue
            count += 1
            if count > settings.max_files:
                raise ValueError("Limite de arquivos excedido; análise incompleta")
            total_bytes += path.stat().st_size
            if total_bytes > settings.max_scan_bytes:
                raise ValueError("Limite agregado da análise excedido")
            if path.stat().st_size > settings.max_file_bytes:
                raise ValueError(f"Arquivo excede o limite: {path.relative_to(root)}")
            yield path
