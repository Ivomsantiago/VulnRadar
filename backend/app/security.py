from pathlib import Path
from fastapi import HTTPException
from .config import settings
import os
import stat


def read_file(root: Path, path: Path, maximum=None):
    """Read regular files through directory handles on POSIX; reject symlink races."""
    maximum = settings.max_file_bytes if maximum is None else maximum
    root, path = root.absolute(), path.absolute()
    relative = path.relative_to(root)
    if ".." in relative.parts:
        raise ValueError("Arquivo fora do escopo")
    if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
        descriptor = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in (*root.parts[1:], *relative.parts[:-1]):
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            handle = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        finally:
            os.close(descriptor)
    else:
        # Windows: check every component (including junctions), then verify identity.
        for parent in (path, *path.parents):
            if parent.is_symlink() or getattr(parent, "is_junction", lambda: False)():
                raise ValueError("Links não são permitidos no escopo de análise")
        if not path.resolve(strict=True).is_relative_to(root):
            raise ValueError("Arquivo fora do escopo")
        before = path.stat()
        handle = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        if (before.st_dev, before.st_ino) != (os.fstat(handle).st_dev, os.fstat(handle).st_ino):
            os.close(handle)
            raise ValueError("Arquivo alterado durante a leitura")
        if os.name == "nt":
            import ctypes
            import msvcrt
            from ctypes import wintypes
            final_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
            final_path.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
            final_path.restype = wintypes.DWORD
            buffer = ctypes.create_unicode_buffer(32768)
            length = final_path(msvcrt.get_osfhandle(handle), buffer, len(buffer), 0)
            resolved = buffer.value
            if resolved.startswith("\\\\?\\UNC\\"):
                resolved = "\\\\" + resolved[8:]
            elif resolved.startswith("\\\\?\\"):
                resolved = resolved[4:]
            if not length or length >= len(buffer) or not Path(resolved).is_relative_to(root):
                os.close(handle)
                raise ValueError("Destino do handle fora do escopo autorizado")
    with os.fdopen(handle, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Somente arquivos regulares podem ser analisados")
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError("Arquivo excede o limite")
    return content


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
