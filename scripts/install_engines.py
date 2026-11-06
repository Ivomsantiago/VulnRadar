"""Install optional official OCI scanner binaries after verifying release SHA256."""
import argparse
import hashlib
import io
import platform
import shutil
import tarfile
import zipfile
from pathlib import Path
import httpx

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("engine", choices=["trivy", "grype", "all"], default="all", nargs="?")
args = parser.parse_args()
system, machine = platform.system(), platform.machine().lower()
architecture = "arm64" if machine in {"aarch64", "arm64"} else "amd64" if machine in {"x86_64", "amd64"} else None
if not architecture or system not in {"Linux", "Darwin", "Windows"}:
    parser.error("Plataforma não suportada pelo instalador; instale o scanner oficialmente e adicione ao PATH")
destination = Path(__file__).resolve().parents[1] / ".engines" / "bin"
destination.mkdir(parents=True, exist_ok=True)
versions = {"trivy": ("aquasecurity/trivy", "0.76.2"), "grype": ("anchore/grype", "0.121.2")}
with httpx.Client(follow_redirects=True, timeout=180) as client:
    for engine in versions if args.engine == "all" else [args.engine]:
        repository, version = versions[engine]
        if engine == "trivy":
            suffix = f"{'macOS' if system == 'Darwin' else system}-{('ARM64' if architecture == 'arm64' else '64bit')}"
        else:
            suffix = f"{system.lower()}_{architecture}"
        archive = f"{engine}_{version}_{suffix}.{'zip' if system == 'Windows' else 'tar.gz'}"
        base = f"https://github.com/{repository}/releases/download/v{version}/"
        sums = client.get(base + f"{engine}_{version}_checksums.txt")
        sums.raise_for_status()
        expected = next((line.split()[0] for line in sums.text.splitlines() if line.split()[-1].lstrip("*") == archive), None)
        if expected is None:
            raise RuntimeError("Checksum oficial não encontrado")
        response = client.get(base + archive)
        response.raise_for_status()
        if hashlib.sha256(response.content).hexdigest() != expected:
            raise RuntimeError("Checksum inválido; instalação interrompida")
        binary = engine + (".exe" if system == "Windows" else "")
        target = destination / binary
        if system == "Windows":
            with zipfile.ZipFile(io.BytesIO(response.content)) as bundle:
                with bundle.open(binary) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
        else:
            with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as bundle:
                member = bundle.getmember(binary)
                if not member.isfile():
                    raise RuntimeError("Arquivo de release inválido")
                with bundle.extractfile(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
        target.chmod(0o755)
        print(f"{engine} {version} instalado com SHA256 verificado: {target}")
