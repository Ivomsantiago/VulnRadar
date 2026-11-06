"""Present source fields without inventing missing fixes or collapsing disagreements."""

ECOSYSTEMS = {"pip": "PyPI", "maven": "Maven", "go": "Go", "rubygems": "RubyGems", "cargo": "crates.io", "nuget": "NuGet", "composer": "Packagist", "npm": "npm"}


def evidence(source, raw):
    if source == "osv":
        packages = []
        for entry in raw.get("affected", []):
            package = entry.get("package", {})
            fixed = [event["fixed"] for interval in entry.get("ranges", []) for event in interval.get("events", []) if "fixed" in event]
            packages.append(
                {
                    "ecosystem": package.get("ecosystem", "unknown"),
                    "package": package.get("name", "unknown"),
                    "ranges": entry.get("ranges", []),
                    "versions": entry.get("versions", []),
                    "fixed": fixed,
                }
            )
        return {
            "source": source,
            "packages": packages,
            "references": raw.get("references", []),
            "scores": raw.get("severity", []),
            "cwes": raw.get("database_specific", {}).get("cwe_ids", []),
        }
    if source == "github":
        packages = []
        for entry in raw.get("vulnerabilities", []):
            package = entry.get("package", {})
            fixed = entry.get("first_patched_version")
            if isinstance(fixed, dict):
                fixed = fixed.get("identifier")
            packages.append(
                {
                    "ecosystem": ECOSYSTEMS.get(package.get("ecosystem"), package.get("ecosystem", "unknown")),
                    "package": package.get("name", "unknown"),
                    "ranges": entry.get("vulnerable_version_range"),
                    "fixed": [fixed] if fixed else [],
                }
            )
        return {
            "source": source,
            "packages": packages,
            "references": [{"url": ref} if isinstance(ref, str) else ref for ref in raw.get("references", [])],
            "scores": raw.get("cvss_severities") or raw.get("cvss"),
            "cwes": raw.get("cwes", []),
        }
    if source == "nvd":
        cve = raw.get("cve", raw)
        return {
            "source": source,
            "packages": [],
            "products": cve.get("configurations", []),
            "references": cve.get("references", []),
            "scores": cve.get("metrics", {}),
            "cwes": cve.get("weaknesses", []),
        }
    if source == "kev":
        return {
            "source": source,
            "packages": [],
            "references": [{"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}],
            "mitigation": raw.get("requiredAction"),
            "date_added": raw.get("dateAdded"),
        }
    return {"source": source, "packages": [], "references": []}
