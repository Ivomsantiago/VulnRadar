from urllib.parse import quote


def cyclone_dx(inventory):
    ecosystem_types = {"npm": "npm", "PyPI": "pypi", "Maven": "maven", "Go": "golang", "crates.io": "cargo", "NuGet": "nuget", "Packagist": "composer", "RubyGems": "gem"}
    unique = {(d["ecosystem"], d["package"], d["version"]): d for d in inventory}
    components = []
    for (ecosystem, package, version), dependency in unique.items():
        kind = ecosystem_types.get(ecosystem)
        component = {"type": "library", "name": package, "version": version}
        if dependency.get("purl"):
            component["purl"] = dependency["purl"]
        if kind:
            name = package.replace(":", "/") if kind == "maven" else package
            component["purl"] = f"pkg:{kind}/{quote(name, safe='/')}@{quote(version, safe='')}"
        components.append(component)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}


def sarif(findings):
    rules = {}
    results = []
    for finding in findings:
        rule_id = finding["check_id"]
        extra = finding.get("extra", {})
        rules[rule_id] = {"id": rule_id, "shortDescription": {"text": extra.get("message", rule_id)}}
        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if extra.get("severity") == "ERROR" else "warning",
                "message": {"text": extra.get("message", rule_id)},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": quote(finding["path"].replace("\\", "/"), safe="/")}, "region": {"startLine": finding["start"]["line"]}}}
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Semgrep via VulnRadar", "rules": list(rules.values())}}, "results": results}],
    }
