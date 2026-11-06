"""Canonical package names only where the ecosystem defines equivalence."""

import re


def package_identity(ecosystem, name):
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in {"NuGet", "Packagist"}:
        return name.lower()
    return name
