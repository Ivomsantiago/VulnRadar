"""Offline validation using bundled official schemas; never retrieves input URLs."""
import json
from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from ..config import settings


def cyclonedx_validator():
    base = settings.semgrep_rules.parent / "schemas"
    registry = Registry()
    documents = {}
    for name in ("bom-1.5.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        document = json.loads((base / name).read_text(encoding="utf-8"))
        documents[name] = document
        registry = registry.with_resource(document["$id"], Resource.from_contents(document))
    return Draft7Validator(documents["bom-1.5.schema.json"], registry=registry, format_checker=FormatChecker())
