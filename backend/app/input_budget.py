"""Bound untrusted document complexity before domain/schema processing."""
from collections.abc import Mapping
import json
import tomllib
from typing import Any

import yaml

MAX_DEPTH = 32
MAX_NODES = 200_000


def check_structure(value: Any) -> Any:
    pending = [(value, 0)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if depth > MAX_DEPTH or visited > MAX_NODES:
            raise ValueError("Documento excede o limite de profundidade ou estrutura")
        if isinstance(item, (Mapping, list, tuple)):
            if visited + len(pending) + len(item) > MAX_NODES:
                raise ValueError("Documento excede o limite de estrutura")
            children = item.values() if isinstance(item, Mapping) else item
            pending.extend((child, depth + 1) for child in children)
    return value


def load_json(text: str) -> Any:
    try:
        document = check_structure(json.loads(text))
        if not isinstance(document, dict):
            raise ValueError("Manifesto JSON exige um objeto na raiz")
        return document
    except RecursionError:
        raise ValueError("JSON excede o limite de profundidade") from None


def load_toml(text: str) -> dict[str, Any]:
    document = tomllib.loads(text)
    check_structure(document)
    return document


def load_yaml(text: str) -> Any:
    # Event parsing stops before SafeLoader can expand merge/alias graphs.
    depth = count = 0
    events = yaml.parse(text, Loader=yaml.SafeLoader)
    try:
        for event in events:
            count += 1
            if isinstance(event, yaml.events.AliasEvent) or isinstance(event, yaml.events.ScalarEvent) and event.value == "<<":
                raise ValueError("Aliases e merges YAML não são suportados; forneça lockfile expandido")
            if isinstance(event, yaml.events.CollectionStartEvent):
                depth += 1
            elif isinstance(event, yaml.events.CollectionEndEvent):
                depth -= 1
            if depth > MAX_DEPTH or count > MAX_NODES:
                raise ValueError("YAML excede o limite de profundidade ou estrutura")
        document = check_structure(yaml.safe_load(text))
        if not isinstance(document, dict):
            raise ValueError("Manifesto YAML exige um objeto na raiz")
        return document
    except (yaml.YAMLError, RecursionError):
        raise ValueError("YAML inválido ou excede os limites de estrutura") from None
    finally:
        events.close()
