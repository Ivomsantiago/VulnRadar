from typing import Any, Literal
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .db import utc_datetime


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class TriageInput(InputModel):
    status: Literal["new", "pending", "investigating", "applicable", "not_applicable", "false_positive", "planned", "remediating", "mitigated", "resolved", "accepted"]
    reason: str = Field(min_length=3, max_length=4000)


class FindingTriageInput(TriageInput):
    owner: str | None = Field(None, max_length=150)
    due_at: datetime | None = None
    risk_expires_at: datetime | None = None
    remediation_plan: str | None = Field(None, max_length=8000)

    @field_validator("due_at", "risk_expires_at")
    @classmethod
    def normalize_dates(cls, value):
        return utc_datetime(value) if value is not None else None


class PackageQuery(InputModel):
    ecosystem: str = Field(min_length=1, max_length=50)
    package: str = Field(min_length=1, max_length=200)
    version: str | None = Field(None, min_length=1, max_length=100)


class WatchInput(InputModel):
    ecosystem: str = Field(min_length=1, max_length=50)
    package: str = Field(min_length=1, max_length=200)
    version: str | None = Field(None, max_length=100)
    min_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    alerts_enabled: bool = True


class ProjectInput(InputModel):
    name: str = Field(min_length=1, max_length=150)
    path: str = Field(min_length=1, max_length=1000)


class ProjectExposureInput(InputModel):
    internet_exposed: bool | None


class ProjectView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    path: str
    internet_exposed: bool | None


class ScanView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    kind: str
    status: str
    stage: str
    indexed: bool
    result: dict[str, Any]
    created_at: datetime
    completed_at: datetime | None


class SarifInput(InputModel):
    document: dict[str, Any]


class VexInput(InputModel):
    document: dict[str, Any]
    format: Literal["openvex", "cyclonedx"] = "openvex"
    apply_decision: bool = False
    reason: str = Field("", max_length=4000)


class RetentionInput(InputModel):
    apply: bool = False


class NormalizedAdvisory(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
    aliases: list[str] = Field(default_factory=list, max_length=100)
    title: str = Field(max_length=2000)
    description: str = Field(max_length=200000)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    cvss: float | None = Field(None, ge=0, le=10, allow_inf_nan=False)
    published: str | None = Field(None, max_length=60)
    modified: str | None = Field(None, max_length=60)
    affected: list[dict[str, Any]] = Field(default_factory=list, max_length=5000)
    references: list[Any] = Field(default_factory=list, max_length=3000)

    @field_validator("aliases")
    @classmethod
    def validate_aliases(cls, values):
        import re
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}", value) for value in values):
            raise ValueError("Alias inválido na fonte")
        return values
