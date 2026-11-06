from typing import Literal
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
from .db import utc_datetime


class TriageInput(BaseModel):
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


class PackageQuery(BaseModel):
    ecosystem: str = Field(min_length=1, max_length=50)
    package: str = Field(min_length=1, max_length=200)
    version: str | None = Field(None, min_length=1, max_length=100)


class WatchInput(BaseModel):
    ecosystem: str = Field(min_length=1, max_length=50)
    package: str = Field(min_length=1, max_length=200)
    version: str | None = Field(None, max_length=100)
    min_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    alerts_enabled: bool = True


class ProjectInput(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    path: str = Field(min_length=1, max_length=1000)
