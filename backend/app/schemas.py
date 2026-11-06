from typing import Literal
from pydantic import BaseModel, Field


class TriageInput(BaseModel):
    status: Literal["new", "pending", "investigating", "applicable", "not_applicable", "false_positive", "planned", "mitigated", "resolved", "accepted"]
    reason: str = Field(min_length=3, max_length=4000)


class PackageQuery(BaseModel):
    ecosystem: str = Field(min_length=1, max_length=50)
    package: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)


class WatchInput(BaseModel):
    ecosystem: str = Field(min_length=1, max_length=50)
    package: str = Field(min_length=1, max_length=200)
    version: str | None = Field(None, max_length=100)


class ProjectInput(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    path: str = Field(min_length=1, max_length=1000)
