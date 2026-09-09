"""Normalized import schema. Any scanner export can be mapped to this shape
(a small pre-processing script converting scanner-native JSON/CSV into these
field names is the expected on-ramp for a new scanner)."""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, Field, field_validator

from vulngent.db.models import Severity


class VulnRecord(BaseModel):
    external_id: str = Field(description="e.g. CVE-2026-12345 or a scanner-native finding id")
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    cvss_score: float | None = None
    asset_name: str = Field(description="Logical asset/service/repo name this finding applies to")
    repo_full_name: str | None = Field(default=None, description="'org/repo' if this asset maps to a GitHub repo")
    asset_criticality: str = "medium"
    owner_name: str | None = Field(default=None, description="Stakeholder/service-owner display name")
    owner_email: str | None = None
    owner_slack_id: str | None = None
    owner_github_username: str | None = None
    discovered_at: dt.datetime | None = None
    due_date: dt.datetime | None = Field(
        default=None, description="Remediation deadline; defaults to a severity-based SLA if omitted"
    )

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, v: object) -> object:
        if isinstance(v, str):
            return v.strip().lower()
        return v
