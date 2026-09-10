"""SQLAlchemy models for the vulnerability remediation ledger."""

from __future__ import annotations

import datetime as dt
import enum

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


class Reachability(str, enum.Enum):
    UNKNOWN = "unknown"
    PENDING_ANALYST = "pending_analyst"
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"


class StepStatus(str, enum.Enum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class CommChannel(str, enum.Enum):
    SLACK = "slack"
    EMAIL = "email"
    GITHUB = "github"
    JIRA = "jira"
    OTHER = "other"


class CommDirection(str, enum.Enum):
    OUTBOUND = "outbound"
    INBOUND = "inbound"


class RefType(str, enum.Enum):
    GITHUB_PR = "github_pr"
    GITHUB_COMMIT = "github_commit"
    GITHUB_ISSUE = "github_issue"
    JIRA_TICKET = "jira_ticket"


class CommitmentStatus(str, enum.Enum):
    OPEN = "open"
    MET = "met"
    MISSED = "missed"
    RENEGOTIATED = "renegotiated"


class Stakeholder(Base):
    __tablename__ = "stakeholders"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(100), default="service_owner")
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    slack_user_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    github_username: Mapped[str | None] = mapped_column(String(100), nullable=True)

    assets: Mapped[list["Asset"]] = relationship(back_populates="owner")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    repo_full_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    environment: Mapped[str] = mapped_column(String(50), default="production")
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("stakeholders.id"), nullable=True)

    owner: Mapped[Stakeholder | None] = relationship(back_populates="assets")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="asset")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    external_id: Mapped[str] = mapped_column(String(100), index=True)  # e.g. CVE-2026-12345
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[VulnStatus] = mapped_column(Enum(VulnStatus), default=VulnStatus.OPEN)
    reachability: Mapped[Reachability] = mapped_column(Enum(Reachability), default=Reachability.UNKNOWN)
    priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    priority_rationale: Mapped[str] = mapped_column(Text, default="")

    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)

    discovered_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    due_date: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    asset: Mapped[Asset | None] = relationship(back_populates="vulnerabilities")
    remediation_steps: Mapped[list["RemediationStep"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    communications: Mapped[list["CommunicationLog"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    timeline_events: Mapped[list["TimelineEvent"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan", order_by="TimelineEvent.occurred_at"
    )
    external_refs: Mapped[list["ExternalReference"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    commitments: Mapped[list["Commitment"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )


class RemediationStep(Base):
    __tablename__ = "remediation_steps"

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[StepStatus] = mapped_column(Enum(StepStatus), default=StepStatus.PLANNED)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("stakeholders.id"), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="remediation_steps")
    owner: Mapped[Stakeholder | None] = relationship()


class CommunicationLog(Base):
    __tablename__ = "communication_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"))
    channel: Mapped[CommChannel] = mapped_column(Enum(CommChannel))
    direction: Mapped[CommDirection] = mapped_column(Enum(CommDirection), default=CommDirection.OUTBOUND)
    stakeholder_id: Mapped[int | None] = mapped_column(ForeignKey("stakeholders.id"), nullable=True)
    subject: Mapped[str] = mapped_column(String(500), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    external_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)  # thread ts / message id
    sent_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="communications")
    stakeholder: Mapped[Stakeholder | None] = relationship()


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"))
    event_type: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(100), default="agent")
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="timeline_events")


class ExternalReference(Base):
    __tablename__ = "external_references"

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"))
    ref_type: Mapped[RefType] = mapped_column(Enum(RefType))
    external_id: Mapped[str] = mapped_column(String(300))  # e.g. "org/repo#123", commit sha, "SEC-42"
    url: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(50), default="open")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="external_refs")


class Commitment(Base):
    """A stakeholder's stated commitment ('we'll fix this by Friday')."""

    __tablename__ = "commitments"

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"))
    stakeholder_id: Mapped[int | None] = mapped_column(ForeignKey("stakeholders.id"), nullable=True)
    description: Mapped[str] = mapped_column(Text)
    committed_date: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[CommitmentStatus] = mapped_column(Enum(CommitmentStatus), default=CommitmentStatus.OPEN)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="commitments")
    stakeholder: Mapped[Stakeholder | None] = relationship()


class ChatThread(Base):
    """A persisted chat session with the conversational agent."""

    __tablename__ = "chat_threads"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(String(200), default="")
    model: Mapped[str] = mapped_column(String(200), default="")
    agent_state: Mapped[str] = mapped_column(Text, default="")  # JSON from AssistantAgent.save_state()
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    messages: Mapped[list["ChatMessage"]] = relationship(back_populates="thread", cascade="all, delete-orphan")
    mentions: Mapped[list["ChatMention"]] = relationship(back_populates="thread", cascade="all, delete-orphan")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    thread_id: Mapped[str] = mapped_column(ForeignKey("chat_threads.id"), index=True)
    role: Mapped[str] = mapped_column(String(20))  # "user" | "assistant"
    payload: Mapped[str] = mapped_column(Text)  # JSON entry as rendered by the UI
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    thread: Mapped[ChatThread] = relationship(back_populates="messages")


class ChatMention(Base):
    """Links a vulnerability referenced in a chat thread (in text or tool IO)."""

    __tablename__ = "chat_mentions"

    id: Mapped[int] = mapped_column(primary_key=True)
    thread_id: Mapped[str] = mapped_column(ForeignKey("chat_threads.id"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    thread: Mapped[ChatThread] = relationship(back_populates="mentions")
    vulnerability: Mapped[Vulnerability] = relationship()
