"""
SQLAlchemy models for the integration backend domain:
- User
- JiraProject
- ConfluencePage
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .config import Base


class TimestampMixin:
    """Reusable timestamp columns."""

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )


# PUBLIC_INTERFACE
class User(Base, TimestampMixin):
    """Represents an application user who connects JIRA/Confluence accounts."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # OAuth or access tokens (for demo purposes; real deployments should encrypt/secret-manage)
    jira_token: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confluence_token: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    jira_base_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    confluence_base_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    jira_projects: Mapped[list["JiraProject"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    confluence_pages: Mapped[list["ConfluencePage"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"User(id={self.id}, email={self.email})"


# PUBLIC_INTERFACE
class JiraProject(Base, TimestampMixin):
    """Represents a synced JIRA Project for a given user."""

    __tablename__ = "jira_projects"
    __table_args__ = (
        UniqueConstraint("owner_id", "key", name="uq_user_project_key"),
        Index("ix_jira_project_fields", "key", "name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g., "ABC"
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    lead: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    owner: Mapped[User] = relationship(back_populates="jira_projects")

    def __repr__(self) -> str:
        return f"JiraProject(id={self.id}, key={self.key}, name={self.name})"


# PUBLIC_INTERFACE
class ConfluencePage(Base, TimestampMixin):
    """Represents a synced Confluence page for a given user."""

    __tablename__ = "confluence_pages"
    __table_args__ = (
        UniqueConstraint("owner_id", "space_key", "page_id", name="uq_user_space_page"),
        Index("ix_confluence_page_fields", "space_key", "title"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    space_key: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g., "ENG"
    page_id: Mapped[str] = mapped_column(String(128), nullable=False)  # remote page id
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)

    owner: Mapped[User] = relationship(back_populates="confluence_pages")

    def __repr__(self) -> str:
        return f"ConfluencePage(id={self.id}, space={self.space_key}, title={self.title})"
