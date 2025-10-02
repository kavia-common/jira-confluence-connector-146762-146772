"""
Service layer functions wrapping DB operations.
"""

from __future__ import annotations

from typing import Optional, List

from sqlalchemy.orm import Session
from sqlalchemy import select

from .models import User, JiraProject, ConfluencePage


# PUBLIC_INTERFACE
def create_user(db: Session, *, email: str, display_name: Optional[str] = None,
                jira_token: Optional[str] = None, confluence_token: Optional[str] = None,
                jira_base_url: Optional[str] = None, confluence_base_url: Optional[str] = None) -> User:
    """Create a new user or return existing by email (idempotent create)."""
    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing:
        return existing
    user = User(
        email=email,
        display_name=display_name,
        jira_token=jira_token,
        confluence_token=confluence_token,
        jira_base_url=jira_base_url,
        confluence_base_url=confluence_base_url,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# PUBLIC_INTERFACE
def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    """Get a user by id."""
    return db.get(User, user_id)


# PUBLIC_INTERFACE
def list_users(db: Session) -> List[User]:
    """List all users."""
    return list(db.execute(select(User).order_by(User.id.desc())).scalars())


# PUBLIC_INTERFACE
def upsert_jira_project(db: Session, *, owner_id: int, key: str, name: str,
                        lead: Optional[str] = None, url: Optional[str] = None) -> JiraProject:
    """Create or update a JIRA project keyed by (owner_id, key)."""
    stmt = select(JiraProject).where(JiraProject.owner_id == owner_id, JiraProject.key == key)
    project = db.execute(stmt).scalar_one_or_none()
    if project:
        project.name = name
        project.lead = lead
        project.url = url
    else:
        project = JiraProject(owner_id=owner_id, key=key, name=name, lead=lead, url=url)
        db.add(project)
    db.commit()
    db.refresh(project)
    return project


# PUBLIC_INTERFACE
def list_jira_projects_for_user(db: Session, owner_id: int) -> List[JiraProject]:
    """List JIRA projects for a given user."""
    stmt = select(JiraProject).where(JiraProject.owner_id == owner_id).order_by(JiraProject.key.asc())
    return list(db.execute(stmt).scalars())


# PUBLIC_INTERFACE
def upsert_confluence_page(db: Session, *, owner_id: int, space_key: str, page_id: str,
                           title: str, url: Optional[str] = None) -> ConfluencePage:
    """Create or update a Confluence page keyed by (owner_id, space_key, page_id)."""
    stmt = select(ConfluencePage).where(
        ConfluencePage.owner_id == owner_id,
        ConfluencePage.space_key == space_key,
        ConfluencePage.page_id == page_id,
    )
    page = db.execute(stmt).scalar_one_or_none()
    if page:
        page.title = title
        page.url = url
    else:
        page = ConfluencePage(owner_id=owner_id, space_key=space_key, page_id=page_id, title=title, url=url)
        db.add(page)
    db.commit()
    db.refresh(page)
    return page


# PUBLIC_INTERFACE
def list_confluence_pages_for_user(db: Session, owner_id: int) -> List[ConfluencePage]:
    """List Confluence pages for a given user."""
    stmt = select(ConfluencePage).where(ConfluencePage.owner_id == owner_id).order_by(ConfluencePage.title.asc())
    return list(db.execute(stmt).scalars())
