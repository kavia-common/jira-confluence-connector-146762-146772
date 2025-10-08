from __future__ import annotations

import json
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session
from sqlalchemy import select, delete

from .models import ConnectorToken
from src.connectors.base.security import encrypt_json, decrypt_json


# PUBLIC_INTERFACE
def save_tokens(
    db: Session,
    connector_id: str,
    tenant_id: str,
    tokens: Dict[str, Any],
    scopes: Optional[str] = None,
    expires_at: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> ConnectorToken:
    """Persist tokens for a connector tenant (encrypted if configured). Upsert on unique key."""
    payload_b64, enc = encrypt_json(tokens)
    stmt = select(ConnectorToken).where(
        ConnectorToken.connector_id == connector_id, ConnectorToken.tenant_id == tenant_id
    )
    row = db.execute(stmt).scalar_one_or_none()
    if row:
        row.token_payload = payload_b64
        row.encrypted = enc
        row.scopes = scopes
        row.expires_at = expires_at
        row.metadata = json.dumps(metadata or {}) if metadata else row.metadata
    else:
        row = ConnectorToken(
            connector_id=connector_id,
            tenant_id=tenant_id,
            token_payload=payload_b64,
            encrypted=enc,
            scopes=scopes,
            expires_at=expires_at,
            metadata=json.dumps(metadata or {}) if metadata else None,
        )
        db.add(row)
    db.commit()
    db.refresh(row)
    return row


# PUBLIC_INTERFACE
def get_tokens(
    db: Session, connector_id: str, tenant_id: str
) -> Optional[Dict[str, Any]]:
    """Retrieve and decrypt tokens for a connector tenant. Returns None if not found."""
    stmt = select(ConnectorToken).where(
        ConnectorToken.connector_id == connector_id, ConnectorToken.tenant_id == tenant_id
    )
    row = db.execute(stmt).scalar_one_or_none()
    if not row:
        return None
    try:
        return decrypt_json(row.token_payload, row.encrypted)
    except Exception:
        # If decryption fails, expose no tokens
        return None


# PUBLIC_INTERFACE
def get_token_record(
    db: Session, connector_id: str, tenant_id: str
) -> Optional[ConnectorToken]:
    """Return the raw token record (metadata, expiry) without decrypting tokens."""
    stmt = select(ConnectorToken).where(
        ConnectorToken.connector_id == connector_id, ConnectorToken.tenant_id == tenant_id
    )
    return db.execute(stmt).scalar_one_or_none()


# PUBLIC_INTERFACE
def delete_tokens(db: Session, connector_id: str, tenant_id: str) -> int:
    """Delete stored tokens for a connector tenant. Returns rows deleted."""
    result = db.execute(
        delete(ConnectorToken).where(
            ConnectorToken.connector_id == connector_id, ConnectorToken.tenant_id == tenant_id
        )
    )
    db.commit()
    return result.rowcount or 0
