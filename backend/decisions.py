"""
Audit Decision System for Lotus BDAAS.

When the pipeline encounters a critical decision point (e.g., which PHP version
to install, how to start an application, which auth flow to test), it can either:
- Auto-decide (use AI to choose the best option) - default mode
- Ask the user (pause and wait for response) - "ask" mode

This module provides the interface for creating decisions and waiting for answers.
"""

import asyncio
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


async def create_decision(
    repo_id: int,
    category: str,
    question: str,
    options: List[str],
    context: str = "",
    auto_answer: str = "",
    scan_job_id: int = None,
    send=None,
) -> Dict[str, Any]:
    """Create a decision point in the audit.

    In auto-mode: immediately returns the auto_answer without waiting.
    In ask-mode: creates a pending decision and waits up to 5 minutes for user response.

    Returns: {"answer": str, "mode": "auto"|"user", "decision_id": int}
    """
    from backend.main import get_db, AuditDecision, Settings

    db = get_db()
    try:
        settings = db.query(Settings).first()
        api_keys = json.loads(settings.api_keys or '{}') if settings else {}
        mode = api_keys.get('audit_decision_mode', 'auto')

        # Create the decision record
        decision = AuditDecision(
            repo_id=repo_id,
            scan_job_id=scan_job_id,
            category=category,
            question=question,
            options=json.dumps(options),
            context=context,
            auto_answer=auto_answer,
            status="pending" if mode == "ask" else "auto-decided",
        )

        if mode == "auto":
            # Auto-decide: use the provided auto_answer immediately
            decision.answer = auto_answer
            decision.status = "auto-decided"
            decision.answered_at = datetime.utcnow()
            db.add(decision)
            db.commit()
            db.refresh(decision)
            if send:
                await send(repo_id, f"Auto-decided: {question[:60]} -> {auto_answer[:40]}", level="info")
            return {"answer": auto_answer, "mode": "auto", "decision_id": decision.id}

        # Ask mode: create pending decision and wait for user
        db.add(decision)
        db.commit()
        db.refresh(decision)
        decision_id = decision.id

        if send:
            await send(repo_id, f"Waiting for user decision: {question[:80]}", level="warning")
            await send(repo_id, f"Options: {', '.join(options[:5])}", level="info")

    finally:
        db.close()

    # Poll for answer (max 5 minutes, check every 5 seconds)
    timeout = 300
    interval = 5
    elapsed = 0

    while elapsed < timeout:
        await asyncio.sleep(interval)
        elapsed += interval

        db = get_db()
        try:
            d = db.query(AuditDecision).filter(AuditDecision.id == decision_id).first()
            if d and d.status == "answered":
                if send:
                    await send(repo_id, f"User answered: {d.answer[:60]}", level="success")
                return {"answer": d.answer, "mode": "user", "decision_id": decision_id}
        finally:
            db.close()

    # Timeout: fall back to auto_answer
    db = get_db()
    try:
        d = db.query(AuditDecision).filter(AuditDecision.id == decision_id).first()
        if d and d.status == "pending":
            d.status = "expired"
            d.answer = auto_answer
            d.answered_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()

    if send:
        await send(repo_id, f"Decision timed out, using auto-answer: {auto_answer[:40]}", level="warning")
    return {"answer": auto_answer, "mode": "timeout", "decision_id": decision_id}
