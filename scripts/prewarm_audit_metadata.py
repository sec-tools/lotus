"""Build disposable audit metadata projections one terminal job at a time.

Run once after installing the cache schema and before opening busy history UIs.
The prewarm operation writes only the cache table. Importing controller models
also runs normal startup migrations; run after schema and admission migration
have been qualified, within the deployment maintenance window.
"""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace
from sqlalchemy import select


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit', type=int, default=50)
    parser.add_argument('--before-id', type=int)
    args = parser.parse_args()
    if not 1 <= args.limit <= 500:
        parser.error('--limit must be between 1 and 500')
    from backend.main import SessionLocal, ScanJob
    from backend.audit_metadata import load_audit_metadata
    from backend.audit_metadata_cache import prewarm_job
    with SessionLocal() as db:
        query = select(ScanJob.id).where(ScanJob.status.notin_(['queued', 'running', 'paused']))
        if args.before_id is not None:
            query = query.where(ScanJob.id < args.before_id)
        ids = list(db.scalars(query.order_by(ScanJob.id.desc()).limit(args.limit)))
    results = []
    for job_id in ids:
        with SessionLocal() as db:
            state = prewarm_job(db, job_id, lambda: load_audit_metadata(db, SimpleNamespace(id=job_id)))
            db.commit()
        results.append({'job_id': job_id, 'metadata': state})
        print(json.dumps(results[-1]), flush=True)
    print(json.dumps({'examined': len(results), 'next_before_id': min(ids) if ids else None}), flush=True)


if __name__ == '__main__':
    main()
