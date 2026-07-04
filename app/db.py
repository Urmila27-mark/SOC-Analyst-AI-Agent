from __future__ import annotations

from contextlib import contextmanager

from .models import get_engine, get_session_factory, init_db

_engine = None
_SessionFactory = None


def setup(db_path: str = "sqlite:///soc_agent.db"):
    global _engine, _SessionFactory
    _engine = get_engine(db_path)
    init_db(_engine)
    _SessionFactory = get_session_factory(_engine)
    return _engine


@contextmanager
def session_scope():
    if _SessionFactory is None:
        setup()
    session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
