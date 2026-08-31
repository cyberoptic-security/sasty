from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, DeclarativeBase

import os

_db_path = os.environ.get("SASTY_DB_PATH", "./sasty.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{_db_path}"

# NOTE: do not use StaticPool here. It hands every session the *same* DBAPI
# connection, so a request thread closing its session (get_db's finally block)
# rolls back whatever transaction the scan thread has open. On a large scan that
# silently discarded most of the findings and the "completed" status update,
# leaving the scan stuck on "running" with no error anywhere. A normal pool
# gives each concurrent session its own connection; WAL mode lets readers run
# without blocking the scan's write, and `timeout` sets SQLite's busy timeout
# so overlapping writers wait rather than fail.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30},
)

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
