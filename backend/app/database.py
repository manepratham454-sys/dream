import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./test.db')
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401  (registers ORM tables on Base)
    Base.metadata.create_all(bind=engine)

    # Lightweight migration for SQLite: ensure newly added columns exist in users table
    if DATABASE_URL.startswith("sqlite"):
        with engine.connect() as conn:
            cursor = conn.execute(text("PRAGMA table_info(users)"))
            existing_cols = {row[1] for row in cursor.fetchall()}

            migrations = [
                ("avatar_url", "TEXT"),
                ("auth_provider", "VARCHAR DEFAULT 'password'"),
                ("is_active", "BOOLEAN DEFAULT 1"),
                ("last_login", "DATETIME"),
            ]
            for col_name, col_def in migrations:
                if col_name not in existing_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}"))
                        conn.commit()
                    except Exception:
                        pass
