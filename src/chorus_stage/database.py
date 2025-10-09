# src/chorus_stage/database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from chorus_stage.core.config import settings

# Create the SQLAlchemy engine
engine = create_engine(settings.database_url)

# Create a configured "Session" class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get a DB session
def get_db():
    """Get a database session for a request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()