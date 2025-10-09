from sqlalchemy import create_engine
from chorus_stage.core.config import settings
from chorus_stage.models import db_models

engine = create_engine(settings.database_url)

def init_db():
    """Initialize the database by creating all tables."""
    db_models.Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init_db()
    print("Database initialized.")