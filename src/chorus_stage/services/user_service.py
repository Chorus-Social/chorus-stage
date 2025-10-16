# src/chorus_stage/crud/users.py

from sqlalchemy.orm import Session
from chorus_stage.schemas import user as schemas
from chorus_stage.models import user as models
from chorus_stage.core import security

# --- READ ---
def get_user(db: Session, user_id: int):
    """Fetches a single user from the database by their ID."""
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    """Fetches a list of users with pagination."""
    return db.query(models.User).offset(skip).limit(limit).all()


# --- CREATE ---
def create_user(db: Session, user: schemas.UserCreate, user_key: str):
    """Creates a new user record in the database."""
    # Create an instance of the SQLAlchemy model from our Pydantic schema
    hashed_key = security.hash_key(user_key)
    
    db_user = models.User(
        user_key=hashed_key,
        display_name=user.display_name
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user) # Refresh to get the new ID and created_at timestamp
    
    return db_user


# --- UPDATE ---
def update_user(db: Session, db_user: models.User, update_data: schemas.UserUpdate):
    """Updates a user's attributes in the database."""
    # Convert the Pydantic schema to a dictionary, excluding unset values
    update_dict = update_data.model_dump(exclude_unset=True)
    
    for key, value in update_dict.items():
        setattr(db_user, key, value)
        
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# --- DELETE ---
def delete_user(db: Session, db_user: models.User):
    """Deletes a user record from the database."""
    db.delete(db_user)
    db.commit()
    return db_user