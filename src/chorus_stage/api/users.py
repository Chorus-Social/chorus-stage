import secrets
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..models.db_models import User as UserModel
from ..schemas.users import User as UserSchema, UserCreate
from ..database import get_db

router = APIRouter()

@router.post("/users/", response_model=UserSchema)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Create a new user.

    A unique, secure user_key is generated automatically.
    The user's display_name is required.
    """
    
    # 1. Generate a secure, URL-safe random key.
    # The brief says 16 chars, your model says 18. Let's stick with the model.
    generated_key = secrets.token_urlsafe(12) # ~16 chars after encoding

    # 2. Create a SQLAlchemy User model instance with the data.
    db_user = UserModel(
        user_key=generated_key,
        display_name=user.display_name
    )

    # 3. Add the new user to the database session.
    db.add(db_user)
    # 4. Commit the transaction to save it.
    db.commit()
    # 5. Refresh the instance to get the new ID and created_at from the DB.
    db.refresh(db_user)

    # 6. Return the SQLAlchemy object. FastAPI + Pydantic handle the rest!
    return db_user