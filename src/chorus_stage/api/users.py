# src/chorus_stage/routers/users.py

import secrets
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from chorus_stage.services import user_service as user_crud
from chorus_stage.schemas import users as schemas
from chorus_stage.database import get_db

router = APIRouter(
    prefix="/users",  # All paths in this router will start with /users
    tags=["Users"],   # Group these endpoints in the API docs
)


@router.post("/", response_model=schemas.User)
def create_user_endpoint(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Creates a new user with a unique, automatically generated user_key.
    """
    generated_key = secrets.token_urlsafe(12)
    return user_crud.create_user(db=db, user=user, user_key=generated_key)


@router.get("/", response_model=List[schemas.User])
def read_users_endpoint(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Retrieves a list of all users.
    """
    return user_crud.get_users(db, skip=skip, limit=limit)


@router.get("/{user_id}", response_model=schemas.User)
def read_user_endpoint(user_id: int, db: Session = Depends(get_db)):
    """
    Retrieves a single user by their ID.
    """
    db_user = user_crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.patch("/{user_id}", response_model=schemas.User)
def update_user_endpoint(user_id: int, user: schemas.UserUpdate, db: Session = Depends(get_db)):
    """
    Updates a user's information (e.g., their display_name).
    """
    db_user = user_crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user_crud.update_user(db=db, db_user=db_user, update_data=user)


@router.delete("/{user_id}", response_model=schemas.User)
def delete_user_endpoint(user_id: int, db: Session = Depends(get_db)):
    """
    Deletes a user from the database.
    """
    db_user = user_crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user_crud.delete_user(db=db, db_user=db_user)