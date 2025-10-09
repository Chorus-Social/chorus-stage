import datetime
from pydantic import BaseModel, Field, ConfigDict

class UserCreate(BaseModel):
    display_name: str = Field(..., min_length=2, max_length=32)

class UserUpdate(BaseModel):
    display_name: str | None = None

class User(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    user_key: str
    display_name: str
    created_at: datetime.datetime