import datetime
from pydantic import BaseModel, Field

class UserCreate(BaseModel):
    display_name: str = Field(..., min_length=2, max_length=32)

class User(BaseModel):
    id: int
    user_key: str
    display_name: str
    created_at: datetime.datetime
    
    class Config:
        orm_mode = True