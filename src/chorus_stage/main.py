# src/chorus_stage/main.py
from fastapi import FastAPI

# Import the router we created in the users.py file
from .api import users

# Create the main FastAPI application instance
app = FastAPI()

# Tell the main app to include all the endpoints from the users router.
# Any URL starting with /users will be handled by our users.py file.
app.include_router(users.router)

# A simple "hello world" endpoint at the root to check it's working
@app.get("/")
def read_root():
    return {"Hello": "Chorus"}
