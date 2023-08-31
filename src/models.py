
from pydantic import BaseModel

class ClientRegistration(BaseModel):
    username: str
    password:str

    