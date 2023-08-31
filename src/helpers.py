import uuid
import string
import secrets
import bcrypt
from db_config import wrapper
from datetime import timedelta, datetime
import jwt
from decouple import config

def make_serizable(obj):
     obj['_id'] = str(obj.get('_id'))
     return obj
     


def hash_password(password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)

    # Return the hashed password as a string
    return hashed_password.decode()



def generate_client_id():
    return str(uuid.uuid4())

def generate_client_secret(length=10):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def verify_client(client_id, username):
    query = {"client_id":client_id, "username":username}
    result = wrapper.find_one("AuthServer", "Client", query)
    return result


def generate_authorization_code():
    # Generate a random authorization code
    authorization_code = secrets.token_urlsafe(16)
    return authorization_code

def verify_auth_code(auth_code):
    query = {"auth_code":auth_code}
    result = wrapper.find_one("AuthServer", "Client", query)
    return result


def create_access_token(data: dict):    
    access_token = encoded = jwt.encode(data, key = config('SECRET_KEY'), algorithm="HS256")
    return access_token


def verify_password(hashed, input_password):
    print(hashed,".............")
    print(hash_password(input_password),",,,,,,,,,,,,,,,,")
    # Verify the input password against the hashed password
    if hash_password(input_password) == hashed:
        return True
    else:
        return False


def get_user(username):
    query = {"username": username}
    user = wrapper.find_one("AuthServer", "Client", query)
    return user


def decode_token(token: str):
    """
    :param token: jwt token
    :return:
    """
    decoded_data = jwt.decode(jwt=token,
                              key=config("SECRET_KEY"),
                              algorithms=["HS256"])

    print(decoded_data)
    return decoded_data



def authenticate_user(token):
    decode_user = decode_token(token)
    user = get_user(decode_user.get("username"))
    if not user:
        return False
    return user