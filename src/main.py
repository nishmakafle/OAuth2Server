from starlette.responses import JSONResponse
from .helpers import generate_client_id, generate_client_secret, hash_password, make_serizable, verify_client, generate_authorization_code, verify_auth_code, create_access_token, authenticate_user
from decouple import config


from db_config import wrapper
from .models import ClientRegistration


def homepage(request):
    # print(request.url.port)
    return JSONResponse({"message": "Hello, Welcome first Starlette project"})


async def client_regrestration(request):
    data = await request.json()
    try:
        validate_data = ClientRegistration(**data)
        client_id = generate_client_id()
        client_secret = generate_client_secret()
        data = {
            "username": validate_data.username,
            "password": hash_password(validate_data.password),
            "client_id": client_id,
            "client_secret": client_secret

        }
        result = wrapper.insert_one("AuthServer", "Client", data)

        return JSONResponse({"client_id": client_id, "client_secret": client_secret}, status_code=200)
    except Exception as e:
        return JSONResponse({"error": e}, status_code=400)


async def clients(request):
    results = wrapper.find("AuthServer", "Client")

    result = [make_serizable(data) for data in results]
    return JSONResponse(status_code=200, content=result)


async def login(request):
    data = await request.json()
    if not verify_client(data.get("client_id"), data.get("username")):
        return JSONResponse({"message": "Client Not Found"}, status_code=400)
    auth_code = generate_authorization_code()
    query = {"client_id": data.get("client_id")}
    new_values = {"$set": {"auth_code": auth_code}}
    wrapper.update_one("AuthServer", "Client", query, new_values)

    return JSONResponse({"auth_code": auth_code, "redirect_url": config("REDIRECT_URL")}, status_code=200)


async def token(request):
    data = await request.json()
    auth_code = data.get("auth_code")
    if not verify_auth_code(auth_code):
        return JSONResponse({"message": "Invalid Authorization Code"}, status_code=400)
    query = {"auth_code": auth_code}
    client = wrapper.find_one("AuthServer", "Client", query)
    data = {
        "username": client.get('username')
    }
    access_token = create_access_token(data)
    return JSONResponse({"access_token": access_token, "redirect_url": config("REDIRECT_URL")}, status_code=200)


async def verify_user(request):
    data = await request.json()
    if not authenticate_user(data.get("token")):
        return JSONResponse({"message": "Invalid User"}, status_code=400)

    return JSONResponse({"message": "Valid User"}, status_code=200)
