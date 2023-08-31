from starlette.applications import Starlette
from starlette.routing import Route
from .main import homepage, client_regrestration, clients, login, token, verify_user




routers = [
    Route('/', homepage),
    Route('/client_regrestration', client_regrestration, methods = ["POST"]),
    Route('/clients', clients, methods = ["GET"]),
    Route('/login', login, methods=["POST"]),
    Route('/token', token, methods = ["POST"]),
    Route('/verify_user', verify_user, methods=["POSt"])

]


app = Starlette(debug=True, routes=routers)