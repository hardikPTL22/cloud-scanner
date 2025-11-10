from boto3 import Session
from functools import wraps


def inject_clients(clients: list[str]):
    def inner_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            session = args[0] if args else None

            if not session or not isinstance(session, Session):
                raise ValueError("Session required as first positional argument")

            for client_name in clients:
                kwargs[f"{client_name}_client"] = session.client(client_name)

            return func(**kwargs)

        return wrapper

    return inner_decorator
