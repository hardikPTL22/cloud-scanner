from boto3 import Session


def inject_clients(clients: list[str]):
    def inner_decorator(func):
        def wrapper(session: Session, *args, **kwargs):
            for client in clients:
                kwargs[f"{client}_client"] = session.client(client)
            return func(*args, **kwargs)

        return wrapper

    return inner_decorator
