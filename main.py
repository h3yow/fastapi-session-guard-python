import logging

import uvicorn
from fastapi import FastAPI

from app.auth import AuthService, hash_password
from app.deps import AppContext
from app.models import User
from app.routes import router
from app.store import SessionStore, UserStore

logging.basicConfig(level=logging.INFO)


def seed_users() -> UserStore:
    return UserStore(
        {
            "alice": User(
                username="alice",
                password_hash=hash_password("alice-pass"),
                permissions=frozenset({"admin"}),
            ),
            "bob": User(
                username="bob",
                password_hash=hash_password("bob-pass"),
                permissions=frozenset(),
            ),
            "carol": User(
                username="carol",
                password_hash=hash_password("carol-pass"),
                disabled=True,
            ),
        }
    )


def create_app(users: UserStore | None = None, access_ttl: float = 300.0,
               refresh_ttl: float = 3600.0) -> FastAPI:
    app = FastAPI(title="fastapi-session-guard")
    user_store = users or seed_users()
    session_store = SessionStore()
    app.state.ctx = AppContext(
        users=user_store,
        sessions=session_store,
        auth=AuthService(user_store, session_store, access_ttl, refresh_ttl),
    )
    app.include_router(router)
    return app


app = create_app()


@app.get("/")
def read_root():
    return {"Hello": "World"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
