"""本地启动入口：uvicorn main:app --reload"""

import uvicorn

from app.config import DEFAULT_SETTINGS
from app.main import create_app

app = create_app(DEFAULT_SETTINGS)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
