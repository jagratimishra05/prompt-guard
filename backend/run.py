import sys
import os
from pathlib import Path

import uvicorn


BACKEND_ROOT = Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.main import app


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=os.getenv("PROMPTGUARD_HOST", "127.0.0.1"),
        port=int(os.getenv("PROMPTGUARD_PORT", "8000")),
    )
