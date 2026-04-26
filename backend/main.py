from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import argparse
import uvicorn

try:
    from .routers import sla, scan, patch
except ImportError:
    from routers import sla, scan, patch

app = FastAPI(title="SLAyer API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["tauri://localhost", "http://localhost:1420", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(sla.router, prefix="/api")
app.include_router(scan.router, prefix="/api")
app.include_router(patch.router, prefix="/api")


@app.get("/api/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18765)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
