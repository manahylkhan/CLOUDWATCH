from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import init_db
from routers import aws_config, scans, cloudtrail, ai_analyze, reports

app = FastAPI(title="CLOUDWATCH API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(aws_config.router)
app.include_router(scans.router)
app.include_router(cloudtrail.router)
app.include_router(ai_analyze.router)
app.include_router(reports.router)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "CLOUDWATCH"}
