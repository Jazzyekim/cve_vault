from contextlib import asynccontextmanager

from fastapi import FastAPI
from api_cve_service.routes.router import api_route
from db.engine import get_engine
from db.models import Base


@asynccontextmanager
async def lifespan(_app: FastAPI):
    engine = get_engine()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    pass


app = FastAPI(title="CVE Vault", lifespan=lifespan, debug=True)
app.include_router(api_route)
