from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine

from db import DB_CONFIG


class DatabaseEngineSingleton:
    _instance = None

    def __new__(cls, db_url=DB_CONFIG["uri"]):
        if cls._instance is None:
            cls._instance = super(DatabaseEngineSingleton, cls).__new__(cls)
            cls._instance.engine = create_async_engine(db_url, echo=True)
        return cls._instance

    def get_engine(self):
        return self.engine


def get_engine() -> AsyncEngine:
    return DatabaseEngineSingleton().get_engine()

async def get_db_session() -> AsyncIterator[AsyncSession]:
    engine = get_engine()
    session_factory = async_sessionmaker(engine)
    async with session_factory() as session:
        yield session