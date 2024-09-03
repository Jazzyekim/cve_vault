from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker

from api_cve_service.db.engine import get_engine


async def get_db_session() -> AsyncIterator[AsyncSession]:
    engine = get_engine()
    session_factory = async_sessionmaker(engine)
    async with session_factory() as session:
        yield session
