import logging
from collections.abc import Sequence
from typing import Annotated, List, Optional

from db.models.cve import CVERecordDB
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from api_cve_service.schemas import CVERecord

from db import deps
from datetime import datetime

logger = logging.getLogger('sqlalchemy_queries')

class CVERepository:
    def __init__(self, db: Annotated[AsyncSession, Depends(deps.get_db_session)]):
        self.db = db

    async def get_all_cve(self, limit: int, offset: int) -> Sequence[CVERecordDB]:
        stmt = (select(CVERecordDB).order_by(CVERecordDB.id).limit(limit)
                .offset(offset))
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def get_cve_by_id(self, cve_id: str) -> CVERecordDB:
        stmt = (select(CVERecordDB).where(CVERecordDB.id == cve_id))
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def add_cve_record(self, record: CVERecord) -> CVERecordDB:
        cve_record_db = CVERecordDB(**record.model_dump())
        self.db.add(cve_record_db)
        await self.db.commit()

        await self.db.refresh(cve_record_db)
        return cve_record_db

    async def add_cve_batch(self, records: List[CVERecordDB]) -> None:
        self.db.add_all(records)
        await self.db.commit()

    async def search_cve_by_published_date(self, start_date: Optional[datetime], end_date: Optional[datetime]
                                           ) -> Sequence[CVERecordDB]:
        stmt = select(CVERecordDB).order_by(CVERecordDB.id)

        if start_date:
            stmt = stmt.where(CVERecordDB.date_published >= start_date)
        if end_date:
            stmt = stmt.where(CVERecordDB.date_published <= end_date)

        logger.info("Executing query: %s", stmt.compile(compile_kwargs={"literal_binds": True}))

        result = await self.db.execute(stmt)
        return result.scalars().all()


async def get_cve_repository(db: Annotated[AsyncSession, Depends(deps.get_db_session)]) -> CVERepository:
    return CVERepository(db)


def make_cve(cve_id: str, title: str, description: str, date_published: datetime,
             date_updated: datetime) -> CVERecordDB:
    return CVERecordDB(id=cve_id,
                       title=title,
                       description=description,
                       date_published=date_published,
                       date_updated=date_updated
                       )
