from collections.abc import Sequence
from typing import Annotated

from db.models.cve import CVERecordDB
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from api_cve_service.schemas import CVERecord

from api_cve_service import deps


class CVERepository:
    def __init__(self, db: Annotated[AsyncSession, Depends(deps.get_db_session)]):
        self.db = db

    async def get_all_cve(self) -> Sequence[CVERecordDB]:
        stmt = (select(CVERecordDB).order_by(CVERecordDB.id))
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


async def get_cve_repository(db: Annotated[AsyncSession, Depends(deps.get_db_session)]) -> CVERepository:
    return CVERepository(db)
