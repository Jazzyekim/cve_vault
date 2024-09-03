from typing import Annotated, Sequence

from fastapi import APIRouter, Depends, HTTPException, Response

from api_cve_service.db.cve_repository import CVERepository, get_cve_repository
from api_cve_service.schemas import CVERecord

cve_api = APIRouter(prefix="/cve_records")


@cve_api.get("/",
             name="Get all CVERecord",
             description="Returns all registered CVERecords")
async def get_all_cve(repo: Annotated[CVERepository, Depends(get_cve_repository)]) -> Sequence[CVERecord]:
    return await repo.get_all_cve()


@cve_api.get("/{cve_id}",
             name="Get CVERecord by ID",
             description="Returns a single CVERecord by its ID")
async def get_cve_by_id(cve_id: str,
                        repo: Annotated[CVERepository, Depends(get_cve_repository)]
                        ) -> CVERecord:
    cve_record = await repo.get_cve_by_id(cve_id)
    if cve_record is None:
        raise HTTPException(status_code=404, detail="CVERecord not found")
    return CVERecord.model_validate(cve_record)


@cve_api.post("/",
              name="Add new CVERecord",
              description="Returns the list of all registered CVERecords",
              status_code=201)
async def add_cve_record(record: CVERecord,
                         repo: Annotated[CVERepository, Depends(get_cve_repository)],
                         response: Response) -> CVERecord:
    cve_record_db = await repo.add_cve_record(record)
    response.status_code = 201
    return CVERecord.model_validate(cve_record_db)
