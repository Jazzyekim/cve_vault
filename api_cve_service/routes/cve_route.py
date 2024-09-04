from typing import Annotated, Sequence
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi import Query

from api_cve_service.schemas import CVERecord
from db.cve_repository import CVERepository, get_cve_repository

cve_api = APIRouter(prefix="/cve_records")


@cve_api.get("/",
             name="Get all CVERecord",
             description="Returns all registered CVERecords")
async def get_all_cve(repo: Annotated[CVERepository, Depends(get_cve_repository)],
                      limit: Optional[int] = Query(10, description="Limit the number of CVERecords returned"),
                      offset: Optional[int] = Query(0, description="Offset for pagination")
                      ) -> Sequence[CVERecord]:
    return await repo.get_all_cve(limit=limit, offset=offset)


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
