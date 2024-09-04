import logging
from datetime import datetime
from typing import Annotated, Sequence
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi import Query

from api_cve_service.schemas import CVERecord
from db.cve_repository import CVERepository, get_cve_repository

cve_api = APIRouter(prefix="/cve_records")
logger = logging.getLogger(__name__)


@cve_api.get("/",
             name="Get all CVERecord",
             description="Returns all registered CVERecords")
async def get_all_cve(repo: Annotated[CVERepository, Depends(get_cve_repository)],
                      limit: Optional[int] = Query(10, description="Limit the number of CVERecords returned"),
                      offset: Optional[int] = Query(0, description="Offset for pagination")
                      ) -> Sequence[CVERecord]:
    cve_list = await repo.get_all_cve(limit=limit, offset=offset)
    return [CVERecord.model_validate(cve) for cve in cve_list]


@cve_api.get("/search",
             name="Search CVERecords by Published Date Range",
             description="Search CVERecords within a specified published date range")
async def search_cve_by_date(
        repo: Annotated[CVERepository, Depends(get_cve_repository)],
        start_date: Optional[datetime] = Query(None, description="Start date for the search range "
                                                                 "in ISO 8601 format (e.g., 2021-01-01T00:00:00Z)"),
        end_date: Optional[datetime] = Query(None, description="End date for the search range "
                                                               "in ISO 8601 format (e.g., 2021-12-31T23:59:59Z)")
) -> Sequence[CVERecord]:
    logging.warning(f"Searching CVERecords within {start_date} to {end_date}")
    cve_list = await repo.search_cve_by_published_date(start_date=start_date, end_date=end_date)
    return [CVERecord.model_validate(cve) for cve in cve_list]


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
