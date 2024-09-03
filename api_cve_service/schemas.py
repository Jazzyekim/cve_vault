from pydantic import BaseModel, ConfigDict, field_validator
from pydantic.fields import Field
from datetime import datetime


class CVERecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    title: str
    description:str
    date_published: datetime = Field(..., description="The date when the CVE was published")
    date_updated: datetime = Field(..., description="The date when the CVE was published")

    @field_validator('id')
    def id_must_start_with_cve(cls, value):
        if not value.startswith("CVE"):
            raise ValueError("ID must start with 'CVE'")
        return value
