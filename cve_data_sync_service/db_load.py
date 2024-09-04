import asyncio
import json
import os
from datetime import datetime
from typing import List

import aiofiles

from cve_data_sync_service import SYNC_CONFIG
from db.cve_repository import make_cve, CVERepository
from db.deps import get_db_session
from db.models.cve import CVERecordDB


class DbDataLoader:
    def __init__(self, batch_size=SYNC_CONFIG['batch_size']):
        self.batch_size = batch_size
        pass

    async def batch_data(self, file_path, cve_batch: List[CVERecordDB]):
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            content = await f.read()
            data = json.loads(content)

            state = data['cveMetadata']['state']
            if state == "PUBLISHED":
                cve_id = data['cveMetadata']['cveId']
                title = data['containers']['adp'][0]['title'] if 'adp' in data['containers'] else ""

                description = data['containers']['cna']['descriptions'][0]['value']

                published_ = data['cveMetadata']['datePublished'] if 'datePublished' in data['cveMetadata'] else \
                    data['cveMetadata']['dateUpdated']

                date_published = datetime.fromisoformat(published_)
                date_updated = datetime.fromisoformat(data['cveMetadata']['dateUpdated'])
                cve: CVERecordDB = make_cve(cve_id, title, description, date_published, date_updated)

                cve_batch.append(cve)

    async def scan_directory(self, data_path=SYNC_CONFIG['data_dir']):
        cve_batch: List[CVERecordDB] = []

        for dirpath, dirnames, filenames in os.walk(data_path):
            tasks = []
            for filename in filenames:
                if filename.endswith('.json') and filename.startswith("CVE"):
                    file_path = os.path.join(dirpath, filename)
                    tasks.append(self.batch_data(file_path, cve_batch))

            if tasks:
                await asyncio.gather(*tasks)

            if len(cve_batch) >= self.batch_size:
                async for db in get_db_session():
                    async with db as session:
                        await CVERepository(session).add_cve_batch(cve_batch)
                    cve_batch.clear()

        if cve_batch:
            async for db in get_db_session():
                async with db as session:
                    await CVERepository(session).add_cve_batch(cve_batch)



if __name__ == '__main__':
    asyncio.run(DbDataLoader(batch_size=100).scan_directory(data_path="cve_data/cves/1999"))
