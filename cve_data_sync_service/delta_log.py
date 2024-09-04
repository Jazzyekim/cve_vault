import asyncio
import json
import os
from datetime import datetime

import aiofiles

from api_cve_service.schemas import CVERecord
from cve_data_sync_service import SYNC_CONFIG
from db.deps import get_db_session

DELTA_LOG_PATH = SYNC_CONFIG['delta_log_path']
ROOT_FOLDER = SYNC_CONFIG['cves_folder']


async def find_file(file_name):
    for root, dirs, files in os.walk(ROOT_FOLDER):
        if file_name in files:
            return os.path.join(root, file_name)
    return None


async def search_file(file_name):
    tasks = []
    name_split = file_name.split(".")[0].split("-")
    year = name_split[1]
    number = name_split[2][:-3] + 'xxx'
    for root, _, _ in os.walk(os.path.join(ROOT_FOLDER, year, number)):
        tasks.append(asyncio.create_task(find_file(file_name)))

    results = await asyncio.gather(*tasks)
    return next((result for result in results if result is not None), None)


async def read_stored_fetch_time(file_path):
    try:
        async with aiofiles.open(file_path, mode='r') as f:
            content = await f.read()
            data = json.loads(content)
            return datetime.fromisoformat(data['lastFetchTime'].replace('Z', '+00:00'))
    except FileNotFoundError:
        return None


async def store_fetch_time(file_path, fetch_time):
    async with aiofiles.open(file_path, mode='w') as f:
        await f.write(json.dumps({'lastFetchTime': fetch_time.isoformat()}))


async def get_last_fetch_time():
    async with aiofiles.open(DELTA_LOG_PATH, mode='r') as file:
        async for line in file:
            if '"fetchTime":' in line:
                fetch_time_str = line.split('"fetchTime":')[1].split('"')[1]
                return datetime.fromisoformat(fetch_time_str.replace('Z', '+00:00'))


async def read_delta_log(last_fetch_time):
    object_lines = []

    async with aiofiles.open(DELTA_LOG_PATH, mode='r') as file:
        async for line in file:
            object_lines.append(line.strip())
            if '"fetchTime":' in line:
                fetch_time_str = line.split('"fetchTime":')[1].split('"')[1]
                fetch_time = datetime.fromisoformat(fetch_time_str.replace('Z', '+00:00'))

                if last_fetch_time is None or fetch_time > last_fetch_time:
                    pass
                else:
                    if len(object_lines) <= 3:
                        return []
                    object_lines.pop()
                    object_lines[-2] = "}"
                    object_lines[-1] = "]"
                    break
    data = json.loads(''.join(object_lines))
    entries = data if isinstance(data, list) else []
    entries.sort(key=lambda x: datetime.fromisoformat(x['fetchTime'].replace('Z', '+00:00')))
    return entries


def extract_cve_ids(json_content: str):
    new_cves = [f"{item['cveId']}.json" for item in json_content.get('new', [])]
    updated_cves = [f"{item['cveId']}.json" for item in json_content.get('updated', [])]

    return {
        "new_cves": new_cves,
        "updated_cves": updated_cves
    }

from db_load import DbDataLoader
from db.cve_repository import CVERepository


async def get_and_process_updates(last_fetch_time):
    new_entries = await read_delta_log(last_fetch_time)

    for entry in new_entries:
        cve_ids = extract_cve_ids(entry)
        for cve in cve_ids['new_cves']:
            file_path = await search_file(cve)
            cve_record = await DbDataLoader().cve_from_file(file_path)
            async for db in get_db_session():
                async with db as session:
                    print("NEW", cve_record)
                    await CVERepository(session).add_cve_record(CVERecord.model_validate(cve_record))
        for cve in cve_ids["updated_cves"]:
            file_path = await search_file(cve)
            cve_record = await DbDataLoader().cve_from_file(file_path)
            async for db in get_db_session():
                async with db as session:
                    print("UPDATE", cve_record)
                    await CVERepository(session).update_cve_record(cve_record.id, CVERecord.model_validate(cve_record))


if __name__ == "__main__":
    t = datetime.fromisoformat("2024-09-04T16:10:39.061Z".replace('Z', '+00:00'))
    asyncio.run(get_and_process_updates(t))
