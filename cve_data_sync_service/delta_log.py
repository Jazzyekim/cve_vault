import asyncio
import json
from datetime import datetime

import aiofiles

from cve_data_sync_service import SYNC_CONFIG

DELTA_LOG_PATH = SYNC_CONFIG['delta_log_path']


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


async def get_and_process_updates(last_fetch_time):
    # last_fetch_time = await get_last_fetch_time()
    new_entries = await read_delta_log(last_fetch_time)

    for entry in new_entries:
        cve_ids = extract_cve_ids(entry)
        print(entry['fetchTime'], cve_ids, sep=":")


# asyncio.run(get_and_process_updates())
